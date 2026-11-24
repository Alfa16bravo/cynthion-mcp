"""Pure decoding helpers for the Cynthion USB analyzer stream.

This module is stdlib-only and performs no USB access, so it can be fully unit
tested. It implements:

* the bulk-IN stream parser of the Cynthion analyzer gateware (protocol 1.1):
  - event record  : ``FF <code:u8> <ts:u16 BE>``
  - packet record : ``<len:u16 BE> <ts:u16 BE> <len bytes> [1 pad byte if len odd]``
  - ``ts`` is a delta in 60 MHz ticks, accumulated into an absolute tick count;
* USB 2.0 packet decoding (PID, token fields, SOF frame, SPLIT, CRC5/CRC16);
* SETUP packet decoding;
* record filtering with address/endpoint inference for data/handshake packets;
* transaction grouping and capture summaries;
* pcap export/import with LINKTYPE_USB_2_0 (288).
"""

from __future__ import annotations

import enum
import struct
import time
from dataclasses import dataclass
from typing import Any, BinaryIO, Iterable, Iterator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

USB_CLOCK_HZ = 60_000_000
TICK_NS = 1e9 / 60e6  # 16.666... ns per tick

#: Maximum length of a well-formed USB 2.0 packet (1024 payload + PID + CRC16).
#: Longer records are legitimate analyzer output (babble / noise): the gateware
#: does not cap ``packet_size`` (MAX_PACKET_SIZE_BYTES is unused there), so they
#: are kept and flagged as oversize by ``decode_packet``.
MAX_PACKET_LEN = 1027

#: Largest record length the analyzer can emit: the packet must fit in the
#: 4096 x 16-bit analyzer ring buffer (``mem_depth=4096`` words), otherwise
#: the gateware goes to OVERRUN.  Anything above this is a real framing error.
MAX_RECORD_LEN = 2 * 4096

#: Speed values for the analyzer state register bits [2:1].
SPEED_BITS = {"high": 0, "full": 1, "low": 2, "auto": 3}
SPEED_NAMES = {v: k for k, v in SPEED_BITS.items()}

#: Synthetic event code emitted by StreamParser when the stream desynchronises.
DESYNC_CODE = -1


def ticks_to_ns(ticks: int) -> int:
    """Convert 60 MHz analyzer ticks to integer nanoseconds."""
    return ticks * 50 // 3


class AnalyzerEvent(enum.IntEnum):
    """Event codes emitted by the analyzer gateware (cynthion/gateware/analyzer/events.py)."""

    NONE = 0
    CAPTURE_STOP_NORMAL = 1
    CAPTURE_STOP_FULL = 2
    CAPTURE_STOP_ERROR = 3
    CAPTURE_START_HIGH = 4
    CAPTURE_START_FULL = 5
    CAPTURE_START_LOW = 6
    CAPTURE_START_AUTO = 7
    SPEED_DETECT_HIGH = 8
    SPEED_DETECT_FULL = 9
    SPEED_DETECT_LOW = 10
    SPEED_DETECT_AUTO = 11
    LINESTATE_SE0 = 12
    LINESTATE_CHIRP_J = 13
    LINESTATE_CHIRP_K = 14
    LINESTATE_CHIRP_SE1 = 15
    LINESTATE_LS_J = 16
    LINESTATE_LS_K = 17
    LINESTATE_FS_J = 18
    LINESTATE_FS_K = 19
    LINESTATE_SE1 = 20
    VBUS_INVALID = 21
    VBUS_VALID = 22
    LS_ATTACH = 23
    FS_ATTACH = 24
    BUS_RESET = 25
    DEVICE_CHIRP_VALID = 26
    HOST_CHIRP_VALID = 27
    SUSPEND = 28
    RESUME = 29
    LS_KEEPALIVE = 30


def event_name(code: int) -> str:
    """Return the symbolic name of an analyzer event code."""
    if code == DESYNC_CODE:
        return "DESYNC"
    try:
        return AnalyzerEvent(code).name
    except ValueError:
        return f"UNKNOWN_{code}"


# ---------------------------------------------------------------------------
# PIDs
# ---------------------------------------------------------------------------

PID_NAMES = {
    0x1: "OUT", 0x9: "IN", 0x5: "SOF", 0xD: "SETUP",
    0x3: "DATA0", 0xB: "DATA1", 0x7: "DATA2", 0xF: "MDATA",
    0x2: "ACK", 0xA: "NAK", 0xE: "STALL", 0x6: "NYET",
    0xC: "PRE_ERR", 0x8: "SPLIT", 0x4: "PING",
}
PID_BY_NAME = {name.upper(): pid for pid, name in PID_NAMES.items()}
PID_BY_NAME.update({"PRE": 0xC, "ERR": 0xC, "PRE/ERR": 0xC})

TOKEN_PIDS = {0x1, 0x9, 0xD, 0x4}
DATA_PIDS = {0x3, 0xB, 0x7, 0xF}
HANDSHAKE_PIDS = {0x2, 0xA, 0xE, 0x6}
SOF_PID = 0x5
SPLIT_PID = 0x8


def normalize_pid_name(name: str) -> str:
    """Normalise a user-supplied PID name to the canonical PID_NAMES spelling.

    Raises ValueError for unknown names.
    """
    key = str(name).strip().upper()
    if key not in PID_BY_NAME:
        raise ValueError(f"unknown PID name {name!r}; expected one of {sorted(PID_BY_NAME)}")
    return PID_NAMES[PID_BY_NAME[key]]


# ---------------------------------------------------------------------------
# CRC
# ---------------------------------------------------------------------------

def crc16_usb(data: bytes) -> int:
    """CRC-16/USB (poly 0x8005 reflected, init 0xFFFF, xorout 0xFFFF)."""
    c = 0xFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c ^ 0xFFFF


def crc5_usb(val11: int) -> int:
    """CRC-5/USB over 11 bits sent LSB first (token addr|ep<<7, or SOF frame number)."""
    c = 0x1F
    for i in range(11):
        bit = (val11 >> i) & 1
        if (c ^ bit) & 1:
            c = (c >> 1) ^ 0x14
        else:
            c >>= 1
    return c ^ 0x1F


# ---------------------------------------------------------------------------
# Records and stream parser
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Record:
    """One analyzer stream record.

    ``ticks`` is the absolute 60 MHz tick count since capture start.
    ``data`` holds the raw packet (PID..CRC) for packets; ``code`` the event code for events.
    """

    seq: int
    kind: str  # 'packet' | 'event'
    ticks: int
    data: bytes = b""
    code: int = 0

    def __repr__(self) -> str:
        if self.kind == "event":
            return (f"Record(seq={self.seq}, kind='event', ticks={self.ticks}, "
                    f"code={self.code}, event={event_name(self.code)})")
        return (f"Record(seq={self.seq}, kind={self.kind!r}, ticks={self.ticks}, "
                f"data={self.data!r})")


class StreamParser:
    """Incremental parser for the analyzer bulk-IN byte stream."""

    def __init__(self, require_start: bool = False, drop_codes: "frozenset[int] | set[int] | None" = None) -> None:
        #: Event codes that are consumed (ticks still accumulated) but not
        #: turned into Record objects; counts go to ``dropped_by_code``.  This
        #: matters for throughput: LINESTATE events are ~90% of a busy stream.
        self.drop_codes = frozenset(drop_codes or ())
        self.dropped_by_code: dict[int, int] = {}
        #: When True, bytes are discarded until a CAPTURE_START event
        #: (FF 04..07 00 00) is seen, so leftovers of a previous capture can
        #: never be parsed as headers.
        self.require_start = require_start
        self.awaiting_start = require_start
        self.skipped_bytes = 0
        self.buf = bytearray()
        self.ticks = 0
        self.seq = 0
        self.bytes_in = 0
        self.desync_count = 0
        #: True once a framing error was detected.  The stream cannot be
        #: realigned on a record boundary from the host side, so every later
        #: byte is discarded until ``reset()`` (i.e. a capture restart).
        self.desynced = False

    def reset(self) -> None:
        """Reset all state (buffer, timebase, sequence numbers, counters)."""
        self.buf = bytearray()
        self.ticks = 0
        self.seq = 0
        self.bytes_in = 0
        self.desync_count = 0
        self.desynced = False
        self.awaiting_start = self.require_start
        self.skipped_bytes = 0
        self.dropped_by_code = {}

    @property
    def pending_bytes(self) -> int:
        """Number of buffered bytes not yet forming a complete record."""
        return len(self.buf)

    def _next_seq(self) -> int:
        s = self.seq
        self.seq += 1
        return s

    def feed(self, data: bytes) -> list[Record]:
        """Feed raw bytes; return the complete records decoded so far."""
        if data:
            self.bytes_in += len(data)
            if self.desynced:
                return []
            self.buf += data
        buf = self.buf
        out: list[Record] = []
        pos = 0
        n = len(buf)
        if self.awaiting_start:
            i = 0
            while i + 4 <= n:
                if buf[i] == 0xFF and 4 <= buf[i + 1] <= 7 and buf[i + 2] == 0 and buf[i + 3] == 0:
                    break
                i += 1
            if i + 4 > n:
                keep = min(n, 3)  # a start marker may straddle reads
                self.skipped_bytes += n - keep
                del buf[:n - keep]
                return out
            self.skipped_bytes += i
            pos = i
            self.awaiting_start = False
        drop = self.drop_codes
        dropped = self.dropped_by_code
        while n - pos >= 4:
            if buf[pos] == 0xFF:
                code = buf[pos + 1]
                ts = (buf[pos + 2] << 8) | buf[pos + 3]
                self.ticks += ts
                pos += 4
                if code in drop:
                    dropped[code] = dropped.get(code, 0) + 1
                    self.seq += 1
                    continue
                out.append(Record(self._next_seq(), "event", self.ticks, b"", code))
                continue
            length, ts = struct.unpack_from(">HH", buf, pos)
            if length > MAX_RECORD_LEN:
                # Impossible length: the stream is out of sync.  Do not try to
                # guess the next boundary (payload bytes would be read as fake
                # headers and corrupt the timebase); stop decoding until reset.
                self.desync_count += 1
                self.desynced = True
                out.append(Record(self._next_seq(), "event", self.ticks, b"", DESYNC_CODE))
                pos = n
                break
            total = 4 + length + (length & 1)
            if n - pos < total:
                break
            pkt = bytes(buf[pos + 4:pos + 4 + length])
            self.ticks += ts
            pos += total
            out.append(Record(self._next_seq(), "packet", self.ticks, pkt, 0))
        if pos:
            del buf[:pos]
        return out


# ---------------------------------------------------------------------------
# Packet decoding
# ---------------------------------------------------------------------------

def decode_packet(p: bytes) -> dict[str, Any]:
    """Decode one raw USB 2.0 packet (PID byte through CRC, no SYNC/EOP)."""
    p = bytes(p)
    if not p:
        return {"pid": "EMPTY", "len": 0}
    b = p[0]
    pid = b & 0xF
    valid = ((b ^ (b >> 4)) & 0xF) == 0xF
    d: dict[str, Any] = {
        "pid": PID_NAMES.get(pid, "?"),
        "pid_raw": f"0x{b:02x}",
        "pid_valid": valid,
        "len": len(p),
    }
    errors: list[str] = []
    if not valid:
        errors.append("invalid PID check bits")

    if pid in TOKEN_PIDS:
        if len(p) == 3:
            v = p[1] | (p[2] << 8)
            d["addr"] = v & 0x7F
            d["ep"] = (v >> 7) & 0xF
            d["crc5"] = v >> 11
            d["crc_ok"] = crc5_usb(v & 0x7FF) == (v >> 11)
        else:
            errors.append(f"token length {len(p)} != 3")
    elif pid == SOF_PID:
        if len(p) == 3:
            v = p[1] | (p[2] << 8)
            d["frame"] = v & 0x7FF
            d["crc5"] = v >> 11
            d["crc_ok"] = crc5_usb(v & 0x7FF) == (v >> 11)
        else:
            errors.append(f"SOF length {len(p)} != 3")
    elif pid == SPLIT_PID:
        if len(p) == 4:
            v = p[1] | (p[2] << 8) | (p[3] << 16)
            d.update(
                hub_addr=v & 0x7F,
                sc=(v >> 7) & 1,
                port=(v >> 8) & 0x7F,
                s=(v >> 15) & 1,
                e=(v >> 16) & 1,
                et=(v >> 17) & 3,
                crc_ok=None,
            )
        else:
            errors.append(f"SPLIT length {len(p)} != 4")
    elif pid in DATA_PIDS:
        if len(p) >= 3:
            payload = p[1:-2]
            d["data_len"] = len(payload)
            d["data_hex"] = payload.hex()
            d["crc_ok"] = crc16_usb(payload) == int.from_bytes(p[-2:], "little")
        else:
            d["crc_ok"] = False
            errors.append("short data packet")
    elif pid in HANDSHAKE_PIDS:
        if len(p) != 1:
            errors.append(f"handshake length {len(p)} != 1")

    if len(p) > MAX_PACKET_LEN:
        d["oversize"] = True
        errors.append(f"oversize packet ({len(p)} > {MAX_PACKET_LEN} bytes, babble?)")

    if d.get("crc_ok") is False and "short data packet" not in errors:
        errors.insert(0, "CRC")
    if errors:
        d["error"] = errors[0] if len(errors) == 1 else "; ".join(errors)
    return d


_STD_REQUESTS = {
    0: "GET_STATUS", 1: "CLEAR_FEATURE", 3: "SET_FEATURE", 5: "SET_ADDRESS",
    6: "GET_DESCRIPTOR", 7: "SET_DESCRIPTOR", 8: "GET_CONFIGURATION",
    9: "SET_CONFIGURATION", 10: "GET_INTERFACE", 11: "SET_INTERFACE", 12: "SYNCH_FRAME",
}
_DESCRIPTOR_TYPES = {
    1: "DEVICE", 2: "CONFIGURATION", 3: "STRING", 4: "INTERFACE", 5: "ENDPOINT",
    6: "DEVICE_QUALIFIER", 0x0F: "BOS", 0x21: "HID", 0x22: "HID_REPORT",
}
_REQ_TYPES = ("standard", "class", "vendor", "reserved")
_RECIPIENTS = {0: "device", 1: "interface", 2: "endpoint", 3: "other"}


def decode_setup(payload: bytes) -> dict[str, Any] | None:
    """Decode an 8-byte SETUP data stage. Returns None when the length is not 8."""
    payload = bytes(payload)
    if len(payload) != 8:
        return None
    bm, breq, wvalue, windex, wlength = struct.unpack("<BBHHH", payload)
    rtype = _REQ_TYPES[(bm >> 5) & 3]
    d: dict[str, Any] = {
        "bmRequestType": f"0x{bm:02x}",
        "direction": "IN" if bm & 0x80 else "OUT",
        "type": rtype,
        "recipient": _RECIPIENTS.get(bm & 0x1F, f"reserved_{bm & 0x1F}"),
        "bRequest": breq,
        "wValue": wvalue,
        "wIndex": windex,
        "wLength": wlength,
    }
    if rtype == "standard":
        name = _STD_REQUESTS.get(breq)
        if name:
            d["request_name"] = name
            if breq in (6, 7):
                dt = wvalue >> 8
                d["descriptor_type"] = _DESCRIPTOR_TYPES.get(dt, f"0x{dt:02x}")
                d["descriptor_index"] = wvalue & 0xFF
            elif breq == 5:
                d["address"] = wvalue & 0x7F
            elif breq == 9:
                d["configuration"] = wvalue & 0xFF
    return d


def record_to_dict(r: Record, raw: bool = False) -> dict[str, Any]:
    """Convert a Record to a JSON-friendly dict (decoded)."""
    d: dict[str, Any] = {
        "seq": r.seq,
        "kind": r.kind,
        "ticks": r.ticks,
        "t_us": round(ticks_to_ns(r.ticks) / 1000, 3),
    }
    if r.kind == "event":
        d["event"] = event_name(r.code)
        d["code"] = r.code
    else:
        d.update(decode_packet(r.data))
        if raw or len(r.data) <= 8:
            d["raw_hex"] = r.data.hex()
    return d


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

class TokenContext:
    """Tracks the last token so data/handshake packets can inherit addr/ep.

    Context is cleared by a handshake (end of transaction) and by events
    that interrupt the bus (bus reset, capture start/stop, desync).
    """

    _RESET_EVENTS = {
        AnalyzerEvent.BUS_RESET, AnalyzerEvent.CAPTURE_STOP_NORMAL,
        AnalyzerEvent.CAPTURE_STOP_FULL, AnalyzerEvent.CAPTURE_STOP_ERROR,
        AnalyzerEvent.CAPTURE_START_HIGH, AnalyzerEvent.CAPTURE_START_FULL,
        AnalyzerEvent.CAPTURE_START_LOW, AnalyzerEvent.CAPTURE_START_AUTO,
    }

    def __init__(self) -> None:
        self.token: str | None = None
        self.addr: int | None = None
        self.ep: int | None = None

    def update(self, r: Record, decoded: dict[str, Any] | None = None) -> dict[str, Any] | None:
        """Process a record; for packets return the decoded dict, annotated with
        inferred 'addr'/'ep'/'token' for data and handshake packets."""
        if r.kind == "event":
            if r.code == DESYNC_CODE or r.code in self._RESET_EVENTS:
                self.token = self.addr = self.ep = None
            return decoded
        if decoded is None:
            decoded = decode_packet(r.data)
        pid = r.data[0] & 0xF if r.data else -1
        if pid in TOKEN_PIDS and "addr" in decoded:
            self.token = decoded["pid"]
            self.addr = decoded["addr"]
            self.ep = decoded["ep"]
        elif pid in DATA_PIDS or pid in HANDSHAKE_PIDS:
            if self.addr is not None:
                decoded.setdefault("addr", self.addr)
                decoded.setdefault("ep", self.ep)
                decoded.setdefault("token", self.token)
                decoded["inferred"] = True
            if pid in HANDSHAKE_PIDS:
                self.token = self.addr = self.ep = None
        return decoded


@dataclass
class RecordFilter:
    """Selection criteria for analyzer records.

    pids are canonical upper-case names (see PID_NAMES). include_nak=False drops
    NAK handshakes only (the preceding IN/PING token is kept; use
    group_transactions for NAK-free transaction views).
    """

    kinds: set[str] | None = None
    pids: set[str] | None = None
    address: int | None = None
    endpoint: int | None = None
    include_sof: bool = False
    include_nak: bool = True
    only_errors: bool = False

    def __post_init__(self) -> None:
        if self.kinds is not None:
            self.kinds = {str(k).lower() for k in self.kinds}
        if self.pids is not None:
            self.pids = {normalize_pid_name(p) for p in self.pids}

    def matches(self, r: Record, decoded: dict[str, Any] | None = None) -> bool:
        if self.kinds is not None and r.kind not in self.kinds:
            return False
        if r.kind == "event":
            # Events have no PID/address; exclude them when PID/address filters are set.
            if self.pids or self.address is not None or self.endpoint is not None:
                return False
            if self.only_errors:
                return r.code in (DESYNC_CODE, AnalyzerEvent.CAPTURE_STOP_FULL,
                                  AnalyzerEvent.CAPTURE_STOP_ERROR)
            return True
        if decoded is None:
            decoded = decode_packet(r.data)
        pid = decoded.get("pid")
        if pid == "SOF" and not self.include_sof and not (self.pids and "SOF" in self.pids):
            return False
        if pid == "NAK" and not self.include_nak:
            return False
        if self.pids is not None and pid not in self.pids:
            return False
        if self.address is not None and decoded.get("addr") != self.address:
            return False
        if self.endpoint is not None and decoded.get("ep") != self.endpoint:
            return False
        if self.only_errors and "error" not in decoded:
            return False
        return True

    def apply(self, records: Iterable[Record]) -> list[Record]:
        """Return the matching Records, propagating the token address/endpoint
        to the following data and handshake packets (unlike ``matches`` alone)."""
        ctx = TokenContext()
        out: list[Record] = []
        for r in records:
            if r.kind == "packet":
                ok = self.matches(r, ctx.update(r, decode_packet(r.data)))
            else:
                ctx.update(r)
                ok = self.matches(r)
            if ok:
                out.append(r)
        return out


def filter_records(records: Iterable[Record], flt: RecordFilter, limit: int,
                   raw: bool = False) -> tuple[list[dict[str, Any]], int | None]:
    """Decode and filter records.

    Returns (matching record dicts, seq of the last record examined). When the
    limit is reached, iteration stops right after the record that filled it,
    so callers can resume from ``last_seq + 1``.
    """
    ctx = TokenContext()
    out: list[dict[str, Any]] = []
    last_seq: int | None = None
    for r in records:
        last_seq = r.seq
        if r.kind == "packet":
            decoded = ctx.update(r, record_to_dict(r, raw=raw))
            ok = flt.matches(r, decoded)
        else:
            ctx.update(r)
            decoded = None
            ok = flt.matches(r)
            if ok:
                decoded = record_to_dict(r, raw=raw)
        if ok:
            out.append(decoded)  # type: ignore[arg-type]
            if len(out) >= limit:
                break
    return out, last_seq


# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------

def group_transactions(records: Iterable[Record], include_sof: bool = False,
                       include_nak: bool = False,
                       decode_setup_packets: bool = True,
                       include_events: bool = False) -> list[dict[str, Any]]:
    """Group packets into USB transactions (token [+ data] [+ handshake]).

    Output items:
      * {seq, t_us, type: 'SETUP'|'IN'|'OUT'|'PING', addr, ep, data_pid, data_hex,
         data_len, handshake, crc_ok, setup?}
      * {seq, t_us, type: 'SOF', frame} when include_sof
      * {seq, t_us, type: 'EVENT', event} when include_events
      * {seq, t_us, type: 'ORPHAN', pid, ...} for data/handshake without a token
    """
    out: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None

    def close(handshake: str | None) -> None:
        nonlocal cur
        if cur is None:
            return
        cur["handshake"] = handshake
        if not (handshake == "NAK" and not include_nak):
            out.append(cur)
        cur = None

    for r in records:
        t_us = round(ticks_to_ns(r.ticks) / 1000, 3)
        if r.kind == "event":
            close(None)
            if include_events:
                out.append({"seq": r.seq, "t_us": t_us, "type": "EVENT",
                            "event": event_name(r.code)})
            continue
        d = decode_packet(r.data)
        pid = r.data[0] & 0xF if r.data else -1
        if pid in TOKEN_PIDS:
            close(None)
            cur = {
                "seq": r.seq, "t_us": t_us, "type": d["pid"],
                "addr": d.get("addr"), "ep": d.get("ep"),
                "data_pid": None, "data_hex": None, "data_len": 0,
                "handshake": None, "crc_ok": d.get("crc_ok", False),
            }
        elif pid == SOF_PID:
            # SOF never sits inside a transaction.
            close(None)
            if include_sof:
                out.append({"seq": r.seq, "t_us": t_us, "type": "SOF", "frame": d.get("frame"),
                            "crc_ok": d.get("crc_ok")})
        elif pid in DATA_PIDS:
            if cur is not None and cur["data_pid"] is None:
                cur["data_pid"] = d["pid"]
                cur["data_hex"] = d.get("data_hex", "")
                cur["data_len"] = d.get("data_len", 0)
                if d.get("crc_ok") is False:
                    cur["crc_ok"] = False
                if cur["type"] == "SETUP" and decode_setup_packets:
                    setup = decode_setup(bytes.fromhex(cur["data_hex"] or ""))
                    if setup is not None:
                        cur["setup"] = setup
                # Isochronous / no-handshake transfers: keep open until next token.
            else:
                close(None)
                out.append({"seq": r.seq, "t_us": t_us, "type": "ORPHAN", "pid": d["pid"],
                            "data_hex": d.get("data_hex"), "data_len": d.get("data_len", 0)})
        elif pid in HANDSHAKE_PIDS:
            if cur is not None:
                close(d["pid"])
            elif not (d["pid"] == "NAK" and not include_nak):
                out.append({"seq": r.seq, "t_us": t_us, "type": "ORPHAN", "pid": d["pid"]})
        else:
            # SPLIT, PRE/ERR, invalid PIDs, empty packets.
            close(None)
            item = {"seq": r.seq, "t_us": t_us, "type": "OTHER", "pid": d["pid"]}
            if "error" in d:
                item["error"] = d["error"]
            out.append(item)
    close(None)
    return out


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def summarize(records: Iterable[Record]) -> dict[str, Any]:
    """Compute aggregate statistics over a set of records.

    ``devices`` is keyed by str(address) then str(endpoint) for JSON stability.
    """
    packets_by_pid: dict[str, int] = {}
    events: dict[str, int] = {}
    devices: dict[str, dict[str, dict[str, int]]] = {}
    crc_errors = 0
    invalid_pids = 0
    packets = 0
    first_ticks: int | None = None
    last_ticks: int | None = None
    detected_speed: str | None = None
    cur_ep: dict[str, int] | None = None

    for r in records:
        if first_ticks is None:
            first_ticks = r.ticks
        last_ticks = r.ticks
        if r.kind == "event":
            name = event_name(r.code)
            events[name] = events.get(name, 0) + 1
            if AnalyzerEvent.CAPTURE_START_HIGH <= r.code <= AnalyzerEvent.CAPTURE_START_AUTO:
                detected_speed = SPEED_NAMES.get(r.code - AnalyzerEvent.CAPTURE_START_HIGH)
            elif AnalyzerEvent.SPEED_DETECT_HIGH <= r.code <= AnalyzerEvent.SPEED_DETECT_AUTO:
                detected_speed = SPEED_NAMES.get(r.code - AnalyzerEvent.SPEED_DETECT_HIGH)
            continue
        packets += 1
        d = decode_packet(r.data)
        packets_by_pid[d["pid"]] = packets_by_pid.get(d["pid"], 0) + 1
        if d.get("pid_valid") is False:
            invalid_pids += 1
        if d.get("crc_ok") is False:
            crc_errors += 1
        pid = r.data[0] & 0xF if r.data else -1
        if pid in TOKEN_PIDS and "addr" in d and d.get("crc_ok"):
            dev = devices.setdefault(str(d["addr"]), {})
            cur_ep = dev.setdefault(str(d["ep"]), {"IN": 0, "OUT": 0, "SETUP": 0, "PING": 0, "bytes": 0})
            cur_ep[d["pid"]] = cur_ep.get(d["pid"], 0) + 1
        elif pid in DATA_PIDS:
            if cur_ep is not None:
                cur_ep["bytes"] += d.get("data_len", 0)
        elif pid in HANDSHAKE_PIDS or pid == SOF_PID:
            if pid != SOF_PID:
                cur_ep = None

    def _us(t: int | None) -> float | None:
        return None if t is None else round(ticks_to_ns(t) / 1000, 3)

    return {
        "packets": packets,
        "packets_by_pid": packets_by_pid,
        "events": events,
        "devices": devices,
        "crc_errors": crc_errors,
        "invalid_pids": invalid_pids,
        "first_t_us": _us(first_ticks),
        "last_t_us": _us(last_ticks),
        "duration_s": (None if first_ticks is None or last_ticks is None
                       else round(ticks_to_ns(last_ticks - first_ticks) / 1e9, 6)),
        "detected_speed": detected_speed,
    }


# ---------------------------------------------------------------------------
# pcap (LINKTYPE_USB_2_0)
# ---------------------------------------------------------------------------

LINKTYPE_USB_2_0 = 288
PCAP_MAGIC_NS = 0xA1B23C4D
PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_SNAPLEN = 65535


def _pcap_header(nanosecond: bool) -> bytes:
    return struct.pack("<IHHiIII", PCAP_MAGIC_NS if nanosecond else PCAP_MAGIC_US,
                       2, 4, 0, 0, PCAP_SNAPLEN, LINKTYPE_USB_2_0)


def _as_tick_packets(packets: Iterable[Any]) -> Iterator[tuple[int, bytes]]:
    """Accept (ticks, bytes) tuples or Record objects (events / empty packets skipped)."""
    for item in packets:
        if isinstance(item, Record):
            if item.kind != "packet" or not item.data:
                continue
            yield item.ticks, item.data
        else:
            yield item


def _pcap_records(packets: Iterable[Any], start_epoch_ns: int,
                  nanosecond: bool) -> Iterator[bytes]:
    for ticks, pkt in _as_tick_packets(packets):
        pkt = bytes(pkt)
        t = start_epoch_ns + ticks_to_ns(ticks)
        sec, frac = divmod(t, 1_000_000_000)
        if not nanosecond:
            frac //= 1000
        yield struct.pack("<IIII", sec & 0xFFFFFFFF, frac, len(pkt), len(pkt)) + pkt


def pcap_bytes(packets: Iterable[tuple[int, bytes]], start_epoch_ns: int | None = None,
               nanosecond: bool = True) -> bytes:
    """Build a pcap file in memory. ``packets`` yields (abs_ticks, raw_packet) or Records."""
    if start_epoch_ns is None:
        start_epoch_ns = time.time_ns()
    parts = [_pcap_header(nanosecond)]
    parts.extend(_pcap_records(packets, start_epoch_ns, nanosecond))
    return b"".join(parts)


def write_pcap(path: str, packets: Iterable[tuple[int, bytes]], start_epoch_ns: int | None = None,
               nanosecond: bool = True) -> int:
    """Stream a pcap file to ``path``. Returns the number of bytes written."""
    if start_epoch_ns is None:
        start_epoch_ns = time.time_ns()
    written = 0
    with open(path, "wb") as f:
        hdr = _pcap_header(nanosecond)
        f.write(hdr)
        written += len(hdr)
        for rec in _pcap_records(packets, start_epoch_ns, nanosecond):
            f.write(rec)
            written += len(rec)
    return written


def records_to_pcap_packets(records: Iterable[Record], include_sof: bool = True
                            ) -> Iterator[tuple[int, bytes]]:
    """Adapt Records to the (ticks, bytes) iterable expected by pcap writers.

    Events and empty packets are skipped (LINKTYPE_USB_2_0 cannot represent them).
    """
    for r in records:
        if r.kind != "packet" or not r.data:
            continue
        if not include_sof and (r.data[0] & 0xF) == SOF_PID:
            continue
        yield r.ticks, r.data


def read_pcap(path_or_bytes: str | bytes | bytearray | BinaryIO) -> list[tuple[int, bytes]]:
    """Minimal pcap reader: returns [(timestamp_ns, data), ...]."""
    if isinstance(path_or_bytes, (bytes, bytearray)):
        blob = bytes(path_or_bytes)
    elif hasattr(path_or_bytes, "read"):
        blob = path_or_bytes.read()  # type: ignore[union-attr]
    else:
        with open(path_or_bytes, "rb") as f:  # type: ignore[arg-type]
            blob = f.read()
    if len(blob) < 24:
        raise ValueError("not a pcap file (too short)")
    magic_le = struct.unpack_from("<I", blob, 0)[0]
    if magic_le in (PCAP_MAGIC_NS, PCAP_MAGIC_US):
        endian = "<"
        magic = magic_le
    else:
        magic = struct.unpack_from(">I", blob, 0)[0]
        if magic not in (PCAP_MAGIC_NS, PCAP_MAGIC_US):
            raise ValueError(f"not a pcap file (magic 0x{magic_le:08x})")
        endian = ">"
    ns = magic == PCAP_MAGIC_NS
    out: list[tuple[int, bytes]] = []
    pos = 24
    while pos + 16 <= len(blob):
        sec, frac, incl, _orig = struct.unpack_from(endian + "IIII", blob, pos)
        pos += 16
        if pos + incl > len(blob):
            raise ValueError("truncated pcap record")
        t = sec * 1_000_000_000 + (frac if ns else frac * 1000)
        out.append((t, blob[pos:pos + incl]))
        pos += incl
    return out


def pcap_linktype(path_or_bytes: str | bytes) -> int:
    """Return the linktype field of a pcap global header."""
    if isinstance(path_or_bytes, (bytes, bytearray)):
        blob = bytes(path_or_bytes)
    else:
        with open(path_or_bytes, "rb") as f:
            blob = f.read(24)
    if len(blob) < 24:
        raise ValueError("not a pcap file (too short)")
    endian = "<" if struct.unpack_from("<I", blob, 0)[0] in (PCAP_MAGIC_NS, PCAP_MAGIC_US) else ">"
    return struct.unpack_from(endian + "I", blob, 20)[0]


__all__ = [
    "USB_CLOCK_HZ", "TICK_NS", "MAX_PACKET_LEN", "MAX_RECORD_LEN", "SPEED_BITS", "SPEED_NAMES", "DESYNC_CODE",
    "ticks_to_ns", "AnalyzerEvent", "event_name",
    "PID_NAMES", "PID_BY_NAME", "TOKEN_PIDS", "DATA_PIDS", "HANDSHAKE_PIDS", "normalize_pid_name",
    "crc16_usb", "crc5_usb",
    "Record", "StreamParser", "decode_packet", "decode_setup", "record_to_dict",
    "TokenContext", "RecordFilter", "filter_records", "group_transactions", "summarize",
    "LINKTYPE_USB_2_0", "pcap_bytes", "write_pcap", "records_to_pcap_packets", "read_pcap",
    "pcap_linktype",
]
