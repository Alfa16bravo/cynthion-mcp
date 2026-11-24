"""Pure (hardware-free) tests for cynthion_mcp.usbdecode.

Test vectors come from the Cynthion analyzer gateware unit tests
(cynthion/gateware/analyzer/analyzer.py) and from the CRC reference doctests in
luna/gateware/test/contrib/usb_packet.py.

The record/transaction containers produced by usbdecode may be tuples, dicts or
objects; the small accessor helpers below normalise them so these tests pin
down behaviour rather than one specific container shape.
"""
from __future__ import annotations

import inspect
import os
import struct
import sys

import pytest

_SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)

usbdecode = pytest.importorskip("cynthion_mcp.usbdecode")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _get(rec, *names, index=None, default=None):
    if isinstance(rec, dict):
        for n in names:
            if n in rec:
                return rec[n]
    elif isinstance(rec, (tuple, list)) and index is not None and not hasattr(rec, "_fields"):
        return rec[index] if len(rec) > index else default
    else:
        for n in names:
            if hasattr(rec, n):
                return getattr(rec, n)
        if isinstance(rec, tuple) and index is not None and len(rec) > index:
            return rec[index]
    return default


def kind(rec) -> str:
    k = _get(rec, "kind", "type", "record_type", index=0)
    return str(getattr(k, "value", k)).lower()


def ticks(rec) -> int:
    return int(_get(rec, "ticks", "abs_ticks", "timestamp_ticks", "time_ticks", index=1))


def data(rec) -> bytes:
    d = _get(rec, "data", "raw", "bytes", "packet", "payload", index=2)
    if isinstance(d, str):
        return bytes.fromhex(d)
    return bytes(d)


def code(rec) -> int:
    c = _get(rec, "code", "event", "event_code", index=2)
    return int(getattr(c, "value", c))


def as_text(obj) -> str:
    return repr(obj).upper()


def call_flex(fn, *args, **kwargs):
    """Call fn, dropping keyword args its signature does not accept."""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return fn(*args, **kwargs)
    if any(p.kind is p.VAR_KEYWORD for p in params.values()):
        return fn(*args, **kwargs)
    return fn(*args, **{k: v for k, v in kwargs.items() if k in params})


def parse(stream: bytes, chunk: int | None = None) -> list:
    p = usbdecode.StreamParser()
    out = []
    if chunk is None:
        out.extend(p.feed(stream) or [])
    else:
        for i in range(0, len(stream), chunk):
            out.extend(p.feed(stream[i:i + chunk]) or [])
    return out


def packets(records):
    return [r for r in records if kind(r) == "packet"]


def events(records):
    return [r for r in records if kind(r) == "event"]


def pkt_record(raw: bytes, ts: int) -> bytes:
    """Encode one analyzer packet record: <len BE><ts BE><raw>[pad]."""
    rec = struct.pack(">HH", len(raw), ts) + raw
    if len(raw) & 1:
        rec += b"\x00"
    return rec


def token(pid_byte: int, addr: int, ep: int) -> bytes:
    v = addr | (ep << 7)
    v |= usbdecode.crc5_usb(v & 0x7FF) << 11
    return bytes([pid_byte, v & 0xFF, v >> 8])


def data_pkt(pid_byte: int, payload: bytes) -> bytes:
    return bytes([pid_byte]) + payload + usbdecode.crc16_usb(payload).to_bytes(2, "little")


SETUP, IN, OUT, SOF = 0x2D, 0x69, 0xE1, 0xA5
DATA0, DATA1, ACK, NAK = 0xC3, 0x4B, 0xD2, 0x5A
GET_DESC_DEVICE = bytes.fromhex("8006000100001200")


# ---------------------------------------------------------------------------
# CRC
# ---------------------------------------------------------------------------

def test_crc16_check_value():
    assert usbdecode.crc16_usb(b"123456789") == 0xB4C8


def test_crc5_reference_vectors():
    assert usbdecode.crc5_usb(0) == 0x02
    assert usbdecode.crc5_usb(3) == 0x0A


# ---------------------------------------------------------------------------
# stream parser
# ---------------------------------------------------------------------------

def test_capture_start_event():
    recs = parse(bytes.fromhex("FF040000"))
    assert len(recs) == 1
    assert kind(recs[0]) == "event"
    assert code(recs[0]) == 4  # CAPTURE_START_HIGH
    assert ticks(recs[0]) == 0


def test_gateware_setup_vector_and_valid_token():
    # Raw vector from the gateware unit test: len 3, ts 10, SETUP token, + pad.
    recs = parse(bytes.fromhex("FF040000") + bytes.fromhex("0003000a2d0010") + b"\x00")
    pk = packets(recs)
    assert len(pk) == 1
    assert len(data(pk[0])) == 3
    assert ticks(pk[0]) == 10
    assert usbdecode.decode_packet(data(pk[0]))["pid"] == "SETUP"

    # Same framing with a properly CRC'd token -> crc_ok True.
    tok = token(SETUP, addr=3, ep=0)
    recs = parse(bytes.fromhex("FF040000") + pkt_record(tok, 10))
    d = usbdecode.decode_packet(data(packets(recs)[0]))
    assert d["pid"] == "SETUP"
    assert d["addr"] == 3 if "addr" in d else d["address"] == 3
    assert d.get("ep", d.get("endpoint")) == 0
    assert d["crc_ok"] is True


def test_timestamp_wrap():
    stream = bytes.fromhex("FF040000" "FF00FFFF" "00010123AB") + b"\x00"
    recs = parse(stream)
    pk = packets(recs)
    assert len(pk) == 1
    assert data(pk[0]) == b"\xab"
    assert ticks(pk[0]) == 0xFFFF + 0x0123


def test_capture_stop_event():
    recs = parse(bytes.fromhex("FF040000" "FF010123"))
    assert [code(r) for r in events(recs)] == [4, 1]
    assert ticks(recs[-1]) == 0x0123


def _sample_stream() -> bytes:
    return (
        bytes.fromhex("FF040000")
        + pkt_record(token(SETUP, 0, 0), 10)
        + pkt_record(data_pkt(DATA0, GET_DESC_DEVICE), 20)   # 11 bytes: odd
        + pkt_record(bytes([ACK]), 5)                         # 1 byte: odd
        + bytes.fromhex("FF00FFFF")
        + pkt_record(token(IN, 0, 0), 7)
        + pkt_record(data_pkt(DATA1, b"\x12\x01"), 3)         # 5 bytes: odd
        + pkt_record(bytes([ACK]), 2)
        + bytes.fromhex("FF010004")
    )


def _norm(records):
    out = []
    for r in records:
        k = kind(r)
        out.append((k, ticks(r), data(r) if k == "packet" else code(r)))
    return out


def test_byte_by_byte_feeding_is_identical():
    stream = _sample_stream()
    whole = _norm(parse(stream))
    for chunk in (1, 2, 3, 7, 512):
        assert _norm(parse(stream, chunk=chunk)) == whole
    assert len(packets(parse(stream))) == 6


def test_odd_length_padding():
    recs = parse(_sample_stream())
    pk = packets(recs)
    assert [len(data(p)) for p in pk] == [3, 11, 1, 3, 5, 1]
    assert data(pk[1]) == data_pkt(DATA0, GET_DESC_DEVICE)
    assert data(pk[2]) == bytes([ACK])
    # Cumulative ticks: 10, 30, 35, (+0xFFFF wrap) 35+0xFFFF+7, +3, +2
    base = 35 + 0xFFFF
    assert [ticks(p) for p in pk] == [10, 30, 35, base + 7, base + 10, base + 12]
    assert code(events(recs)[-1]) == 1


def test_long_packet_is_not_a_desync():
    # The gateware does not cap packet_size: babble > 1027 bytes is valid framing.
    body = bytes([0xC3]) + b"\xFF" * 1279  # 0xFF bytes must not be read as events
    stream = (bytes.fromhex("FF040000") + struct.pack(">HH", len(body), 1) + body
              + struct.pack(">HH", 1, 2) + bytes([0xD2, 0x00]))
    recs = parse(stream, chunk=100)
    assert not any("DESYNC" in as_text(r) for r in recs), recs
    pk = packets(recs)
    assert [len(data(p)) for p in pk] == [1280, 1]
    assert [ticks(p) for p in pk] == [1, 3]
    d = usbdecode.decode_packet(data(pk[0]))
    assert d.get("oversize") is True and "OVERSIZE" in as_text(d.get("error"))


def test_desync_on_impossible_length_stops_decoding():
    p = usbdecode.StreamParser()
    stream = bytes.fromhex("FF040000") + struct.pack(">HH", 0x3000, 1) + b"\x00" * 16
    recs = p.feed(stream)
    assert any("DESYNC" in as_text(r) for r in recs), recs
    assert p.desynced
    # Later bytes are not misread as fake headers / fake timestamps.
    assert p.feed(bytes.fromhex("FF010005") + struct.pack(">HH", 1, 7) + b"\xD2\x00") == []
    p.reset()
    assert not p.desynced


# ---------------------------------------------------------------------------
# decode_packet
# ---------------------------------------------------------------------------

def _crc_bad(d) -> bool:
    return d.get("crc_ok") is False and "CRC" in as_text(d.get("error", d.get("errors")))


def test_decode_handshakes():
    assert usbdecode.decode_packet(b"\xd2")["pid"] == "ACK"
    assert usbdecode.decode_packet(b"\x5a")["pid"] == "NAK"


def test_decode_data0_crc():
    good = data_pkt(DATA0, GET_DESC_DEVICE)
    d = usbdecode.decode_packet(good)
    assert d["pid"] == "DATA0"
    assert d["crc_ok"] is True
    assert GET_DESC_DEVICE.hex() in as_text(d).lower() or d.get("data") in (
        GET_DESC_DEVICE.hex(), GET_DESC_DEVICE)

    bad = bytearray(good)
    bad[3] ^= 0xFF
    d = usbdecode.decode_packet(bytes(bad))
    assert _crc_bad(d), d


def test_decode_sof_frame():
    frame = 0x5A3
    v = frame | (usbdecode.crc5_usb(frame) << 11)
    d = usbdecode.decode_packet(bytes([SOF, v & 0xFF, v >> 8]))
    assert d["pid"] == "SOF"
    assert d["frame"] == frame
    assert d["crc_ok"] is True


def test_decode_invalid_pid():
    d = usbdecode.decode_packet(b"\x2e\x00\x00")  # low nibble != ~high nibble
    assert d.get("pid_valid") is False or "PID" in as_text(d.get("error", d.get("errors")))


# ---------------------------------------------------------------------------
# decode_setup
# ---------------------------------------------------------------------------

def test_decode_setup_get_descriptor_device():
    d = usbdecode.decode_setup(GET_DESC_DEVICE)
    text = as_text(d)
    assert "GET_DESCRIPTOR" in text
    assert "DEVICE" in text
    assert 0x12 in [v for v in (d.values() if isinstance(d, dict) else []) if isinstance(v, int)] \
        or "WLENGTH': 18" in text or "LENGTH': 18" in text


# ---------------------------------------------------------------------------
# transactions and filtering
# ---------------------------------------------------------------------------

def _control_stream(with_nak: bool) -> bytes:
    s = (
        bytes.fromhex("FF040000")
        + pkt_record(token(SETUP, 0, 0), 10)
        + pkt_record(data_pkt(DATA0, GET_DESC_DEVICE), 10)
        + pkt_record(bytes([ACK]), 10)
    )
    if with_nak:
        s += pkt_record(token(IN, 0, 0), 10) + pkt_record(bytes([NAK]), 10)
    s += (
        pkt_record(token(IN, 0, 0), 10)
        + pkt_record(data_pkt(DATA1, bytes.fromhex("12010002")), 10)
        + pkt_record(bytes([ACK]), 10)
    )
    return s


def _txs(result):
    if isinstance(result, dict):
        result = result.get("transactions", result)
    return list(result)


def test_group_transactions_control_read():
    recs = parse(_control_stream(with_nak=True))
    txs = _txs(usbdecode.group_transactions(recs))
    assert len(txs) == 2, txs
    assert "GET_DESCRIPTOR" in as_text(txs[0])
    assert "SETUP" in as_text(txs[0])
    assert "IN" in as_text(txs[1])

    try:
        with_nak = _txs(usbdecode.group_transactions(recs, include_nak=True))
    except TypeError:
        pytest.skip("group_transactions has no include_nak parameter")
    assert len(with_nak) == 3


def _filter_records(flt, records):
    for name in ("apply", "filter", "filter_records", "__call__"):
        fn = getattr(flt, name, None)
        if fn is None:
            continue
        try:
            res = fn(records)
        except TypeError:
            continue
        if res is not None and not isinstance(res, bool):
            return list(res)
    for name in ("matches", "match", "accept"):
        fn = getattr(flt, name, None)
        if fn is not None:
            return [r for r in records if fn(r)]
    raise AssertionError("RecordFilter exposes no usable filtering method")


def test_record_filter_propagates_address_to_data():
    stream = (
        bytes.fromhex("FF040000")
        + pkt_record(token(OUT, 3, 1), 10)
        + pkt_record(data_pkt(DATA0, b"\xaa\xbb"), 10)
        + pkt_record(bytes([ACK]), 10)
        + pkt_record(token(OUT, 5, 1), 10)
        + pkt_record(data_pkt(DATA0, b"\xcc\xdd"), 10)
        + pkt_record(bytes([ACK]), 10)
    )
    recs = packets(parse(stream))
    flt = call_flex(usbdecode.RecordFilter, address=3, endpoint=1)
    kept = [r for r in _filter_records(flt, recs) if kind(r) == "packet"]
    kept_bytes = [data(r) for r in kept]
    assert token(OUT, 3, 1) in kept_bytes
    assert data_pkt(DATA0, b"\xaa\xbb") in kept_bytes
    assert token(OUT, 5, 1) not in kept_bytes
    assert data_pkt(DATA0, b"\xcc\xdd") not in kept_bytes


# ---------------------------------------------------------------------------
# pcap
# ---------------------------------------------------------------------------

START_NS = 1_700_000_000_123_456_789


def _make_pcap(records):
    fn = usbdecode.pcap_bytes
    params = inspect.signature(fn).parameters
    start_kw = next((n for n in params if "start" in n or "base" in n or "epoch" in n), None)
    kwargs = {"nanosecond": True}
    if start_kw:
        kwargs[start_kw] = START_NS
    return call_flex(fn, records, **kwargs), start_kw is not None


def _pcap_entries(parsed):
    if isinstance(parsed, dict):
        parsed = parsed.get("packets", parsed.get("records", parsed))
    out = []
    for e in parsed:
        if isinstance(e, dict):
            ts = e.get("ts_ns", e.get("timestamp_ns", e.get("t_ns", e.get("ts"))))
            d = e.get("data", e.get("bytes", e.get("raw")))
        elif isinstance(e, (tuple, list)):
            ts, d = e[0], e[-1]
        else:
            ts = getattr(e, "ts_ns", getattr(e, "timestamp_ns", None))
            d = getattr(e, "data", None)
        out.append((int(ts), bytes.fromhex(d) if isinstance(d, str) else bytes(d)))
    return out


def test_pcap_header_and_round_trip():
    recs = parse(_sample_stream())
    blob, has_start = _make_pcap(recs)
    assert isinstance(blob, (bytes, bytearray))
    magic, vmaj, vmin, _zone, _sig, snaplen, linktype = struct.unpack_from("<IHHiIII", blob, 0)
    assert magic == 0xA1B23C4D
    assert (vmaj, vmin) == (2, 4)
    assert linktype == 288
    assert snaplen >= 1027

    pk = packets(recs)
    try:
        parsed = usbdecode.read_pcap(bytes(blob))
    except (TypeError, OSError):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(blob)
            path = f.name
        try:
            parsed = usbdecode.read_pcap(path)
        finally:
            os.unlink(path)
    entries = _pcap_entries(parsed)
    assert [d for _, d in entries] == [data(p) for p in pk]

    expected = [ticks(p) * 50 // 3 for p in pk]
    got = [ts for ts, _ in entries]
    if has_start:
        got = [g - START_NS for g in got]
    else:
        got = [g - got[0] + expected[0] for g in got]
    for g, e in zip(got, expected):
        assert abs(g - e) <= 1, (got, expected)


def test_require_start_skips_stale_bytes_real_r14_stream():
    # Leftover tail of a previous capture (mid-record), then a real r1.4 FS stream.
    stale = bytes.fromhex("a5e0d4ff0003ea60a5e12cff0003ea5e")
    live = bytes.fromhex("ff050000" "0003185a" "a53124ff" "0003ea5b" "a53264ff")
    p = usbdecode.StreamParser(require_start=True)
    recs = []
    data = stale + live
    for i in range(0, len(data), 5):  # split across reads, incl. inside the marker
        recs += p.feed(data[i:i + 5])
    assert not p.desynced
    assert recs[0].kind == "event" and recs[0].code == 5
    pkts = [r for r in recs if r.kind == "packet"]
    assert [r.data for r in pkts] == [bytes.fromhex("a53124"), bytes.fromhex("a53264")]
    assert pkts[1].ticks - pkts[0].ticks == 0xEA5B


def test_drop_codes_counts_without_records_and_keeps_time():
    # START_FULL, 3 LINESTATE events, one SOF packet; LINESTATE dropped in-parser.
    data = bytes.fromhex("ff050000" "ff130010" "ff120010" "ff130010" "00030020" "a53124ff")
    p = usbdecode.StreamParser(require_start=True, drop_codes=frozenset(range(12, 21)))
    recs = p.feed(data)
    assert [r.kind for r in recs] == ["event", "packet"]
    assert p.dropped_by_code == {0x13: 2, 0x12: 1}
    assert recs[1].ticks == 0x10 * 3 + 0x20
    assert recs[1].seq == 4  # dropped records still consume sequence numbers
