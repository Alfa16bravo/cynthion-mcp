"""Tests for cynthion_mcp.analyzer (state helpers + CaptureManager).

No hardware is needed: the analyzer USB driver is replaced by
FakeAnalyzerDevice through ``analyzer._device_factory``.  The fake speaks the
real Cynthion analyzer bulk-stream format (verified against the installed
cynthion 0.2.5 gateware source, analyzer.py / events.py):

  EVENT  record : FF <code:u8> <ts:u16 BE>
  PACKET record : <len:u16 BE> <ts:u16 BE> <len bytes> [1 pad byte if len odd]

State register: bit0 ENABLE, bits[2:1] speed (HIGH=0, FULL=1, LOW=2, AUTO=3),
bits 3..6 power routing, bit7 POWER_CONTROL_ENABLE.
"""
from __future__ import annotations

import struct
import sys
import threading
import time
from pathlib import Path

import pytest

# src layout: make the package importable even without conftest / install.
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from cynthion_mcp import analyzer, common, usbdecode  # noqa: E402


# ---------------------------------------------------------------------------
# USB packet helpers (independent reference implementation of the CRCs)
# ---------------------------------------------------------------------------

def _crc5_usb(val11: int) -> int:
    c = 0x1F
    for i in range(11):
        bit = (val11 >> i) & 1
        if (c ^ bit) & 1:
            c = (c >> 1) ^ 0x14
        else:
            c >>= 1
    return c ^ 0x1F


def _crc16_usb(data: bytes) -> int:
    c = 0xFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return c ^ 0xFFFF


def _token(pid_byte: int, addr: int, ep: int) -> bytes:
    v = (addr & 0x7F) | ((ep & 0xF) << 7)
    v |= _crc5_usb(v) << 11
    return bytes([pid_byte, v & 0xFF, v >> 8])


def _sof(frame: int) -> bytes:
    v = frame & 0x7FF
    v |= _crc5_usb(v) << 11
    return bytes([0xA5, v & 0xFF, v >> 8])


def _data(pid_byte: int, payload: bytes) -> bytes:
    return bytes([pid_byte]) + payload + _crc16_usb(payload).to_bytes(2, "little")


PID_IN, PID_OUT, PID_SETUP = 0x69, 0xE1, 0x2D
PID_DATA0, PID_DATA1 = 0xC3, 0x4B
PID_ACK, PID_NAK = 0xD2, 0x5A


def _mixed_traffic(n_frames: int = 20) -> list[bytes]:
    """SOF + IN/DATA1/ACK transaction per frame, plus a few NAKed INs."""
    pkts: list[bytes] = []
    for f in range(n_frames):
        pkts.append(_sof(f))
        pkts.append(_token(PID_IN, 5, 1))
        pkts.append(_data(PID_DATA1 if f & 1 else PID_DATA0, bytes([f, 1, 2])))  # odd length -> pad
        pkts.append(bytes([PID_ACK]))
        if f % 5 == 0:
            pkts.append(_token(PID_IN, 5, 2))
            pkts.append(bytes([PID_NAK]))
    return pkts


def _packet_record(pkt: bytes, ts: int = 10) -> bytes:
    rec = struct.pack(">HH", len(pkt), ts) + pkt
    if len(pkt) & 1:
        rec += b"\x00"
    return rec


def _event_record(code: int, ts: int = 0) -> bytes:
    return bytes([0xFF, code]) + struct.pack(">H", ts)


# ---------------------------------------------------------------------------
# Fake analyzer driver
# ---------------------------------------------------------------------------

class FakeAnalyzerDevice:
    """Stand-in for the analyzer USB driver used by CaptureManager.

    It records every state write, and when ENABLE is set it queues a
    CAPTURE_START event (+ SPEED_DETECT_HIGH in auto mode) followed by the
    configured packets; clearing ENABLE queues CAPTURE_STOP_NORMAL.
    """

    def __init__(self, packets=None, chunk=4096):
        self.packets = list(packets if packets is not None else _mixed_traffic())
        self.chunk = chunk
        self.state_writes: list[int] = []
        self._state = 0
        self._buf = bytearray()
        self._lock = threading.Lock()
        self.closed = False
        self.test_config: list[int] = []
        # Identification attributes a driver typically exposes.
        self.serial = "FAKE0001"
        self.serial_number = "FAKE0001"
        self.revision = "r1.4"
        self.major = 1
        self.minor = 1
        self.protocol_major = 1
        self.protocol_minor = 1
        self.protocol_version = "1.1"
        self.bcd_device = 0x0104

    # --- state register -------------------------------------------------
    def set_state(self, value: int) -> None:
        value &= 0xFF
        with self._lock:
            was_enabled = bool(self._state & 1)
            self.state_writes.append(value)
            self._state = value
            if value & 1:
                # Starting resets the FIFOs and discards stale data.
                self._buf.clear()
                speed = (value >> 1) & 3
                self._buf += _event_record(4 | speed, 0)  # CAPTURE_START_*
                if speed == 3:
                    self._buf += _event_record(8, 5)      # SPEED_DETECT_HIGH
                for p in self.packets:
                    self._buf += _packet_record(p)
            elif was_enabled:
                self._buf += _event_record(1, 0x123)      # CAPTURE_STOP_NORMAL

    def get_state(self) -> int:
        return self._state

    def state(self) -> int:  # name used by the research sketch
        return self._state

    def start(self, speed="auto", power_bits=0, **_kw) -> None:
        code = {"high": 0, "full": 1, "low": 2, "auto": 3}[speed]
        self.set_state(1 | (code << 1) | power_bits)

    def stop(self) -> None:
        self.set_state(self._state & ~1)

    # --- capabilities -----------------------------------------------------
    def get_speeds(self) -> list[str]:
        return ["auto", "low", "full", "high"]

    speeds = get_speeds

    def get_speeds_mask(self) -> int:
        return 0x0F

    def get_minor_version(self) -> int:
        return 1

    def set_test_config(self, value: int) -> None:
        self.test_config.append(value)

    def test_device(self, connect=True, speed="high") -> None:
        self.test_config.append(int(connect) | ({"high": 0, "full": 1, "low": 2}[speed] << 1))

    # --- bulk stream -------------------------------------------------------
    def read(self, size: int = 16384, timeout_ms: int = 100, **_kw) -> bytes:
        with self._lock:
            n = min(size or self.chunk, self.chunk, len(self._buf))
            if n:
                out = bytes(self._buf[:n])
                del self._buf[:n]
                return out
        time.sleep(min(timeout_ms, 20) / 1000.0)
        return b""

    read_raw = read
    read_stream = read

    def close(self) -> None:
        self.closed = True

    def info(self) -> dict:
        return {"serial": self.serial, "revision": self.revision,
                "protocol_version": self.protocol_version}


# ---------------------------------------------------------------------------
# Tolerant accessors (status / record shapes)
# ---------------------------------------------------------------------------

def _first(d: dict, *keys, default=None):
    for k in keys:
        if isinstance(d, dict) and k in d and d[k] is not None:
            return d[k]
    return default


def _status_state(st: dict) -> str:
    s = _first(st, "state", "status")
    if isinstance(s, str):
        return s
    return "running" if _first(st, "running", default=False) else "stopped"


def _status_packets(st: dict) -> int:
    v = _first(st, "packets", "packet_count", "packets_captured", "total_packets", default=0)
    if isinstance(v, dict):
        v = _first(v, "total", "count", "captured", default=0)
    return int(v)


def _status_dropped(st: dict) -> int:
    return int(_first(st, "dropped_records", "dropped", default=0))


def _rec_pid(rec: dict):
    pid = _first(rec, "pid", "pid_name")
    if pid is None and isinstance(rec.get("decoded"), dict):
        pid = _first(rec["decoded"], "pid", "pid_name")
    return pid


def _rec_kind(rec: dict):
    return _first(rec, "kind", "type")


def _is_running(cm) -> bool:
    return bool(cm.is_running())


def _wait(pred, timeout=2.0, step=0.02) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(step)
    return pred()


def _pcap_count(result) -> int:
    if isinstance(result, dict):
        pk = _first(result, "packets", "records")
        return len(pk) if isinstance(pk, (list, tuple)) else int(pk)
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], (list, tuple)):
        return len(result[1])  # (header, packets)
    return len(list(result))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake(monkeypatch):
    dev = FakeAnalyzerDevice()
    monkeypatch.setattr(analyzer, "_device_factory", lambda serial=None, **_kw: dev)
    return dev


@pytest.fixture
def cm():
    mgr = analyzer.CaptureManager()
    yield mgr
    try:
        if mgr.is_running():
            mgr.stop()
    except Exception:
        pass


def _capture_all(mgr, fake_dev, **start_kw):
    """Start, wait until every fake packet is counted, then stop."""
    mgr.start(**start_kw)
    expected = len(fake_dev.packets)
    _wait(lambda: _status_packets(mgr.status()) >= expected, timeout=2.0)
    mgr.stop()
    return mgr.status()


# ---------------------------------------------------------------------------
# build_state / decode_state
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("speed,value", [("high", 0x01), ("full", 0x03), ("low", 0x05), ("auto", 0x07)])
def test_build_state_speeds(speed, value):
    assert analyzer.build_state(speed, True) == value
    assert analyzer.build_state(speed, False) == value & ~1


def _build_with_power(speed, **flags):
    """Call build_state with power flags, accepting dict or keyword styles."""
    try:
        return analyzer.build_state(speed, True, power=flags)
    except TypeError:
        return analyzer.build_state(speed, True, **flags)


@pytest.mark.parametrize("flag,bit", [
    ("vbus_from_target_c", 0x08),
    ("vbus_from_control_host", 0x10),
    ("vbus_from_aux", 0x20),
    ("discharge_target_a", 0x40),
])
def test_build_state_power_bits(flag, bit):
    v = _build_with_power("high", **{flag: True})
    assert v == 0x80 | bit | 0x01


@pytest.mark.parametrize("value", [0x00, 0x01, 0x03, 0x05, 0x07, 0x06, 0x89, 0x97, 0xB1, 0xC5])
def test_decode_state_round_trip(value):
    d = analyzer.decode_state(value)
    assert isinstance(d, dict)
    assert bool(_first(d, "enabled", "enable")) == bool(value & 1)
    speed = d["speed"]
    assert speed == ["high", "full", "low", "auto"][(value >> 1) & 3]
    power_ctl = bool(_first(d, "power_control", "power_control_enable", default=False))
    assert power_ctl == bool(value & 0x80)
    flags = {}
    if power_ctl:
        flags = {k: True for k, b in (("vbus_from_target_c", 0x08), ("vbus_from_control_host", 0x10),
                                      ("vbus_from_aux", 0x20), ("discharge_target_a", 0x40))
                 if value & b}
        rebuilt = _build_with_power(speed, **flags) if flags else (analyzer.build_state(speed, True) | 0x80)
        rebuilt = rebuilt if value & 1 else rebuilt & ~1
    else:
        rebuilt = analyzer.build_state(speed, bool(value & 1))
    assert rebuilt == value


# ---------------------------------------------------------------------------
# CaptureManager lifecycle
# ---------------------------------------------------------------------------

def test_start_status_stop(fake, cm):
    cm.start(speed="auto")
    st = cm.status()
    assert _status_state(st) == "running"
    assert cm.is_running()

    expected = len(fake.packets)
    assert _wait(lambda: _status_packets(cm.status()) >= expected, timeout=2.0), cm.status()

    cm.stop()
    st = cm.status()
    assert _status_state(st) == "stopped"
    assert not cm.is_running()

    # The fake saw an AUTO start (0x07) followed by a write with ENABLE cleared.
    assert 0x07 in fake.state_writes
    i = fake.state_writes.index(0x07)
    assert any((v & 1) == 0 for v in fake.state_writes[i + 1:]), fake.state_writes
    assert st.get("stop_event_received") is True
    assert _status_packets(st) == expected


def test_read_filters_and_pagination(fake, cm):
    _capture_all(cm, fake, speed="high")

    # include_sof=False hides SOF packets.
    res = cm.read(start_seq=0, limit=2000, include_sof=False)
    recs = res["records"]
    assert recs
    assert all(_rec_pid(r) != "SOF" for r in recs if _rec_kind(r) == "packet")

    all_res = cm.read(start_seq=0, limit=2000, include_sof=True)
    sofs = [r for r in all_res["records"] if _rec_kind(r) == "packet" and _rec_pid(r) == "SOF"]
    assert len(sofs) == sum(1 for p in fake.packets if p[0] == 0xA5)

    # Pagination: limit respected, next_seq continues without overlap.
    page1 = cm.read(start_seq=0, limit=10, include_sof=True)
    assert len(page1["records"]) == 10
    nxt = page1["next_seq"]
    page2 = cm.read(start_seq=nxt, limit=10, include_sof=True)
    assert 0 < len(page2["records"]) <= 10
    seqs1 = [r["seq"] for r in page1["records"]]
    seqs2 = [r["seq"] for r in page2["records"]]
    assert seqs1 == sorted(seqs1) and seqs2 == sorted(seqs2)
    assert min(seqs2) >= nxt > max(seqs1)
    assert not set(seqs1) & set(seqs2)


def test_ring_buffer_overflow(monkeypatch, cm):
    pkts = [bytes([PID_ACK]) if i % 2 else _token(PID_IN, 3, 1) for i in range(1500)]
    dev = FakeAnalyzerDevice(packets=pkts)
    monkeypatch.setattr(analyzer, "_device_factory", lambda serial=None, **_kw: dev)

    cm.start(speed="high", buffer_packets=1000)
    _wait(lambda: _status_packets(cm.status()) >= 1500, timeout=3.0)
    cm.stop()
    st = cm.status()
    dropped = _status_dropped(st)
    # 1500 packets (+ start/stop events, depending on whether events count as records).
    assert 500 <= dropped <= 502, st

    res = cm.read(start_seq=0, limit=50)
    assert res["truncated"] is True
    assert res["first_available_seq"] >= 500
    assert all(r["seq"] >= res["first_available_seq"] for r in res["records"])


def test_duration_auto_stop(fake, cm):
    cm.start(speed="full", duration_s=0.3)
    assert cm.is_running()
    assert _wait(lambda: not cm.is_running(), timeout=3.0), cm.status()
    assert _status_state(cm.status()) == "stopped"
    assert 0x03 in fake.state_writes
    assert (fake.state_writes[-1] & 1) == 0


# ---------------------------------------------------------------------------
# pcap export
# ---------------------------------------------------------------------------

def test_export_pcap_roundtrip(fake, cm, tmp_path):
    _capture_all(cm, fake, speed="high")
    out = tmp_path / "cap.pcap"
    res = cm.export_pcap(str(out))
    assert out.is_file() and out.stat().st_size > 24
    n = int(_first(res, "packets", "count"))
    assert n == len(fake.packets)

    back = usbdecode.read_pcap(str(out))
    assert _pcap_count(back) == n
    with open(out, "rb") as f:
        magic, _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack("<IHHiIII", f.read(24))
    assert magic in (0xA1B23C4D, 0xA1B2C3D4)
    assert linktype == 288


def test_export_pcap_without_packets(fake, cm, tmp_path):
    with pytest.raises(common.InvalidArgumentError):
        cm.export_pcap(str(tmp_path / "empty.pcap"))


# ---------------------------------------------------------------------------
# Busy handling
# ---------------------------------------------------------------------------

def test_start_while_running_is_busy(fake, cm):
    cm.start(speed="high")
    with pytest.raises(common.BusyError):
        cm.start(speed="high")


def test_clear_while_running_is_busy(fake, cm):
    cm.start(speed="high")
    with pytest.raises(common.BusyError):
        cm.clear()
    cm.stop()
    cm.clear()  # allowed once stopped
    assert _status_packets(cm.status()) == 0 or cm.read(start_seq=0, limit=10)["records"] == []


def test_start_clears_stale_enable_first(fake, cm):
    # A previous process died with the analyzer enabled (maybe in OVERRUN):
    # ENABLE must be cleared before re-enabling so the FSM goes through AWAIT_START.
    fake.set_state(0x01)
    fake.state_writes.clear()
    cm.start(speed="high")
    assert fake.state_writes[0] & 1 == 0, fake.state_writes
    assert fake.state_writes[1] == 0x01, fake.state_writes
    _wait(lambda: _status_packets(cm.status()) >= len(fake.packets), timeout=2.0)
    cm.stop()
    st = cm.status()
    assert st["error"] is None, st


def test_concurrent_starts_only_one_wins(fake, cm):
    import concurrent.futures as cf
    with cf.ThreadPoolExecutor(4) as ex:
        futs = [ex.submit(cm.start, speed="high") for _ in range(4)]
        results = []
        for f in futs:
            try:
                results.append(f.result())
            except common.BusyError:
                results.append("busy")
    assert sum(1 for r in results if r != "busy") == 1, results
    assert sum(1 for v in fake.state_writes if v & 1) == 1, fake.state_writes
    cm.stop()


def test_desync_stops_capture_with_error(fake, cm):
    fake.packets = []
    cm.start(speed="high")
    with fake._lock:
        fake._buf += struct.pack(">HH", 0x3000, 0) + b"\x00" * 8
    # Error is flagged by the parser thread; the reader thread then disables.
    _wait(lambda: cm.status()["state"] == "error" and not cm.is_running(), timeout=5.0)
    st = cm.status()
    assert st["state"] == "error" and "synchronis" in (st["error"] or ""), st
    assert (fake.state_writes[-1] & 1) == 0, fake.state_writes


def test_activity_registry_reports_capture(fake):
    capture = analyzer.CAPTURE
    common.ACTIVITY.check_free()  # nothing running yet
    capture.start(speed="high")
    try:
        with pytest.raises(common.BusyError):
            common.ACTIVITY.check_free()
    finally:
        capture.stop()
    common.ACTIVITY.check_free()
    try:
        capture.clear()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# No hardware
# ---------------------------------------------------------------------------

def test_start_without_hardware(monkeypatch, cm):
    import usb.core

    def _find_nothing(*_a, find_all=False, **_kw):
        return iter(()) if find_all else None

    monkeypatch.setattr(usb.core, "find", _find_nothing)
    with pytest.raises((common.NoDeviceError, common.WrongModeError)):
        cm.start(speed="auto")
    assert not cm.is_running()
