"""Cynthion USB analyzer driver and background capture engine.

Talks to the analyzer gateware (VID 0x1d50 / PID 0x615b, interface 0 with
class 0xFF / subclass 0x10) through pyusb.  Protocol facts were checked against
the installed ``cynthion/gateware/analyzer/{top,analyzer,events,speeds}.py``:

* vendor requests go to interface 0, bmRequestType 0xC1 (IN) / 0x41 (OUT),
  wIndex MUST be 0 or the gateware does not claim the request (STALL);
* GET_STATE=0, SET_STATE=1 (state in low 8 bits of wValue), GET_SPEEDS=2,
  SET_TEST_CONFIG=3, GET_MINOR_VERSION=4;
* state register: bit0 enable, bits[2:1] speed (HIGH=0, FULL=1, LOW=2,
  AUTO=3), bits 3..6 power routing, bit7 power-control enable;
* capture data arrives on bulk IN 0x81 and is decoded by ``usbdecode``.

All USB access is lazy (``usb`` is imported inside functions) so the module
imports fine without pyusb / libusb / hardware.
"""

from __future__ import annotations

import collections
import dataclasses
import queue
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, List, Optional

from .usbdecode import (
    AnalyzerEvent,
    Record,
    RecordFilter,
    SPEED_BITS,
    SPEED_NAMES,
    StreamParser,
    filter_records,
    group_transactions,
    pcap_bytes,
    record_to_dict,  # noqa: F401  (re-exported for callers / tests)
    summarize,
    write_pcap,
)
from .common import (
    ACTIVITY,
    HINT_ANALYZER,
    HINT_WINUSB,
    BusyError,
    InvalidArgumentError,
    NoDeviceError,
    UnsupportedError,
    WrongModeError,
    logger,
    resolve_output_file,
    stdout_to_stderr,
    timestamp_slug,
    translate_exception,
)
from . import device as _device_mod
from .device import PID_CYNTHION, SUBCLASS_ANALYZER, VID_GSG, _get_backend

import logging as _logging

log = _logging.getLogger("cynthion_mcp.analyzer")  # child of common.logger
_ = logger  # imported per design; kept for API symmetry

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------
REQ_GET_STATE = 0
REQ_SET_STATE = 1
REQ_GET_SPEEDS = 2
REQ_SET_TEST_CONFIG = 3
REQ_GET_MINOR_VERSION = 4

BM_IN = 0xC1   # device-to-host | vendor | interface
BM_OUT = 0x41  # host-to-device | vendor | interface

EP_IN = 0x81
READ_SIZE = 16384
READ_TIMEOUT_MS = 100
CTRL_TIMEOUT_MS = 1000

STATE_ENABLE = 0x01
STATE_SPEED_SHIFT = 1
STATE_SPEED_MASK = 0x06

VBUS_FROM_TARGET_C = 0x08
VBUS_FROM_CONTROL_HOST = 0x10
VBUS_FROM_AUX = 0x20
TARGET_A_DISCHARGE = 0x40
POWER_CONTROL_ENABLE = 0x80

SUPPORTED_SPEED_BITS = {"auto": 0x01, "low": 0x02, "full": 0x04, "high": 0x08}

# Event codes (cynthion/gateware/analyzer/events.py).  Kept local as ints so the
# capture loop does not depend on the exact shape of usbdecode.AnalyzerEvent.
_EV_CAPTURE_STOP_NORMAL = int(getattr(AnalyzerEvent, "CAPTURE_STOP_NORMAL", 1))
_EV_LINESTATE_FIRST = 12     # LINESTATE_SE0 .. LINESTATE_SE1
_EV_LINESTATE_LAST = 20
_EV_NONE = 0                 # timestamp wrap filler
_EV_CAPTURE_START_BASE = 4   # 4..7  = CAPTURE_START_{HIGH,FULL,LOW,AUTO}
_EV_SPEED_DETECT_BASE = 8    # 8..11 = SPEED_DETECT_{HIGH,FULL,LOW,AUTO}

_FALLBACK_SPEED_NAMES = ("high", "full", "low", "auto")

PID_SOF = 0x5
MAX_CACHED_PCAP = 64 * 1024 * 1024
DRAIN_MAX_S = 2.0
MAX_BACKLOG_BYTES = 1024 * 1024 * 1024  # raw bytes queued for the parser
DRAIN_MAX_EMPTY_READS = 3
IDLE_WARNING_S = 5.0


def _speed_name(value: int) -> str:
    """Map the 2-bit gateware speed value to its name."""
    try:
        name = SPEED_NAMES[value]
        if name:
            return str(getattr(name, "name", name)).lower()
    except (KeyError, IndexError, TypeError):
        pass
    return _FALLBACK_SPEED_NAMES[value & 0x3]


# ---------------------------------------------------------------------------
# State register helpers
# ---------------------------------------------------------------------------
def build_state(
    speed: str,
    enable: bool,
    vbus_from_target_c: Optional[bool] = None,
    vbus_from_control_host: Optional[bool] = None,
    vbus_from_aux: Optional[bool] = None,
    discharge_target_a: Optional[bool] = None,
) -> int:
    """Build the analyzer state register value.

    Power bits are only meaningful when POWER_CONTROL_ENABLE (bit7) is set; it
    is set as soon as any power argument is not None.  Leaving all of them at
    None keeps the default pass-through of VBUS from TARGET-C to TARGET-A.
    """
    if speed not in SPEED_BITS:
        raise InvalidArgumentError(
            f"Unknown speed: {speed!r}", "Valid values: " + ", ".join(SPEED_BITS)
        )
    v = (STATE_ENABLE if enable else 0) | (int(SPEED_BITS[speed]) << STATE_SPEED_SHIFT)
    power = (
        (vbus_from_target_c, VBUS_FROM_TARGET_C),
        (vbus_from_control_host, VBUS_FROM_CONTROL_HOST),
        (vbus_from_aux, VBUS_FROM_AUX),
        (discharge_target_a, TARGET_A_DISCHARGE),
    )
    if any(arg is not None for arg, _ in power):
        v |= POWER_CONTROL_ENABLE
        for arg, bit in power:
            if arg:
                v |= bit
    return v & 0xFF


def decode_state(v: int) -> Dict[str, Any]:
    """Decode the analyzer state register into named fields."""
    v = int(v) & 0xFF
    return {
        "raw": v,
        "enabled": bool(v & STATE_ENABLE),
        "speed": _speed_name((v & STATE_SPEED_MASK) >> STATE_SPEED_SHIFT),
        "power_control": bool(v & POWER_CONTROL_ENABLE),
        "power_control_enabled": bool(v & POWER_CONTROL_ENABLE),
        "vbus_from_target_c": bool(v & VBUS_FROM_TARGET_C),
        "vbus_from_control_host": bool(v & VBUS_FROM_CONTROL_HOST),
        "vbus_from_aux": bool(v & VBUS_FROM_AUX),
        "discharge_target_a": bool(v & TARGET_A_DISCHARGE),
    }


def _has_analyzer_iface(dev: Any) -> bool:
    """True when the device exposes a vendor interface with the analyzer subclass."""
    try:
        for cfg in dev:
            for intf in cfg:
                if intf.bInterfaceClass == 0xFF and intf.bInterfaceSubClass == SUBCLASS_ANALYZER:
                    return True
    except Exception:  # descriptor read failure (driver issue) -> not ours
        return False
    return False


def _safe_serial(dev: Any) -> Optional[str]:
    try:
        return dev.serial_number
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Thin pyusb wrapper
# ---------------------------------------------------------------------------
class AnalyzerDevice:
    """One open handle on the analyzer gateware (interface 0 claimed)."""

    def __init__(self, dev: Any):
        self.dev = dev
        self.protocol_major: int = 0
        self.protocol_minor: int = 0
        self._serial: Optional[str] = None
        self._closed = False

    # -- construction ------------------------------------------------------
    @classmethod
    def open(cls, serial: Optional[str] = None) -> "AnalyzerDevice":
        import usb.core
        import usb.util

        def _match(d: Any) -> bool:
            if not _has_analyzer_iface(d):
                return False
            return serial is None or _safe_serial(d) == serial

        try:
            dev = usb.core.find(
                idVendor=VID_GSG,
                idProduct=PID_CYNTHION,
                backend=_get_backend(),
                custom_match=_match,
            )
        except Exception as exc:  # NoBackendError, USBError...
            raise translate_exception(exc) from exc

        if dev is None:
            count = 0
            try:
                count = int(_device_mod.list_devices().get("count", 0))
            except Exception:
                count = 0
            what = "Analyzer gateware not detected"
            if serial is not None:
                what += f" (serial number {serial})"
            if count == 0:
                raise NoDeviceError(
                    "No Cynthion detected (neither analyzer gateware nor Apollo).",
                    HINT_ANALYZER,
                )
            raise WrongModeError(what, HINT_ANALYZER)

        self = cls(dev)
        try:
            try:
                dev.set_configuration()
            except usb.core.USBError:
                pass  # already configured (or WinUSB refuses re-config): fine
            usb.util.claim_interface(dev, 0)
            try:
                intf = dev.get_active_configuration()[(0, 0)]
                self.protocol_major = int(intf.bInterfaceProtocol)
            except Exception:
                self.protocol_major = 0
            try:
                self.protocol_minor = int(self.ctrl_in(REQ_GET_MINOR_VERSION, 1)[0])
            except Exception:
                self.protocol_minor = 0
            self._serial = _safe_serial(dev)
        except Exception as exc:
            self.close()
            err = translate_exception(exc)
            if getattr(err, "hint", None) is None and getattr(err, "code", "") == "DRIVER":
                err.hint = HINT_WINUSB
            raise err from exc
        return self

    # -- control requests ----------------------------------------------------
    def ctrl_in(self, req: int, length: int = 1) -> bytes:
        return bytes(self.dev.ctrl_transfer(BM_IN, req, 0, 0, length, timeout=CTRL_TIMEOUT_MS))

    def ctrl_out(self, req: int, value: int) -> None:
        # wIndex MUST be 0, otherwise the gateware does not handle the request.
        self.dev.ctrl_transfer(BM_OUT, req, int(value) & 0xFFFF, 0, None, timeout=CTRL_TIMEOUT_MS)

    def get_state(self) -> int:
        return self.ctrl_in(REQ_GET_STATE, 1)[0]

    def set_state(self, v: int) -> None:
        self.ctrl_out(REQ_SET_STATE, int(v) & 0xFF)

    def get_speeds(self) -> List[str]:
        mask = self.ctrl_in(REQ_GET_SPEEDS, 1)[0]
        return [name for name, bit in SUPPORTED_SPEED_BITS.items() if mask & bit]

    def set_test_config(self, connect: bool, speed: str) -> int:
        if speed not in ("high", "full", "low"):
            raise InvalidArgumentError(f"Invalid test speed: {speed!r}", "high, full or low")
        value = (1 if connect else 0) | (int(SPEED_BITS[speed]) << 1)
        self.ctrl_out(REQ_SET_TEST_CONFIG, value)
        return value

    # -- bulk stream -------------------------------------------------------
    def read(self, size: int = READ_SIZE, timeout_ms: int = READ_TIMEOUT_MS) -> bytes:
        import usb.core

        try:
            return bytes(self.dev.read(EP_IN, size, timeout_ms))
        except usb.core.USBTimeoutError:
            return b""

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            import usb.util
        except Exception:
            return
        try:
            usb.util.release_interface(self.dev, 0)
        except Exception:
            pass
        try:
            usb.util.dispose_resources(self.dev)
        except Exception:
            pass

    # -- properties ----------------------------------------------------------
    @property
    def serial(self) -> Optional[str]:
        return self._serial

    @property
    def bcd_device(self) -> Optional[int]:
        try:
            return int(self.dev.bcdDevice)
        except Exception:
            return None

    @property
    def protocol_version(self) -> str:
        return f"{self.protocol_major}.{self.protocol_minor}"


# Indirection used by tests to inject a fake device.
_device_factory: Callable[[Optional[str]], Any] = AnalyzerDevice.open


def _open_device(serial: Optional[str]) -> Any:
    # Look the factory up at call time so tests can monkeypatch it.
    return globals()["_device_factory"](serial)


def _revision(bcd: Optional[int]) -> Optional[str]:
    if bcd is None:
        return None
    return f"r{(bcd >> 8) & 0xFF}.{bcd & 0xFF}"


# ---------------------------------------------------------------------------
# Capture engine
# ---------------------------------------------------------------------------
@dataclass
class CaptureConfig:
    speed: str = "auto"
    buffer_packets: int = 200000
    duration_s: Optional[float] = None
    include_sof_in_buffer: bool = True
    #: Keep LINESTATE_* events (codes 12-20). The gateware emits several per
    #: packet (~8 per FS SOF), so they are counted but not stored by default.
    include_linestate: bool = False
    vbus_from_target_c: Optional[bool] = None
    vbus_from_control_host: Optional[bool] = None
    vbus_from_aux: Optional[bool] = None
    discharge_target_a: Optional[bool] = None

    def power_kwargs(self) -> Dict[str, Optional[bool]]:
        return {
            "vbus_from_target_c": self.vbus_from_target_c,
            "vbus_from_control_host": self.vbus_from_control_host,
            "vbus_from_aux": self.vbus_from_aux,
            "discharge_target_a": self.discharge_target_a,
        }


def _is_sof(rec: Any) -> bool:
    data = getattr(rec, "data", None)
    return getattr(rec, "kind", None) == "packet" and bool(data) and (data[0] & 0xF) == PID_SOF


class CaptureManager:
    """Owns one background reader thread and a ring buffer of decoded records."""

    def __init__(self) -> None:
        self._lock = threading.Lock()  # protects records / counters
        # Serialises start/stop/clear: tools run concurrently in worker threads
        # (common.run_blocking -> anyio.to_thread), so the busy check and the
        # device open / thread spawn must be one atomic step.
        self._ctl_lock = threading.RLock()
        self._cfg = CaptureConfig()
        self._records: Deque[Record] = collections.deque(maxlen=self._cfg.buffer_packets)
        self._dropped = 0
        self._thread: Optional[threading.Thread] = None
        self._stop_evt = threading.Event()
        self._dev: Any = None
        self._parser = StreamParser(require_start=True)
        self._state = "idle"
        self._error: Optional[str] = None
        self._start_wall_ns: Optional[int] = None
        self._start_mono: Optional[float] = None
        self._stop_mono: Optional[float] = None
        self._bytes = 0
        self._packets = 0
        self._events = 0
        self._sofs = 0
        self._wraps = 0
        self._linestate = 0
        self._backlog = 0
        self._rawq: Any = None
        self._wraps_direct = 0
        self._linestate_direct = 0
        self._last_data_mono: Optional[float] = None
        self._stop_event_seen = False
        self._detected_speed: Optional[str] = None
        self._last_pcap: Optional[bytes] = None
        self._serial: Optional[str] = None
        self._bcd: Optional[int] = None
        self._protocol: Optional[str] = None
        try:
            ACTIVITY.register(
                "analyzer_capture",
                self.is_running,
                "USB analyzer capture in progress",
                "analyzer_stop",
            )
        except Exception:  # registry problems must never break import
            log.debug("ACTIVITY.register failed", exc_info=True)

    # -- state ---------------------------------------------------------------
    def is_running(self) -> bool:
        if self._state == "starting":
            # Busy even before the reader thread exists (start() in progress).
            return True
        # Busy as long as the reader thread lives: after a parser error the
        # state is already "error" while the reader still disables the
        # analyzer, closes the device and waits for the parser backlog.
        t = self._thread
        return t is not None and t.is_alive()

    def _drop_codes(self) -> "frozenset[int]":
        """Event codes counted but not stored (decoded cheaply in the parser)."""
        codes = {_EV_NONE}
        if not self._cfg.include_linestate:
            codes.update(range(_EV_LINESTATE_FIRST, _EV_LINESTATE_LAST + 1))
        return frozenset(codes)

    def _reset_buffers(self, maxlen: int) -> None:
        with self._lock:
            self._records = collections.deque(maxlen=maxlen)
            self._dropped = 0
            self._parser = StreamParser(require_start=True, drop_codes=self._drop_codes())
            self._bytes = self._packets = self._events = self._sofs = 0
            self._wraps = 0
            self._linestate = 0
            self._backlog = 0
            self._rawq = None
            self._wraps_direct = 0
            self._linestate_direct = 0
            self._last_data_mono = None
            self._stop_event_seen = False
            self._detected_speed = None
            self._last_pcap = None
            self._error = None

    # -- start / stop --------------------------------------------------------
    def start(
        self, cfg: Optional[CaptureConfig] = None, serial: Optional[str] = None, **kwargs: Any
    ) -> Dict[str, Any]:
        """Start a capture from a CaptureConfig, or from CaptureConfig field keywords
        (e.g. ``start(speed="high", buffer_packets=1000)``)."""
        with self._ctl_lock:
            return self._start_locked(cfg, serial, **kwargs)

    @staticmethod
    def _force_disable(dev: Any) -> None:
        """Clear ENABLE (keeping the power bits) and drain stale stream data.

        The gateware only restarts a capture (FIFO reset, endpoint discard,
        CAPTURE_START event, timestamp reset) on ``starting = stopped &
        capture_enable``, i.e. when the FSM is in AWAIT_START.  If a previous
        process died with the analyzer still enabled (possibly stuck in
        OVERRUN, which only exits on ~capture_enable), writing ENABLE=1 again
        would be a no-op.  Clearing ENABLE first forces the FSM back through
        AWAIT_START so the following enable is a clean restart.
        """
        try:
            cur = int(dev.get_state()) & 0xFF
        except Exception as exc:
            log.debug("get_state before start failed: %s", exc)
            cur = 0
        dev.set_state(cur & ~STATE_ENABLE & 0xFF)
        if cur & STATE_ENABLE:
            log.info("Analyzer was left enabled (state=0x%02x); stopped it before restart", cur)
        # Always drain: bytes of a previous capture (e.g. after a stop or a
        # desync) can remain queued on EP 0x81 and would start the next
        # stream in the middle of a record (observed on r1.4 hardware).
        end = time.monotonic() + DRAIN_MAX_S
        empty = 0
        while empty < DRAIN_MAX_EMPTY_READS and time.monotonic() < end:
            try:
                data = dev.read()
            except Exception as exc:
                log.debug("Pre-start drain read failed: %s", exc)
                break
            empty = 0 if data else empty + 1

    def _start_locked(
        self, cfg: Optional[CaptureConfig], serial: Optional[str], **kwargs: Any
    ) -> Dict[str, Any]:
        if cfg is None:
            try:
                cfg = CaptureConfig(**kwargs)
            except TypeError as exc:
                raise InvalidArgumentError(f"Invalid capture parameter: {exc}") from exc
        elif kwargs:
            cfg = dataclasses.replace(cfg, **kwargs)
        if self.is_running():
            raise BusyError("Capture already running", "analyzer_stop()")
        ACTIVITY.check_free(allow=("analyzer_capture",))
        if cfg.speed not in SPEED_BITS:
            raise InvalidArgumentError(
                f"Unknown speed: {cfg.speed!r}", "Valid values: " + ", ".join(SPEED_BITS)
            )
        if cfg.buffer_packets < 1:
            raise InvalidArgumentError("buffer_packets must be >= 1")
        state_value = build_state(cfg.speed, True, **cfg.power_kwargs())

        self._state = "starting"
        dev = None
        try:
            with stdout_to_stderr():
                dev = _open_device(serial)
                speeds = dev.get_speeds()
                if cfg.speed not in speeds:
                    if cfg.speed == "auto":
                        raise UnsupportedError(
                            "AUTO mode not supported by this revision",
                            "Choose speed='high', 'full' or 'low'.",
                        )
                    raise UnsupportedError(
                        f"Speed {cfg.speed!r} not supported (supported: {', '.join(speeds)})"
                    )
                # Force the FSM through AWAIT_START (stale enabled capture).
                self._force_disable(dev)
                self._cfg = cfg
                self._reset_buffers(cfg.buffer_packets)
                self._stop_evt = threading.Event()
                self._dev = dev
                self._serial = getattr(dev, "serial", None)
                self._bcd = getattr(dev, "bcd_device", None)
                self._protocol = getattr(dev, "protocol_version", None)
                self._start_wall_ns = time.time_ns()
                self._start_mono = time.monotonic()
                self._stop_mono = None
                # SET_STATE with ENABLE resets FIFOs and emits CAPTURE_START.
                dev.set_state(state_value)
        except BaseException as exc:
            self._state = "idle" if self._state == "starting" else self._state
            self._dev = None
            if dev is not None:
                try:
                    dev.close()
                except Exception:
                    pass
            if isinstance(exc, (KeyboardInterrupt,)):
                raise
            raise translate_exception(exc) from exc

        self._state = "running"
        self._thread = threading.Thread(target=self._run, name="cynthion-analyzer", daemon=True)
        self._thread.start()
        log.info("Analyzer capture started (speed=%s, state=0x%02x)", cfg.speed, state_value)
        return self.status()

    def _ingest(self, data: bytes) -> None:
        now = time.monotonic()
        recs = self._parser.feed(data)
        with self._lock:
            if self._rawq is None:  # direct ingest (no reader queue, e.g. tests)
                self._bytes += len(data)
                self._last_data_mono = now
            dropped = getattr(self._parser, "dropped_by_code", None) or {}
            self._wraps = dropped.get(_EV_NONE, 0) + self._wraps_direct
            self._linestate = (
                sum(v for k, v in dropped.items() if _EV_LINESTATE_FIRST <= k <= _EV_LINESTATE_LAST)
                + self._linestate_direct
            )
            for r in recs:
                kind = getattr(r, "kind", None)
                if kind == "packet":
                    self._packets += 1
                    if _is_sof(r):
                        self._sofs += 1
                        if not self._cfg.include_sof_in_buffer:
                            continue
                elif kind == "event":
                    code = getattr(r, "code", None)
                    if code is not None and int(code) == _EV_NONE:
                        # Timestamp-wrap filler (~915/s on an idle bus): its ticks are
                        # already folded into the parser's absolute time, so it is
                        # counted but not stored (it would flood the ring buffer).
                        self._wraps_direct += 1
                        self._wraps += 1
                        continue
                    if code is not None and _EV_LINESTATE_FIRST <= int(code) <= _EV_LINESTATE_LAST:
                        self._linestate_direct += 1
                        self._linestate += 1
                        if not self._cfg.include_linestate:
                            continue
                    self._events += 1
                    if code is not None:
                        code = int(code)
                        if code == _EV_CAPTURE_STOP_NORMAL:
                            self._stop_event_seen = True
                        elif _EV_CAPTURE_START_BASE <= code < _EV_CAPTURE_START_BASE + 4:
                            sp = _speed_name(code - _EV_CAPTURE_START_BASE)
                            if sp != "auto":
                                self._detected_speed = sp
                        elif _EV_SPEED_DETECT_BASE <= code < _EV_SPEED_DETECT_BASE + 4:
                            sp = _speed_name(code - _EV_SPEED_DETECT_BASE)
                            if sp != "auto":
                                self._detected_speed = sp
                if self._records.maxlen is not None and len(self._records) >= self._records.maxlen:
                    self._dropped += 1
                self._records.append(r)

    # Reading and decoding run in two threads.  The analyzer gateware has a
    # small on-FPGA ring buffer and, on overflow, enters OVERRUN in the middle
    # of a record (see cynthion/gateware/analyzer/analyzer.py "TODO ... emit an
    # EOP"), which corrupts the stream.  A busy full-speed bus produces ~9 MB/s
    # (mostly LINESTATE events) while the pure-Python parser does ~7-10 MB/s,
    # so the USB reader must never wait for the parser: it only queues raw
    # chunks; the parser thread may lag behind and catch up after the stop.
    def _run(self) -> None:
        dev = self._dev
        cfg = self._cfg
        deadline = (
            (self._start_mono or time.monotonic()) + cfg.duration_s
            if cfg.duration_s is not None
            else None
        )
        rawq: "queue.SimpleQueue[Optional[bytes]]" = queue.SimpleQueue()
        self._rawq = rawq
        parser_thread = threading.Thread(
            target=self._parse_loop, args=(rawq,), name="cynthion-analyzer-parse", daemon=True
        )
        parser_thread.start()
        try:
            while not self._stop_evt.is_set():
                if deadline is not None and time.monotonic() >= deadline:
                    self._stop_evt.set()
                    break
                try:
                    data = dev.read()
                except Exception as exc:
                    self._state = "error"
                    self._error = translate_exception(exc).format()
                    log.error("Analyzer read failed: %s", self._error)
                    break
                if data:
                    self._enqueue(rawq, data)
                    if self._backlog > MAX_BACKLOG_BYTES:
                        self._state = "error"
                        self._error = (
                            "[HARDWARE] Decoding cannot keep up with the bus throughput "
                            f"(backlog > {MAX_BACKLOG_BYTES // (1024 * 1024)} MB); capture stopped.\n"
                            "Hint: capture for a shorter time or at a fixed speed."
                        )
                        log.error("Analyzer parse backlog too large; capture stopped")
                        break
        finally:
            if self._state != "error":
                self._state = "stopping"
            self._stop_sequence(dev, rawq, parser_thread)

    def _enqueue(self, rawq: Any, data: bytes) -> None:
        with self._lock:
            self._bytes += len(data)
            self._backlog += len(data)
            self._last_data_mono = time.monotonic()
        rawq.put(data)

    def _parse_loop(self, rawq: Any) -> None:
        failed = False
        while True:
            data = rawq.get()
            if data is None:
                return
            with self._lock:
                self._backlog -= len(data)
            if failed:
                continue  # keep draining the queue so memory is released
            try:
                self._ingest(data)
            except Exception as exc:  # parser bug: keep the error visible
                self._state = "error"
                self._error = translate_exception(exc).format()
                log.exception("Analyzer stream parsing failed")
                self._stop_evt.set()
                failed = True
                continue
            if getattr(self._parser, "desynced", False):
                # Framing lost: the host cannot find the next record boundary.
                # Stop (ENABLE=0) so the next start realigns on a record.
                self._state = "error"
                self._error = (
                    "[HARDWARE] Analyzer stream desynchronised (impossible record length, "
                    "probably a board FIFO OVERRUN); capture stopped.\n"
                    "Hint: call analyzer_start() again to realign the stream."
                )
                log.error("Analyzer stream desynchronised; capture stopped")
                self._stop_evt.set()
                failed = True

    def _stop_sequence(self, dev: Any, rawq: Any = None, parser_thread: Any = None) -> None:
        try:
            try:
                dev.set_state(dev.get_state() & ~STATE_ENABLE & 0xFF)
            except Exception as exc:
                log.warning("Could not disable capture: %s", exc)
            # Drain: the gateware emits CAPTURE_STOP_NORMAL then flushes the EP.
            if self._state != "error":
                end = time.monotonic() + DRAIN_MAX_S
                empty = 0
                while (
                    not self._stop_event_seen
                    and empty < DRAIN_MAX_EMPTY_READS
                    and time.monotonic() < end
                ):
                    try:
                        data = dev.read()
                    except Exception as exc:
                        log.warning("Drain read failed: %s", exc)
                        break
                    if data:
                        empty = 0
                        if rawq is not None:
                            self._enqueue(rawq, data)
                        else:
                            try:
                                self._ingest(data)
                            except Exception:
                                log.exception("Drain parsing failed")
                                break
                    else:
                        empty += 1
        finally:
            try:
                dev.close()
            except Exception:
                pass
            self._dev = None
            self._stop_mono = time.monotonic()
            if rawq is not None:
                rawq.put(None)
                if parser_thread is not None:
                    # Let the parser finish the backlog; this thread (and thus
                    # is_running()) stays alive meanwhile, in state "stopping".
                    parser_thread.join()
            if self._state != "error":
                self._state = "stopped"
            log.info(
                "Analyzer capture stopped (%d packets, %d events, %d bytes)",
                self._packets,
                self._events,
                self._bytes,
            )

    def stop(self, timeout_s: float = 60.0) -> Dict[str, Any]:
        with self._ctl_lock:
            return self._stop_locked(timeout_s)

    def _stop_locked(self, timeout_s: float) -> Dict[str, Any]:
        if not self.is_running():
            st = self.status()
            st["note"] = "No capture running."
            return st
        self._stop_evt.set()
        t = self._thread
        if t is not None:
            t.join(timeout_s)
        st = self.status()
        if t is not None and t.is_alive():
            st["note"] = (
                "Stop requested; still decoding the backlog "
                f"({st.get('parse_backlog_bytes', 0)} bytes left). Call analyzer_status() again."
            )
        return st

    def shutdown(self) -> None:
        try:
            self.stop(2.0)
        except Exception:
            log.debug("Analyzer shutdown failed", exc_info=True)

    # -- status ------------------------------------------------------------
    def _seq_bounds(self) -> "tuple[Optional[int], Optional[int]]":
        # caller holds self._lock
        if not self._records:
            return None, None
        return self._records[0].seq, self._records[-1].seq

    def status(self) -> Dict[str, Any]:
        now = time.monotonic()
        running = self.is_running()
        with self._lock:
            first, last = self._seq_bounds()
            buffered = len(self._records)
            capacity = self._records.maxlen
            bytes_rx = self._bytes
            packets = self._packets
            events = self._events
            sofs = self._sofs
            wraps = self._wraps
            dropped = self._dropped
            last_data = self._last_data_mono
        if self._start_mono is None:
            elapsed = 0.0
        else:
            end = self._stop_mono if (self._stop_mono is not None and not running) else now
            elapsed = max(0.0, end - self._start_mono)
        ref = last_data if last_data is not None else self._start_mono
        idle = (now - ref) if (running and ref is not None) else None
        st: Dict[str, Any] = {
            "ok": True,
            "state": self._state,
            "running": running,
            "speed_requested": self._cfg.speed if self._start_mono is not None else None,
            "detected_speed": self._detected_speed,
            "elapsed_s": round(elapsed, 3),
            "bytes_received": bytes_rx,
            "packets": packets,
            "events": events,
            "sof_packets": sofs,
            "timestamp_wraps": wraps,
            "linestate_events": self._linestate,
            "parse_backlog_bytes": self._backlog,
            "buffered_records": buffered,
            "dropped_records": dropped,
            "first_seq": first,
            "last_seq": last,
            "stop_event_received": self._stop_event_seen,
            "error": self._error,
            "buffer_capacity": capacity,
            "data_rate_bps": round(bytes_rx * 8 / elapsed, 1) if elapsed > 0 else 0.0,
            "idle_s": round(idle, 3) if idle is not None else None,
            "serial": self._serial,
            "revision": _revision(self._bcd),
        }
        if running and idle is not None and idle > IDLE_WARNING_S and packets > 0:
            st["note"] = (
                "No data for 5 s: bus idle or OVERRUN (LED2 lit); "
                "stop/restart the capture."
            )
        return st

    # -- buffer access -------------------------------------------------------
    def snapshot(self, start_seq: Optional[int] = None) -> List[Record]:
        with self._lock:
            if start_seq is None:
                return list(self._records)
            if not self._records:
                return []
            first = self._records[0].seq
            if start_seq <= first:
                return list(self._records)
            # seqs are contiguous in the deque, so index directly when possible
            idx = start_seq - first
            if 0 <= idx < len(self._records) and self._records[idx].seq == start_seq:
                return [self._records[i] for i in range(idx, len(self._records))]
            return [r for r in self._records if r.seq >= start_seq]

    def _first_available(self) -> Optional[int]:
        with self._lock:
            return self._records[0].seq if self._records else None

    def read(
        self,
        start_seq: Optional[int] = None,
        limit: int = 100,
        flt: Optional[RecordFilter] = None,
        raw: bool = False,
        **filter_kwargs: Any,
    ) -> Dict[str, Any]:
        """Read decoded records; filter with ``flt`` or RecordFilter keywords
        (kinds, pids, address, endpoint, include_sof, include_nak, only_errors)."""
        if flt is None:
            try:
                flt = RecordFilter(**filter_kwargs)
            except TypeError as exc:
                raise InvalidArgumentError(f"Filtre invalide : {exc}") from exc
        elif filter_kwargs:
            flt = dataclasses.replace(flt, **filter_kwargs)
        with self._lock:
            first_available, last_seq = self._seq_bounds()
        effective_start = start_seq if start_seq is not None else first_available
        records = self.snapshot(effective_start)
        items, last = filter_records(records, flt, limit, raw=raw)
        if last is not None:
            next_seq = last + 1
        elif records:
            # nothing matched: everything scanned has been consumed
            next_seq = records[-1].seq + 1
        else:
            next_seq = effective_start if effective_start is not None else 0
        truncated = (
            start_seq is not None and first_available is not None and start_seq < first_available
        )
        return {
            "ok": True,
            "records": items,
            "next_seq": next_seq,
            "first_available_seq": first_available,
            "last_seq": last_seq,
            "truncated": bool(truncated),
        }

    def transactions(
        self,
        start_seq: Optional[int] = None,
        limit: int = 100,
        address: Optional[int] = None,
        endpoint: Optional[int] = None,
        include_sof: bool = False,
        include_nak: bool = False,
        decode_setup: bool = True,
    ) -> Dict[str, Any]:
        records = self.snapshot(start_seq)
        txs = group_transactions(
            records,
            include_sof=include_sof,
            include_nak=include_nak,
            decode_setup_packets=decode_setup,
            include_events=True,
        )
        out: List[Dict[str, Any]] = []
        resume_seq: Optional[int] = None
        for t in txs:
            if len(out) >= limit:
                # Resume at the first transaction not returned (its starting seq).
                resume_seq = t.get("seq")
                break
            if address is not None and t.get("addr") != address:
                continue
            if endpoint is not None and t.get("ep") != endpoint:
                continue
            out.append(t)
        if resume_seq is not None:
            next_seq = resume_seq
        elif records:
            next_seq = records[-1].seq + 1
        else:
            next_seq = start_seq if start_seq is not None else (self._first_available() or 0)
        return {"ok": True, "transactions": out, "next_seq": next_seq}

    def summary(self) -> Dict[str, Any]:
        result = dict(summarize(self.snapshot()))
        st = self.status()
        result.setdefault("ok", True)
        result.setdefault("speed", st["detected_speed"] or st["speed_requested"])
        result.setdefault("duration_s", st["elapsed_s"])
        result["capture"] = {
            k: st[k]
            for k in (
                "state",
                "running",
                "speed_requested",
                "detected_speed",
                "elapsed_s",
                "packets",
                "events",
                "sof_packets",
                "buffered_records",
                "dropped_records",
                "error",
            )
        }
        return result

    # -- pcap ----------------------------------------------------------------
    def _pcap_packets(self, include_sof: bool = True) -> List[tuple]:
        return [
            (r.ticks, r.data)
            for r in self.snapshot()
            if r.kind == "packet" and r.data and (include_sof or (r.data[0] & 0xF) != PID_SOF)
        ]

    def export_pcap(
        self, path: Optional[str] = None, nanosecond: bool = True, include_sof: bool = True
    ) -> Dict[str, Any]:
        packets = self._pcap_packets(include_sof)
        if not packets:
            raise InvalidArgumentError(
                "No packets captured", "Run analyzer_start, then generate some USB traffic."
            )
        out = resolve_output_file(path, f"cynthion_capture_{timestamp_slug()}.pcap")
        write_pcap(str(out), packets, self._start_wall_ns or time.time_ns(), nanosecond)
        size = out.stat().st_size
        self._last_pcap = out.read_bytes() if size < MAX_CACHED_PCAP else None
        return {
            "ok": True,
            "path": str(out),
            "packets": len(packets),
            "bytes": size,
            "linktype": 288,
            "resource_uri": "cynthion://capture/last.pcap",
        }

    def last_pcap_bytes(self) -> bytes:
        """pcap of the current buffer (header only when nothing is buffered)."""
        packets = self._pcap_packets(True)
        if not packets and self._last_pcap is not None:
            return self._last_pcap
        return pcap_bytes(packets, self._start_wall_ns or time.time_ns(), True)

    def clear(self) -> Dict[str, Any]:
        with self._ctl_lock:
            if self.is_running():
                raise BusyError("Cannot clear the buffer while a capture is running", "analyzer_stop()")
            self._reset_buffers(self._cfg.buffer_packets)
            self._state = "idle"
            self._start_wall_ns = None
            self._start_mono = None
            self._stop_mono = None
            return {"ok": True}

    # -- misc device operations ----------------------------------------------
    def test_device(self, connect: bool = True, speed: str = "high") -> Dict[str, Any]:
        if speed not in ("high", "full", "low"):
            raise InvalidArgumentError(f"Invalid test speed: {speed!r}", "high, full or low")
        value = (1 if connect else 0) | (int(SPEED_BITS[speed]) << 1)
        try:
            with stdout_to_stderr():
                if self.is_running() and self._dev is not None:
                    self._dev.ctrl_out(REQ_SET_TEST_CONFIG, value)
                else:
                    dev = _open_device(None)
                    try:
                        dev.ctrl_out(REQ_SET_TEST_CONFIG, value)
                    finally:
                        dev.close()
        except Exception as exc:
            raise translate_exception(exc) from exc
        return {"ok": True, "value": value, "connect": bool(connect), "speed": speed}

    def info(self, serial: Optional[str] = None) -> Dict[str, Any]:
        try:
            with stdout_to_stderr():
                if self.is_running() and self._dev is not None:
                    return self._info_from(self._dev)
                dev = _open_device(serial)
                try:
                    return self._info_from(dev)
                finally:
                    dev.close()
        except Exception as exc:
            raise translate_exception(exc) from exc

    @staticmethod
    def _info_from(dev: Any) -> Dict[str, Any]:
        state = dev.get_state()
        bcd = getattr(dev, "bcd_device", None)
        return {
            "ok": True,
            "protocol_version": getattr(dev, "protocol_version", None),
            "speeds": dev.get_speeds(),
            "state": state,
            "state_decoded": decode_state(state),
            "serial": getattr(dev, "serial", None),
            "bcd_device": bcd,
            "revision": _revision(bcd),
        }


CAPTURE = CaptureManager()
