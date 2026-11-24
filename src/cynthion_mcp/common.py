"""Shared helpers for the Cynthion MCP server.

Stdlib-only at import time: third-party packages (apollo_fpga, pygreat,
facedancer, usb, anyio) are imported lazily inside functions so that importing
any ``cynthion_mcp`` module never fails because of a broken hardware library.

Contents:
  1. Error model (CynthionMCPError + subclasses, translate_exception)
  2. Logging (RingLogHandler / LOG_RING, setup_logging)
  3. Stdout guards (stdout_to_stderr, capture_stdout)
  4. Hardware lock and activity registry (HW_LOCK, hw_lock, ACTIVITY)
  5. Async bridge (run_blocking)
  6. Parse / validation helpers
"""

from __future__ import annotations

import collections
import contextlib
import functools
import hashlib
import io
import logging
import os
import pathlib
import sys
import threading
import time
from datetime import datetime
from typing import Callable, Iterable, Iterator, Optional, TypeVar

T = TypeVar("T")

logger = logging.getLogger("cynthion_mcp")


# =============================================================================
# 1) ERRORS
# =============================================================================

HINT_PLUG = (
    "Plug the Cynthion in through its USB-C CONTROL port and check the cable "
    "(it must carry data, not just power)."
)
HINT_WINUSB = (
    "On Windows, the WinUSB driver must be bound (normally automatic through the "
    "MS OS descriptors; otherwise use Zadig on 1d50:615c / 1d50:615b)."
)
HINT_FACEDANCER = (
    "Load the Facedancer gateware first: run_gateware(target='facedancer')."
)
HINT_ANALYZER = (
    "Load the analyzer gateware first: run_gateware(target='analyzer') "
    "or analyzer_start(auto_load_gateware=True)."
)


class CynthionMCPError(Exception):
    """Base error. ``format()`` gives "[CODE] message" (+ hint line)."""

    code = "ERROR"

    def __init__(self, message: str, hint: str | None = None, *, code: str | None = None):
        super().__init__(message)
        self.message = message
        self.hint = hint
        if code is not None:
            self.code = code

    def format(self) -> str:
        text = f"[{self.code}] {self.message}"
        if self.hint:
            text += f"\nHint: {self.hint}"
        return text

    __str__ = format


class NoDeviceError(CynthionMCPError):
    code = "NO_DEVICE"


class WrongModeError(CynthionMCPError):
    code = "WRONG_MODE"


class BusyError(CynthionMCPError):
    code = "BUSY"


class InvalidArgumentError(CynthionMCPError):
    code = "INVALID_ARGUMENT"


class ConfirmationRequired(CynthionMCPError):
    code = "CONFIRMATION_REQUIRED"


class DriverError(CynthionMCPError):
    code = "DRIVER"


class HardwareError(CynthionMCPError):
    code = "HARDWARE"


class UnsupportedError(CynthionMCPError):
    code = "UNSUPPORTED"


class OperationTimeout(CynthionMCPError):
    code = "TIMEOUT"


# Alias matching the name used in the overall design document (section 2.4).
TimeoutError_ = OperationTimeout


def _lazy_classes() -> dict:
    """Import third-party exception classes lazily; missing ones are skipped."""
    found: dict = {}
    try:
        from apollo_fpga import DebuggerNotFound, USBAPIRequirement  # type: ignore

        found["DebuggerNotFound"] = DebuggerNotFound
        found["USBAPIRequirement"] = USBAPIRequirement
    except Exception:
        pass
    try:
        from apollo_fpga.jtag import JTAGPatternError  # type: ignore

        found["JTAGPatternError"] = JTAGPatternError
    except Exception:
        pass
    try:
        from pygreat.errors import DeviceNotFoundError as GreatNotFound  # type: ignore

        found["GreatNotFound"] = GreatNotFound
    except Exception:
        pass
    try:
        from facedancer.errors import DeviceNotFoundError as FDNotFound  # type: ignore

        found["FDNotFound"] = FDNotFound
    except Exception:
        pass
    try:
        import usb.core  # type: ignore

        found["USBError"] = usb.core.USBError
        found["USBTimeoutError"] = usb.core.USBTimeoutError
        found["NoBackendError"] = usb.core.NoBackendError
    except Exception:
        pass
    return found


def _isinstance(exc: BaseException, classes: dict, *names: str) -> bool:
    types = tuple(classes[n] for n in names if n in classes)
    return bool(types) and isinstance(exc, types)


def _translate_usb_error(exc: BaseException, classes: dict) -> CynthionMCPError:
    errno_ = getattr(exc, "errno", None)
    text = str(exc).lower()
    msg = f"USB error: {exc}"
    if (
        _isinstance(exc, classes, "USBTimeoutError")
        or errno_ in (110, 10060)
        or "timeout" in text
        or "timed out" in text
    ):
        return OperationTimeout(msg, "The device is not responding; reconnect it or run reconfigure_fpga().")
    if errno_ == 13 or "access" in text:
        return DriverError(msg, HINT_WINUSB)
    if errno_ in (2, 19) or "no such device" in text or "entity not found" in text:
        return NoDeviceError(msg, HINT_PLUG)
    return HardwareError(msg)


def translate_exception(exc: BaseException) -> CynthionMCPError:
    """Map any exception raised by hardware libraries to a CynthionMCPError.

    The original exception is attached as ``__cause__``.
    """
    if isinstance(exc, CynthionMCPError):
        return exc

    classes = _lazy_classes()
    err: CynthionMCPError

    if _isinstance(exc, classes, "DebuggerNotFound"):
        text = str(exc)
        if "stub interface found but not requested" in text.lower():
            err = WrongModeError(
                f"Gateware is running on the Cynthion, Apollo is not available: {text}",
                "The operation must force the FPGA offline (force_offline=True) or use force_fpga_offline().",
            )
        else:
            err = NoDeviceError(
                f"No Cynthion detected (Apollo): {text}",
                "Plug in the Cynthion CONTROL port (left-hand USB-C); on Windows, check the WinUSB driver.",
            )
    elif _isinstance(exc, classes, "GreatNotFound", "FDNotFound"):
        err = NoDeviceError(
            f"No Cynthion in Facedancer (Moondancer) mode detected: {exc}",
            HINT_FACEDANCER,
        )
    elif _isinstance(exc, classes, "NoBackendError"):
        err = DriverError(f"libusb not found: {exc}", HINT_WINUSB)
    elif _isinstance(exc, classes, "USBError"):
        err = _translate_usb_error(exc, classes)
    elif _isinstance(exc, classes, "USBAPIRequirement"):
        err = UnsupportedError(
            f"Apollo firmware API version too old: {exc}",
            "Update the Apollo firmware (update_apollo_firmware).",
        )
    elif isinstance(exc, SystemExit):
        err = HardwareError("Operation aborted by the library (sys.exit)")
    elif _isinstance(exc, classes, "JTAGPatternError") or isinstance(exc, OSError):
        # Note: builtin TimeoutError is an OSError subclass; keep it as TIMEOUT.
        if isinstance(exc, TimeoutError):
            err = OperationTimeout(f"Timed out: {exc}")
        else:
            err = HardwareError(f"Hardware error ({type(exc).__name__}): {exc}")
    elif isinstance(exc, ValueError):
        err = InvalidArgumentError(str(exc) or type(exc).__name__)
    else:
        err = HardwareError(f"{type(exc).__name__}: {exc}")

    err.__cause__ = exc
    return err


# =============================================================================
# 2) LOGGING
# =============================================================================


class RingLogHandler(logging.Handler):
    """Keeps the last ``maxlen`` formatted log records in memory."""

    def __init__(self, maxlen: int = 2000):
        super().__init__()
        self._buf: collections.deque = collections.deque(maxlen=maxlen)
        self._ring_lock = threading.Lock()
        self._seq = 0
        self.setFormatter(logging.Formatter("%(name)s: %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            text = self.format(record)
        except Exception:
            text = str(getattr(record, "msg", ""))
        with self._ring_lock:
            self._seq += 1
            self._buf.append((self._seq, record.created, record.levelno, text))

    def get(self, lines: int = 200, min_level: int = logging.INFO) -> list[str]:
        with self._ring_lock:
            entries = [e for e in self._buf if e[2] >= min_level]
        if lines is not None and lines >= 0:
            entries = entries[-lines:] if lines else []
        out = []
        for _seq, created, levelno, text in entries:
            stamp = time.strftime("%H:%M:%S", time.localtime(created))
            out.append(f"{stamp} {logging.getLevelName(levelno)} {text}")
        return out

    def clear(self) -> None:
        with self._ring_lock:
            self._buf.clear()


LOG_RING = RingLogHandler()

_LOGGING_CONFIGURED = False
_LOGGING_LOCK = threading.Lock()


def setup_logging(level: str | int = "INFO") -> None:
    """Configure root logging to stderr + in-memory ring. Idempotent."""
    global _LOGGING_CONFIGURED
    with _LOGGING_LOCK:
        if _LOGGING_CONFIGURED:
            return
        if isinstance(level, str):
            level = logging.getLevelName(level.upper())
            if not isinstance(level, int):
                level = logging.INFO
        root = logging.getLogger()
        root.setLevel(level)
        stream = logging.StreamHandler(sys.stderr)
        stream.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root.addHandler(stream)
        if LOG_RING not in root.handlers:
            root.addHandler(LOG_RING)
        logging.getLogger("facedancer").setLevel(logging.INFO)
        _LOGGING_CONFIGURED = True


# =============================================================================
# 3) STDOUT GUARD
# =============================================================================


@contextlib.contextmanager
def stdout_to_stderr() -> Iterator[None]:
    """Redirect library print() output to stderr (protects the MCP stdio stream)."""
    with contextlib.redirect_stdout(sys.stderr):
        yield


@contextlib.contextmanager
def capture_stdout() -> Iterator[io.StringIO]:
    """Capture library print() output into a StringIO."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        yield buf


# =============================================================================
# 4) LOCKS AND ACTIVITY
# =============================================================================

HW_LOCK = threading.RLock()


@contextlib.contextmanager
def hw_lock(timeout: float = 30.0) -> Iterator[None]:
    """Serialise in-process hardware access (Apollo/JTAG/Moondancer)."""
    if not HW_LOCK.acquire(timeout=timeout):
        raise BusyError("Another hardware operation is in progress", "Try again in a few seconds.")
    try:
        yield
    finally:
        HW_LOCK.release()


class ActivityRegistry:
    """Tracks long-lived owners of the Cynthion USB device (capture, emulation)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[Callable[[], bool], str, str]] = {}

    def register(self, name: str, probe: Callable[[], bool], description: str, stop_tool: str) -> None:
        with self._lock:
            self._entries[name] = (probe, description, stop_tool)

    def unregister(self, name: str) -> None:
        with self._lock:
            self._entries.pop(name, None)

    def _snapshot(self) -> list[tuple[str, Callable[[], bool], str, str]]:
        with self._lock:
            return [(n, p, d, s) for n, (p, d, s) in self._entries.items()]

    @staticmethod
    def _probe(probe: Callable[[], bool]) -> bool:
        try:
            return bool(probe())
        except Exception:
            return False

    def active(self) -> dict[str, str]:
        return {n: d for n, p, d, _s in self._snapshot() if self._probe(p)}

    def check_free(self, allow: Iterable[str] = ()) -> None:
        allowed = set(allow)
        for name, probe, description, stop_tool in self._snapshot():
            if name in allowed:
                continue
            if self._probe(probe):
                raise BusyError(
                    f"The USB device is in use by: {description}",
                    f"Stop it first with {stop_tool}().",
                )


ACTIVITY = ActivityRegistry()


# =============================================================================
# 5) ASYNC BRIDGE
# =============================================================================


async def run_blocking(fn: Callable[..., T], /, *args, **kwargs) -> T:
    """Run a blocking callable in a worker thread (keeps the MCP loop responsive)."""
    import anyio.to_thread  # lazy

    return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))


ProgressFn = Callable[[float, Optional[float], Optional[str]], None]


def noop_progress(p: float, t: float | None = None, m: str | None = None) -> None:
    pass


# =============================================================================
# 6) PARSE / VALIDATION HELPERS
# =============================================================================


def parse_int(value: int | str, name: str) -> int:
    """Accept int, decimal string, '0x..', '0b..', '0o..'."""
    if isinstance(value, bool):
        raise InvalidArgumentError(f"Parameter {name}: integer expected, got a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip().replace("_", "")
        try:
            return int(s, 0)
        except ValueError:
            # int(s, 0) rejects leading zeros such as "010"; accept plain decimals.
            if s.isdigit():
                return int(s, 10)
    raise InvalidArgumentError(
        f"Parameter {name}: invalid integer {value!r} (accepted formats: 42, 0x2A, 0b101010)"
    )


def parse_hex_bytes(s: str) -> bytes:
    """Parse '2d 00 10', '2d:00:10', '0x2d,0x00', '2d0010' into bytes."""
    if not isinstance(s, str):
        raise InvalidArgumentError("Hex string expected")
    tokens = s.replace(",", " ").replace(":", " ").split()
    cleaned = []
    for tok in tokens:
        if tok[:2].lower() == "0x":
            tok = tok[2:]
        if len(tok) % 2:
            tok = "0" + tok if len(tokens) > 1 else tok
        cleaned.append(tok)
    joined = "".join(cleaned)
    try:
        return bytes.fromhex(joined)
    except ValueError as e:
        raise InvalidArgumentError(f"Invalid hex bytes {s!r}: {e}") from e


def resolve_input_file(path: str, max_size: int | None = None) -> pathlib.Path:
    """Validate an existing readable input file and return its resolved path."""
    if not path or not str(path).strip():
        raise InvalidArgumentError("Empty file path")
    p = pathlib.Path(os.path.expandvars(str(path).strip().strip('"'))).expanduser()
    try:
        p = p.resolve()
    except OSError as e:
        raise InvalidArgumentError(f"Invalid path {path!r}: {e}") from e
    if not p.exists():
        raise InvalidArgumentError(f"File not found: {p}")
    if not p.is_file():
        raise InvalidArgumentError(f"Not a file: {p}")
    if max_size is not None:
        size = p.stat().st_size
        if size > max_size:
            raise InvalidArgumentError(f"File too large ({size} bytes > {max_size}): {p}")
    return p


def resolve_output_file(path: str | None, default_name: str) -> pathlib.Path:
    """Resolve an output path (default dir: $CYNTHION_MCP_OUTPUT_DIR or ~/cynthion_mcp)."""
    if path is None or not str(path).strip():
        base = os.environ.get("CYNTHION_MCP_OUTPUT_DIR") or (pathlib.Path.home() / "cynthion_mcp")
        p = pathlib.Path(base).expanduser() / default_name
    else:
        p = pathlib.Path(os.path.expandvars(str(path).strip().strip('"'))).expanduser()
    try:
        p = p.resolve()
    except OSError as e:
        raise InvalidArgumentError(f"Invalid path {path!r}: {e}") from e
    if p.is_dir():
        raise InvalidArgumentError(f"Output path is an existing directory: {p}")
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise InvalidArgumentError(f"Cannot create directory {p.parent}: {e}") from e
    return p


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_confirm(confirm: bool, action_description: str) -> None:
    if not confirm:
        raise ConfirmationRequired(
            f"Destructive action: {action_description}. "
            "Run again with confirm=true after explicit approval from the user."
        )


def timestamp_slug() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


__all__ = [
    "CynthionMCPError", "NoDeviceError", "WrongModeError", "BusyError", "InvalidArgumentError",
    "ConfirmationRequired", "DriverError", "HardwareError", "UnsupportedError", "OperationTimeout",
    "TimeoutError_", "HINT_PLUG", "HINT_WINUSB", "HINT_FACEDANCER", "HINT_ANALYZER",
    "translate_exception", "RingLogHandler", "LOG_RING", "setup_logging", "logger",
    "stdout_to_stderr", "capture_stdout", "HW_LOCK", "hw_lock", "ActivityRegistry", "ACTIVITY",
    "run_blocking", "ProgressFn", "noop_progress", "parse_int", "parse_hex_bytes",
    "resolve_input_file", "resolve_output_file", "sha256_hex", "require_confirm", "timestamp_slug",
]
