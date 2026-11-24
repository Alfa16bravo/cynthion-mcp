"""Parent-side manager of the Facedancer (Moondancer) emulation subprocess.

The emulated USB device runs in a CHILD PROCESS (``cynthion_mcp.facedancer_worker``)
so that facedancer's busy asyncio loop, its blocking libusb RPCs, its stdout
``print()`` calls (umass) and any ``sys.exit()`` (USBProxy) cannot disturb the
MCP server.  This module never imports facedancer; it only speaks the
JSON-lines protocol below.

Protocol
--------
Parent -> child (stdin, one JSON object per line)::

    {"id": <int>, "cmd": "<command>", "args": {...}}

Child -> parent (stdout, one JSON object per line), ``type`` is one of:

* ``result``     : ``{"type":"result","id":N,"ok":bool,"value":...,"error":str}``
* ``connected``  : the emulated device is connected to the target host
                   (free-form info: kind, vid, pid, speed, ...)
* ``error``      : ``{"type":"error","code":"NO_DEVICE"|...,"message":str,
                   "hint":str|None,"fatal":bool}``
* ``stopped``    : final message (``unhandled_requests``, reason, ...)
* ``data`` / ``host_event`` : asynchronous events (serial data from the host,
                   bus reset, control requests, proxied traffic, ...)
* ``log``        : ``{"type":"log","text":str}`` (optional, stored with logs)

The child's stderr (logging output) is captured line by line into a log ring.
"""

from __future__ import annotations

import atexit
import concurrent.futures
import datetime as _dt
import itertools
import json
import logging
import os
import subprocess
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from . import common

log = logging.getLogger("cynthion_mcp.facedancer_runner")

# ---------------------------------------------------------------------------
# Names from .common, resolved defensively (fallbacks keep this module usable
# even if a helper is renamed).
# ---------------------------------------------------------------------------
CynthionMCPError = common.CynthionMCPError
NoDeviceError = getattr(common, "NoDeviceError", CynthionMCPError)
WrongModeError = getattr(common, "WrongModeError", CynthionMCPError)
BusyError = getattr(common, "BusyError", CynthionMCPError)
InvalidArgumentError = getattr(common, "InvalidArgumentError", CynthionMCPError)
HardwareError = getattr(common, "HardwareError", CynthionMCPError)
DriverError = getattr(common, "DriverError", HardwareError)
UnsupportedError = getattr(common, "UnsupportedError", HardwareError)
ConfirmationRequired = getattr(common, "ConfirmationRequired", CynthionMCPError)
OperationTimeout = (
    getattr(common, "OperationTimeout", None)
    or getattr(common, "TimeoutError_", None)
    or HardwareError
)

HINT_PLUG = getattr(
    common,
    "HINT_PLUG",
    "Plug in the Cynthion CONTROL port (left-hand USB-C); on Windows "
    "check the WinUSB driver.",
)
HINT_FACEDANCER = getattr(
    common,
    "HINT_FACEDANCER",
    "Load the Facedancer gateware first: run_gateware(target='facedancer').",
)

# Map of error codes sent by the worker to exception classes.
_CODE_TO_CLASS: dict[str, type] = {
    "NO_DEVICE": NoDeviceError,
    "WRONG_MODE": WrongModeError,
    "BUSY": BusyError,
    "INVALID_ARGUMENT": InvalidArgumentError,
    "CONFIRMATION_REQUIRED": ConfirmationRequired,
    "DRIVER": DriverError,
    "HARDWARE": HardwareError,
    "UNSUPPORTED": UnsupportedError,
    "TIMEOUT": OperationTimeout,
}


def _make_error(cls: type, message: str, hint: str | None = None) -> BaseException:
    """Instantiate a CynthionMCPError subclass tolerant to constructor variants."""
    try:
        return cls(message, hint)
    except TypeError:
        try:
            return cls(message)
        except TypeError:
            return HardwareError(message)


def _resolve_input_file(path: str) -> Path:
    fn = getattr(common, "resolve_input_file", None)
    if fn is not None:
        return Path(fn(path))
    p = Path(os.path.expandvars(os.path.expanduser(str(path)))).resolve()
    if not p.is_file():
        raise _make_error(InvalidArgumentError, f"File not found: {p}")
    return p


# ---------------------------------------------------------------------------
# Kind catalogue (must match facedancer_worker)
# ---------------------------------------------------------------------------
COMMON_COMMANDS: list[str] = [
    "stop",
    "ping",
    "status",
    "board_op",
    "unhandled_requests",
    "descriptor",
    "generate_code",
]

KIND_SPECS: dict[str, dict[str, Any]] = {
    "keyboard": {
        "description": "USB HID keyboard (8-key rollover)",
        "params": {},
        "commands": {
            "type_string": {
                "text": {"type": "str", "description": "Text to type (ASCII)"},
                "duration": {"type": "float", "default": 0.05,
                             "description": "Press duration per key (s)"},
            },
            "key_combo": {
                "keys": {"type": "list", "description":
                         "Keys: KeyboardKeys names (e.g. 'A', 'ENTER') or int scancodes"},
                "modifiers": {"type": "list", "description":
                              "KeyboardModifiers modifiers (e.g. 'MOD_LEFT_CTRL')"},
                "duration": {"type": "float", "default": 0.1,
                             "description": "Press duration (s)"},
            },
            "all_keys_up": {},
        },
        "events": [],
    },
    "ftdi": {
        "description": "FTDI FT232 USB-serial adapter (0403:6001)",
        "params": {},
        "commands": {
            "serial_write": {
                "data": {"type": "str", "description": "Data to send to the host"},
                "is_hex": {"type": "bool", "default": False,
                           "description": "data is a hexadecimal string"},
            },
        },
        "events": ["data source=ftdi direction=out (host->device serial)"],
    },
    "mass_storage": {
        "description": "USB mass-storage stick (SCSI bulk-only)",
        "params": {
            "image_path": {"type": "str|None", "default": None,
                           "description": "Existing raw disk image (r+b); "
                                          "None = synthetic FAT32 image"},
            "block_size": {"type": "int", "default": 512,
                           "description": "Block size of the raw image"},
            "size_mb": {"type": "int", "default": 64,
                        "description": "Size of the synthetic FAT32 image (MB)"},
        },
        "commands": {},
        "events": [],
    },
    "proxy": {
        "description": "USBProxy: relays a real device plugged into the PC "
                       "to the target host (USB MITM)",
        "params": {
            "vid": {"type": "int", "description": "idVendor of the real device"},
            "pid": {"type": "int", "description": "idProduct of the real device"},
        },
        "commands": {},
        "note": "the proxied device must use the WinUSB driver (Zadig) on Windows",
        "events": [
            "host_event kind=control_in / control_out (relayed control requests)",
            "data direction=in / out (relayed endpoint traffic)",
        ],
    },
    "script": {
        "description": "Device defined by a user Python script",
        "params": "free-form (passed to create_device)",
        "commands": {},
        "note": "script_path required; must define device or create_device(params)",
        "events": [],
    },
}


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return _dt.datetime.fromtimestamp(ts).isoformat(timespec="seconds")


class FacedancerRunner:
    """Manages at most one facedancer_worker child process."""

    def __init__(
        self,
        python_exe: str = sys.executable,
        worker_module: str = "cynthion_mcp.facedancer_worker",
        worker_cmd: list[str] | None = None,
    ) -> None:
        self.python_exe = python_exe
        self.worker_module = worker_module
        self.worker_cmd = list(worker_cmd) if worker_cmd else None

        self._proc: subprocess.Popen | None = None
        self._lock = threading.Lock()          # guards process lifecycle
        self._data_lock = threading.Lock()     # guards buffers / state
        self._write_lock = threading.Lock()    # serialises stdin writes

        self._logs: deque = deque(maxlen=5000)       # (seq, t, text)
        self._events: deque = deque(maxlen=20000)    # dicts with 'seq'
        self._log_seq = itertools.count(1)
        self._event_seq = itertools.count(1)
        self._last_log_seq = 0
        self._last_event_seq = 0

        self._pending: dict[int, concurrent.futures.Future] = {}
        self._next_id = itertools.count(1)

        self._kind: str | None = None
        self._params: dict | None = None
        self._script: str | None = None
        self._speed: str | None = None
        self._started_at: float | None = None
        self._exit_code: int | None = None
        self._last_error: dict | None = None
        self._fatal_error: dict | None = None
        self._connected_evt = threading.Event()
        self._connect_info: dict | None = None
        self._stopped_msg: dict | None = None
        self._threads: list[threading.Thread] = []

        try:
            common.ACTIVITY.register(
                "facedancer", self.is_running,
                "Facedancer emulation running", "facedancer_stop",
            )
        except Exception:  # pragma: no cover - registry is optional
            log.debug("ACTIVITY registration failed", exc_info=True)

    # ------------------------------------------------------------------ state
    def is_running(self) -> bool:
        proc = self._proc
        return proc is not None and proc.poll() is None

    def _append_log(self, text: str) -> None:
        with self._data_lock:
            seq = next(self._log_seq)
            self._last_log_seq = seq
            self._logs.append((seq, time.time(), text))

    def _append_event(self, msg: dict) -> None:
        with self._data_lock:
            seq = next(self._event_seq)
            self._last_event_seq = seq
            ev = dict(msg)
            ev["seq"] = seq
            ev.setdefault("t", time.time())
            self._events.append(ev)

    def _reset_session_state(self) -> None:
        with self._data_lock:
            self._logs.clear()
            self._events.clear()
            self._pending.clear()
        self._exit_code = None
        self._last_error = None
        self._fatal_error = None
        self._connect_info = None
        self._stopped_msg = None
        self._connected_evt = threading.Event()

    # ----------------------------------------------------------------- start
    def start(
        self,
        kind: str,
        params: dict | None = None,
        script_path: str | None = None,
        ready_timeout_s: float = 15.0,
        check_mode: bool = True,
        speed: str | None = None,
    ) -> dict:
        """Spawn the worker for ``kind`` and wait until the device is connected."""
        with self._lock:
            if self.is_running():
                raise _make_error(BusyError, "An emulation is already running", "facedancer_stop()")
            if kind not in KIND_SPECS:
                raise _make_error(
                    InvalidArgumentError,
                    f"Unknown device kind: {kind!r} "
                    f"(expected: {', '.join(KIND_SPECS)})",
                )
            if params is not None and not isinstance(params, dict):
                raise _make_error(InvalidArgumentError, "params must be a JSON object")
            script: Path | None = None
            if kind == "script":
                if not script_path:
                    raise _make_error(
                        InvalidArgumentError,
                        "script_path is required for kind='script'",
                    )
                script = _resolve_input_file(script_path)
            elif script_path:
                script = _resolve_input_file(script_path)
            if speed is not None and str(speed).lower() not in ("full", "high", "low", "auto"):
                raise _make_error(InvalidArgumentError, f"Invalid speed: {speed!r}")

            if check_mode:
                from .device import current_mode  # lazy: pulls in pyusb
                m = current_mode()
                if m == "absent":
                    raise _make_error(NoDeviceError, "No Cynthion detected", HINT_PLUG)
                if m != "facedancer":
                    raise _make_error(
                        WrongModeError, f"The Cynthion is in {m} mode", HINT_FACEDANCER
                    )

            common.ACTIVITY.check_free(allow=("facedancer",))

            try:
                params_json = json.dumps(params or {})
            except (TypeError, ValueError) as exc:
                raise _make_error(
                    InvalidArgumentError, f"params is not JSON-serialisable: {exc}"
                )

            prefix = self.worker_cmd or [self.python_exe, "-u", "-m", self.worker_module]
            argv = list(prefix) + ["--kind", kind, "--params", params_json]
            if script is not None:
                argv += ["--script", str(script)]
            if speed:
                argv += ["--speed", str(speed).lower()]

            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            env["BACKEND"] = "cynthion"
            env["PYTHONIOENCODING"] = "utf-8"
            pkg_parent = str(Path(__file__).resolve().parents[1])
            existing = env.get("PYTHONPATH", "")
            parts = [p for p in existing.split(os.pathsep) if p]
            if pkg_parent not in parts:
                env["PYTHONPATH"] = os.pathsep.join([pkg_parent] + parts)

            creationflags = (
                getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            )

            self._reset_session_state()
            self._kind = kind
            self._params = params or {}
            self._script = str(script) if script is not None else None
            self._speed = speed
            log.info("Starting facedancer worker: %s", argv)
            try:
                proc = subprocess.Popen(
                    argv,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    env=env,
                    creationflags=creationflags,
                )
            except OSError as exc:
                raise _make_error(
                    HardwareError, f"Could not start the Facedancer process: {exc}"
                )
            self._proc = proc
            self._started_at = time.time()
            self._threads = [
                threading.Thread(target=self._read_stdout, args=(proc,), daemon=True,
                                 name="facedancer-stdout"),
                threading.Thread(target=self._read_stderr, args=(proc,), daemon=True,
                                 name="facedancer-stderr"),
            ]
            for t in self._threads:
                t.start()

        # Wait (outside the lifecycle lock) for connection / failure / timeout.
        deadline = time.monotonic() + max(0.0, float(ready_timeout_s))
        connected_evt = self._connected_evt
        while True:
            if connected_evt.wait(0.05):
                break
            if self._fatal_error is not None or proc.poll() is not None:
                # Give the stdout reader a moment to drain final messages.
                for t in self._threads:
                    t.join(1.0)
                if connected_evt.is_set() and proc.poll() is None:
                    break
                self._raise_start_failure(proc)
            if time.monotonic() >= deadline:
                st = self.status()
                st["warning"] = (
                    f"not connected yet after {ready_timeout_s:.1f} s; the emulation "
                    "keeps running - check facedancer_status() / facedancer_logs()"
                )
                return st
        return self.status()

    def _raise_start_failure(self, proc: subprocess.Popen) -> None:
        err = self._fatal_error or self._last_error or {}
        code = str(err.get("code") or "HARDWARE").upper()
        message = err.get("message") or err.get("error")
        if not message:
            rc = proc.poll()
            message = f"Facedancer process exited (exit code {rc})"
        hint = err.get("hint")
        with self._data_lock:
            tail = [text for _, _, text in list(self._logs)[-20:]]
        if tail:
            message = f"{message}\n--- last logs ---\n" + "\n".join(tail)
        # Ensure the child is gone if only a fatal message arrived.
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        self._exit_code = proc.poll()
        cls = _CODE_TO_CLASS.get(code, HardwareError)
        raise _make_error(cls, message, hint)

    # --------------------------------------------------------------- readers
    def _read_stdout(self, proc: subprocess.Popen) -> None:
        stream = proc.stdout
        try:
            for raw in iter(stream.readline, ""):
                line = raw.rstrip("\r\n")
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except ValueError:
                    self._append_log(f"[stdout] {line}")
                    continue
                if not isinstance(msg, dict):
                    self._append_log(f"[stdout] {line}")
                    continue
                self._handle_message(msg)
        except Exception as exc:  # pragma: no cover - defensive
            self._append_log(f"[runner] stdout reading interrupted: {exc}")
        finally:
            with self._data_lock:
                pending = list(self._pending.values())
                self._pending.clear()
            for fut in pending:
                if not fut.done():
                    fut.set_exception(
                        _make_error(HardwareError, "Facedancer process exited")
                    )

    def _handle_message(self, msg: dict) -> None:
        mtype = msg.get("type")
        if mtype == "result":
            mid = msg.get("id")
            with self._data_lock:
                fut = self._pending.pop(mid, None) if isinstance(mid, int) else None
            if fut is not None and not fut.done():
                fut.set_result(msg)
        elif mtype == "connected":
            self._connect_info = {k: v for k, v in msg.items() if k != "type"}
            self._append_event(msg)
            self._connected_evt.set()
        elif mtype == "error":
            self._last_error = msg
            self._append_event(msg)
            if msg.get("fatal"):
                self._fatal_error = msg
            self._append_log(
                f"[error] {msg.get('code', '')} {msg.get('message', '')}".strip()
            )
        elif mtype == "stopped":
            self._stopped_msg = msg
            self._append_event(msg)
        elif mtype == "log":
            self._append_log(str(msg.get("text", "")))
        elif mtype in ("data", "host_event"):
            self._append_event(msg)
        else:
            self._append_event(msg)

    def _read_stderr(self, proc: subprocess.Popen) -> None:
        stream = proc.stderr
        try:
            for raw in iter(stream.readline, ""):
                line = raw.rstrip("\r\n")
                if line:
                    self._append_log(line)
        except Exception:  # pragma: no cover - defensive
            pass

    # -------------------------------------------------------------- commands
    def _write(self, obj: dict) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise _make_error(HardwareError, "Facedancer process unavailable")
        data = json.dumps(obj) + "\n"
        with self._write_lock:
            try:
                proc.stdin.write(data)
                proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as exc:
                raise _make_error(
                    HardwareError, f"Facedancer process unreachable: {exc}"
                )

    def send_command(self, cmd: str, args: dict | None = None,
                     timeout_s: float = 30.0) -> dict:
        """Send a command to the worker and wait for its result."""
        if not self.is_running():
            raise _make_error(WrongModeError, "No active emulation", "facedancer_start(...)")
        if args is not None and not isinstance(args, dict):
            raise _make_error(InvalidArgumentError, "args must be a JSON object")
        mid = next(self._next_id)
        fut: concurrent.futures.Future = concurrent.futures.Future()
        with self._data_lock:
            self._pending[mid] = fut
        try:
            self._write({"id": mid, "cmd": cmd, "args": args or {}})
        except BaseException:
            with self._data_lock:
                self._pending.pop(mid, None)
            raise
        try:
            msg = fut.result(timeout=timeout_s)
        except concurrent.futures.TimeoutError:
            with self._data_lock:
                self._pending.pop(mid, None)
            raise _make_error(
                OperationTimeout,
                f"Command {cmd!r} did not respond within {timeout_s:.1f} s",
            )
        if not msg.get("ok"):
            code = str(msg.get("code") or "HARDWARE").upper()
            cls = _CODE_TO_CLASS.get(code, HardwareError)
            raise _make_error(
                cls, str(msg.get("error") or f"command {cmd!r} failed"),
                msg.get("hint"),
            )
        return {"ok": True, "result": msg.get("value")}

    def board_op(self, op: dict) -> dict:
        """Forward a board_io operation to the worker (it owns the Moondancer board)."""
        return self.send_command("board_op", {"op": op})["result"]

    # ---------------------------------------------------------------- status
    def status(self) -> dict:
        proc = self._proc
        rc = proc.poll() if proc is not None else self._exit_code
        if proc is not None and rc is not None:
            self._exit_code = rc
        running = proc is not None and rc is None
        with self._data_lock:
            events_buffered = len(self._events)
            logs_buffered = len(self._logs)
        uptime = None
        if self._started_at is not None and running:
            uptime = round(time.time() - self._started_at, 3)
        return {
            "ok": True,
            "running": running,
            "pid": proc.pid if proc is not None else None,
            "kind": self._kind,
            "params": self._params,
            "script": self._script,
            "speed": self._speed,
            "started_at": _iso(self._started_at),
            "uptime_s": uptime,
            "connected": self._connected_evt.is_set(),
            "connect_info": self._connect_info,
            "exit_code": rc,
            "last_error": self._last_error,
            "events_buffered": events_buffered,
            "logs_buffered": logs_buffered,
            "stopped": self._stopped_msg,
        }

    def logs(self, lines: int = 100, since_seq: int | None = None) -> dict:
        lines = max(1, int(lines))
        with self._data_lock:
            items = list(self._logs)
            last = self._last_log_seq
        if since_seq is not None:
            items = [it for it in items if it[0] > since_seq][:lines]
        else:
            items = items[-lines:]
        out = [{"seq": s, "t": _iso(t), "text": txt} for s, t, txt in items]
        next_seq = out[-1]["seq"] if out else (since_seq if since_seq is not None else last)
        return {"ok": True, "lines": out, "next_seq": next_seq}

    def events(self, since_seq: int | None = None, limit: int = 200,
               types: list[str] | None = None) -> dict:
        limit = max(1, int(limit))
        with self._data_lock:
            items = list(self._events)
            last = self._last_event_seq
        if since_seq is not None:
            items = [e for e in items if e["seq"] > since_seq]
        if types:
            wanted = set(types)
            # Match the event type (data, host_event, connected, error, stopped, ...), the emulation kind,
            # a host_event name (bus_reset, configured, set_address) or a data source (ftdi, proxy, script...).
            items = [e for e in items if any(e.get(f) in wanted for f in ("type", "kind", "name", "source", "event"))]
        if since_seq is None:
            items = items[-limit:]
        else:
            items = items[:limit]
        next_seq = items[-1]["seq"] if items else (since_seq if since_seq is not None else last)
        return {"ok": True, "events": items, "next_seq": next_seq}

    # ------------------------------------------------------------------ stop
    def stop(self, timeout_s: float = 5.0) -> dict:
        with self._lock:
            proc = self._proc
            if proc is None or proc.poll() is not None:
                st = self.status()
                st["note"] = "no emulation running"
                st["unhandled_requests"] = (self._stopped_msg or {}).get(
                    "unhandled_requests", [])
                return st
            try:
                self._write({"id": 0, "cmd": "stop", "args": {}})
            except Exception:
                pass
            try:
                if proc.stdin:
                    proc.stdin.close()
            except Exception:
                pass
            try:
                proc.wait(timeout_s)
            except subprocess.TimeoutExpired:
                self._append_log("[runner] non-cooperative stop: terminate()")
                proc.terminate()
                try:
                    proc.wait(2)
                except subprocess.TimeoutExpired:
                    self._append_log("[runner] kill()")
                    proc.kill()
                    try:
                        proc.wait(2)
                    except subprocess.TimeoutExpired:
                        pass
            for t in self._threads:
                t.join(1.0)
            self._exit_code = proc.poll()
            return {
                "ok": True,
                "exit_code": self._exit_code,
                "unhandled_requests": (self._stopped_msg or {}).get(
                    "unhandled_requests", []),
                "last_error": self._last_error,
            }

    def shutdown(self) -> None:
        """Best-effort stop; used by atexit and the server lifespan."""
        try:
            if self.is_running():
                self.stop(3.0)
        except Exception:
            log.debug("facedancer runner shutdown failed", exc_info=True)


RUNNER = FacedancerRunner()
atexit.register(RUNNER.shutdown)
