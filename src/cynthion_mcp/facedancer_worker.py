"""Facedancer (Moondancer) child-process worker.

Runs ONE emulated USB device on a Cynthion that is running the facedancer
gateware + moondancer SoC firmware, until told to stop.

Usage::

    python -u -m cynthion_mcp.facedancer_worker --kind KIND [--params JSON]
                                                [--script PATH] [--speed auto|full|high]

Protocol (JSON lines):

* stdout  -> protocol messages for the parent (one JSON object per line).
* stderr  -> free-form log lines (logging + any library ``print()``).
* stdin   <- commands ``{"id": int, "cmd": str, "args": {...}}``; EOF means stop.

Child -> parent message types: ``ready``, ``connected``, ``error``, ``result``,
``data``, ``host_event`` and finally always ``stopped``.

Every third-party API used here was checked against the installed sources of
facedancer 3.1.3 / cynthion 0.2.5 / pygreat:

* ``facedancer.backends.moondancer.MoondancerApp(device=None, verbose=0, quirks=[])``
* ``facedancer.devices.keyboard.USBKeyboardDevice`` (``type_string(to_type, *, duration)``,
  ``key_down``, ``modifier_down``, ``all_keys_up``, ``all_modifiers_up``)
* ``facedancer.devices.ftdi.FTDIDevice`` (``handle_serial_data_received(data)``,
  ``transmit(data, *, blocking, adjust_endings)``)
* ``facedancer.devices.umass.{USBMassStorageDevice, RawDiskImage, FAT32DiskImage}``
  (``USBMassStorageDevice.connect()`` takes no speed argument)
* ``facedancer.proxy.USBProxyDevice(idVendor=, idProduct=)`` (``connect()`` takes no
  argument; ``filter_list`` is a class attribute; may ``sys.exit(1)``)
* ``facedancer.filters.{USBProxyFilter, USBProxySetupFilters, USBProxyPrettyPrintFilter}``
* ``facedancer.classes.hid.keyboard.{KeyboardKeys, KeyboardModifiers}``
"""

from __future__ import annotations

import argparse
import asyncio
import importlib.util
import inspect
import json
import logging
import os
import sys
import threading
import time
from typing import Any, Callable, Dict, Optional

# --- make absolute imports work when executed as a plain script ------------
try:  # pragma: no cover - trivial
    import cynthion_mcp  # noqa: F401
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from cynthion_mcp.common import translate_exception
except Exception:  # pragma: no cover - fallback if common is broken
    class _FallbackError(Exception):
        def __init__(self, code: str, message: str, hint: Optional[str] = None):
            super().__init__(message)
            self.code, self.message, self.hint = code, message, hint

        def format(self) -> str:
            s = f"[{self.code}] {self.message}"
            if self.hint:
                s += f"\nHint: {self.hint}"
            return s

    def translate_exception(exc: BaseException):  # type: ignore[misc]
        if hasattr(exc, "code") and hasattr(exc, "format") and hasattr(exc, "message"):
            return exc
        return _FallbackError("HARDWARE", f"{type(exc).__name__}: {exc}")


log = logging.getLogger("cynthion_mcp.facedancer_worker")

HINT_GATEWARE = ("Load the Facedancer gateware: run_gateware(target='facedancer') "
                 "(flashes moondancer.bin then configures facedancer.bit).")
HINT_WINUSB = ("Could not open the device to relay. On Windows, bind it to the WinUSB driver "
               "(Zadig) and check that VID/PID are correct and that no other program is using it.")

MAX_HEX_BYTES = 4096   # truncate very large payloads in data messages

# ---------------------------------------------------------------------------
# Static description of the supported device kinds.
# facedancer_runner keeps an identical copy as KIND_SPECS (no facedancer import
# in the parent process) -- keep both in sync.
# ---------------------------------------------------------------------------
COMMON_COMMANDS = ["stop", "ping", "status", "board_op", "unhandled_requests",
                   "descriptor", "generate_code"]

KINDS: Dict[str, Dict[str, Any]] = {
    "keyboard": {
        "description": "USB HID keyboard (facedancer USBKeyboardDevice). Types text / key combos on the target host.",
        "params": {},
        "commands": {
            "type_string": {"text": "str", "duration": "float=0.05"},
            "key_combo": {"keys": "list[str|int] (KeyboardKeys names e.g. 'ENTER','A','F4' or scancodes)",
                          "modifiers": "list[str] (e.g. 'MOD_LEFT_CTRL','CTRL','SHIFT','ALT','META'/'GUI')",
                          "duration": "float=0.05"},
            "all_keys_up": {},
        },
    },
    "ftdi": {
        "description": "FTDI FT232 USB-serial adapter (VID 0403 PID 6001). Host->device serial data is reported as 'data' events.",
        "params": {},
        "commands": {
            "serial_write": {"data": "str (text, or hex when is_hex=true)", "is_hex": "bool=false"},
        },
    },
    "mass_storage": {
        "description": "USB mass-storage (SCSI bulk-only). Backed by a raw image file or a synthetic FAT32 image.",
        "params": {
            "image_path": "str|None (existing writable raw disk image; omit for synthetic FAT32)",
            "block_size": "int=512",
            "size_mb": "int=64 (synthetic FAT32 size)",
            "vendor_id": "int|None", "product_id": "int|None",
        },
        "commands": {},
    },
    "proxy": {
        "description": "USBProxy: relays a real USB device (plugged into this PC) to the target host; traffic is reported as 'data' events.",
        "params": {"vid": "int", "pid": "int", "pretty_print": "bool=false (log traffic to stderr)"},
        "commands": {},
    },
    "script": {
        "description": ("User Python script (--script PATH) defining `device` (USBDevice) or "
                        "`create_device(params) -> USBDevice`; optional `async def main(device, api)` and "
                        "`handle_command(device, cmd, args)` (sync or async)."),
        "params": {"*": "passed to create_device(params)"},
        "commands": {"*": "forwarded to handle_command(device, cmd, args)"},
    },
}

SPEEDS = ("auto", "full", "high")

# ---------------------------------------------------------------------------
# Protocol output
# ---------------------------------------------------------------------------
_PROTO = None              # the real stdout (set in main)
_EMIT_LOCK = threading.Lock()


def emit(obj: Dict[str, Any]) -> None:
    """Write one JSON protocol message on the real stdout (thread-safe)."""
    stream = _PROTO if _PROTO is not None else sys.__stdout__
    line = json.dumps(obj, default=str) + "\n"
    with _EMIT_LOCK:
        try:
            stream.write(line)
            stream.flush()
        except Exception:  # parent gone; nothing more we can do
            pass


def emit_error(exc: BaseException, fatal: bool, code: Optional[str] = None,
               hint: Optional[str] = None) -> Any:
    err = translate_exception(exc)
    msg = {
        "type": "error",
        "code": code or getattr(err, "code", "HARDWARE"),
        "message": getattr(err, "message", str(err)),
        "hint": hint if hint is not None else getattr(err, "hint", None),
        "fatal": fatal,
    }
    emit(msg)
    return err


def _hex(data: Any) -> str:
    if data is None:
        return ""
    b = bytes(data)
    return b[:MAX_HEX_BYTES].hex()


def _text(data: Any) -> Optional[str]:
    if not data:
        return None
    try:
        b = bytes(data)[:MAX_HEX_BYTES]
        s = b.decode("utf-8")
        return s if all(c.isprintable() or c in "\r\n\t" for c in s) else None
    except Exception:
        return None


def emit_data(source: str, direction: Optional[str], endpoint: Optional[int], data: Any,
              **extra: Any) -> None:
    raw = bytes(data) if data is not None else b""
    msg = {"type": "data", "source": source, "direction": direction, "endpoint": endpoint,
           "hex": _hex(raw), "text": _text(raw), "length": len(raw),
           "truncated": len(raw) > MAX_HEX_BYTES, "t": time.time()}
    msg.update(extra)
    emit(msg)


class WorkerError(Exception):
    """Error with an explicit protocol code (used before/without translate_exception)."""

    def __init__(self, code: str, message: str, hint: Optional[str] = None):
        super().__init__(message)
        self.code, self.message, self.hint = code, message, hint

    def format(self) -> str:
        s = f"[{self.code}] {self.message}"
        if self.hint:
            s += f"\nHint: {self.hint}"
        return s


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _int(v: Any, name: str) -> int:
    if isinstance(v, bool):
        raise WorkerError("INVALID_ARGUMENT", f"Invalid parameter {name}: {v!r}")
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v, 0)
        except ValueError:
            pass
    raise WorkerError("INVALID_ARGUMENT", f"Invalid parameter {name}: {v!r} (integer expected)")


_MOD_ALIASES = {
    "CTRL": "MOD_LEFT_CTRL", "CONTROL": "MOD_LEFT_CTRL", "SHIFT": "MOD_LEFT_SHIFT",
    "ALT": "MOD_LEFT_ALT", "META": "MOD_LEFT_META", "GUI": "MOD_LEFT_META",
    "WIN": "MOD_LEFT_META", "WINDOWS": "MOD_LEFT_META", "CMD": "MOD_LEFT_META",
    "SUPER": "MOD_LEFT_META", "ALTGR": "MOD_RIGHT_ALT",
}


def _resolve_modifier(name: Any):
    from facedancer.classes.hid.keyboard import KeyboardModifiers
    if isinstance(name, int) and not isinstance(name, bool):
        return KeyboardModifiers(name)
    key = str(name).strip().upper().replace(" ", "_")
    key = _MOD_ALIASES.get(key, key)
    if not key.startswith("MOD_"):
        key = "MOD_" + key
    for member in KeyboardModifiers:
        if member.name.upper() == key:
            return member
    raise WorkerError("INVALID_ARGUMENT", f"Unknown modifier: {name!r}",
                      "Possible values: " + ", ".join(m.name for m in KeyboardModifiers))


def _resolve_key(name: Any):
    """Resolve a key name to a scancode (modifiers implied by ASCII are dropped;
    use ``_resolve_key_ex`` to keep them)."""
    return _resolve_key_ex(name)[0]


def _resolve_key_ex(name: Any):
    """Resolve a key name to ``(scancode, implied_modifiers)``.

    ``implied_modifiers`` is non-zero (MOD_LEFT_SHIFT) for a single shifted
    ASCII character such as '!' or '@', as returned by
    ``KeyboardKeys.get_scancode_for_ascii`` -> ``(modifiers, scancode)``.
    """
    from facedancer.classes.hid.keyboard import KeyboardKeys
    if isinstance(name, int) and not isinstance(name, bool):
        return name, 0
    s = str(name).strip()
    upper = s.upper().replace(" ", "_")
    for member in KeyboardKeys:
        if member.name.upper() == upper:
            return member, 0
    aliases = {"RETURN": "ENTER", "ESC": "ESCAPE", "DEL": "DELETE", "SPACEBAR": "SPACE"}
    if upper in aliases:
        for member in KeyboardKeys:
            if member.name.upper() == aliases[upper]:
                return member, 0
    if len(s) == 1:  # single printable character
        try:
            shift, code = KeyboardKeys.get_scancode_for_ascii(s)
            return code, shift
        except Exception:
            pass
    raise WorkerError("INVALID_ARGUMENT", f"Unknown key: {name!r}",
                      "Use a KeyboardKeys name (e.g. 'ENTER', 'A', 'F4', 'TAB') or an integer scancode.")


def _format_suggestion(s: Any) -> str:
    try:
        direction, rtype, recipient, rid, number = s
        def n(x):
            return getattr(x, "name", str(x))
        rid_s = "" if rid is None else f" index={rid}"
        return f"{n(direction)} {n(rtype)} {n(recipient)}{rid_s} request={number}"
    except Exception:
        return str(s)


def unhandled_requests(device: Any) -> list:
    try:
        return sorted(_format_suggestion(x) for x in (getattr(device, "_suggested_requests", None) or []))
    except Exception:
        return []


def board_summary(board: Any) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    for key, fn in (("board_name", lambda: board.board_name()),
                    ("firmware_version", lambda: board.firmware_version()),
                    ("serial", lambda: board.serial_number()),
                    ("part_id", lambda: board.part_id())):
        try:
            info[key] = fn()
        except Exception as e:  # pragma: no cover - hardware dependent
            info[key] = None
            log.debug("board %s unavailable: %s", key, e)
    return info


# ---------------------------------------------------------------------------
# Device builders
# ---------------------------------------------------------------------------
def build_keyboard(params: Dict[str, Any], script_path: Optional[str]):
    from facedancer.devices.keyboard import USBKeyboardDevice
    return USBKeyboardDevice(), None


def build_ftdi(params: Dict[str, Any], script_path: Optional[str]):
    from facedancer.devices.ftdi import FTDIDevice

    # Do NOT subclass: facedancer's instantiate_subordinates() only scans
    # type(obj).__dict__, so a subclass loses FTDIDevice's inner
    # configuration/interface/endpoint classes ("No configurations defined",
    # then KeyError in get_configuration_descriptor).  Override on the instance.
    device = FTDIDevice()

    def handle_serial_data_received(data):
        emit_data("ftdi", "out", None, data)

    device.handle_serial_data_received = handle_serial_data_received
    return device, None


def build_mass_storage(params: Dict[str, Any], script_path: Optional[str]):
    from facedancer.devices.umass import USBMassStorageDevice, RawDiskImage, FAT32DiskImage
    image_path = params.get("image_path")
    if image_path:
        image_path = os.path.abspath(os.path.expanduser(str(image_path)))
        if not os.path.isfile(image_path):
            raise WorkerError("INVALID_ARGUMENT", f"Disk image not found: {image_path}",
                              "Provide an existing raw image file (or omit image_path for a synthetic FAT32 image).")
        if not os.access(image_path, os.W_OK):
            raise WorkerError("INVALID_ARGUMENT", f"Disk image not writable: {image_path}",
                              "RawDiskImage opens the file read/write (r+b).")
        block_size = _int(params.get("block_size", 512), "block_size")
        image = RawDiskImage(image_path, block_size)
    else:
        size_mb = _int(params.get("size_mb", 64), "size_mb")
        if size_mb < 1 or size_mb > 1024 * 1024:
            raise WorkerError("INVALID_ARGUMENT", f"size_mb out of range: {size_mb}")
        image = FAT32DiskImage(size=size_mb * 1024 * 1024)
    kwargs: Dict[str, Any] = {}
    if params.get("vendor_id") is not None:
        kwargs["vendor_id"] = _int(params["vendor_id"], "vendor_id")
    if params.get("product_id") is not None:
        kwargs["product_id"] = _int(params["product_id"], "product_id")
    return USBMassStorageDevice(image, **kwargs), None


def build_proxy(params: Dict[str, Any], script_path: Optional[str]):
    if "vid" not in params or "pid" not in params:
        raise WorkerError("INVALID_ARGUMENT", "Proxy mode requires params.vid and params.pid.")
    vid = _int(params["vid"], "vid")
    pid = _int(params["pid"], "pid")
    from facedancer.proxy import USBProxyDevice
    from facedancer.filters import USBProxySetupFilters, USBProxyPrettyPrintFilter, USBProxyFilter

    class CaptureFilter(USBProxyFilter):
        """Reports proxied traffic as protocol 'data' messages; never alters it."""

        def filter_control_in(self, request, data, stalled):
            if request is not None:
                emit_data("proxy", "control", 0, data or b"", stage="in",
                          setup=str(request), stalled=bool(stalled),
                          request_type=getattr(request, "request_type", None),
                          request=getattr(request, "number", None),
                          value=getattr(request, "value", None),
                          index=getattr(request, "index", None),
                          req_length=getattr(request, "length", None))
            return request, data, stalled

        def filter_control_out(self, request, data):
            if request is not None:
                emit_data("proxy", "control", 0, data or b"", stage="out", setup=str(request),
                          request_type=getattr(request, "request_type", None),
                          request=getattr(request, "number", None),
                          value=getattr(request, "value", None),
                          index=getattr(request, "index", None))
            return request, data

        def filter_in(self, ep_num, data):
            if data:
                emit_data("proxy", "in", ep_num, data)
            return ep_num, data

        def filter_out(self, ep_num, data):
            if data:
                emit_data("proxy", "out", ep_num, data)
            return ep_num, data

    try:
        proxy = USBProxyDevice(idVendor=vid, idProduct=pid)
    except SystemExit as e:
        raise WorkerError("DRIVER", f"Could not open device {vid:04x}:{pid:04x} (sys.exit {e.code}).",
                          HINT_WINUSB) from None
    except BaseException as e:
        if type(e).__name__ == "DeviceNotFoundError":
            raise WorkerError("NO_DEVICE", f"Device to relay {vid:04x}:{pid:04x} not found.",
                              "Plug the device into this PC and check VID/PID (list_devices does not show it: use Device Manager).") from None
        raise WorkerError("DRIVER", f"Could not open device {vid:04x}:{pid:04x}: {e}",
                          HINT_WINUSB) from None
    proxy.filter_list = []   # class-level list in facedancer: make it per instance
    proxy.add_filter(USBProxySetupFilters(proxy, verbose=0))
    proxy.add_filter(CaptureFilter())
    if params.get("pretty_print"):
        proxy.add_filter(USBProxyPrettyPrintFilter(verbose=4))
    return proxy, None


def build_script(params: Dict[str, Any], script_path: Optional[str]):
    if not script_path:
        raise WorkerError("INVALID_ARGUMENT", "Script mode requires --script PATH.")
    path = os.path.abspath(os.path.expanduser(script_path))
    if not os.path.isfile(path):
        raise WorkerError("INVALID_ARGUMENT", f"Script not found: {path}")
    spec = importlib.util.spec_from_file_location("user_facedancer_script", path)
    if spec is None or spec.loader is None:
        raise WorkerError("INVALID_ARGUMENT", f"Could not load script: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["user_facedancer_script"] = module
    spec.loader.exec_module(module)
    if callable(getattr(module, "create_device", None)):
        device = module.create_device(dict(params))
    elif getattr(module, "device", None) is not None:
        device = module.device
    else:
        raise WorkerError("INVALID_ARGUMENT",
                          "The script must define `device` (USBDevice instance) or `create_device(params)`.")
    from facedancer.device import USBBaseDevice
    if not isinstance(device, USBBaseDevice):
        raise WorkerError("INVALID_ARGUMENT",
                          f"`device` must be a facedancer USBDevice instance (got {type(device).__name__}).")
    return device, module


BUILDERS: Dict[str, Callable] = {
    "keyboard": build_keyboard,
    "ftdi": build_ftdi,
    "mass_storage": build_mass_storage,
    "proxy": build_proxy,
    "script": build_script,
}


# ---------------------------------------------------------------------------
# Script API
# ---------------------------------------------------------------------------
class ScriptAPI:
    """Object passed to a user script's `main(device, api)`."""

    def __init__(self, worker: "Worker"):
        self._worker = worker
        self.params = worker.params
        self.log = logging.getLogger("user_facedancer_script")

    def emit(self, obj: Any) -> None:
        """Send a 'data' message to the parent (dict fields are merged in)."""
        msg: Dict[str, Any] = {"type": "data", "source": "script", "direction": None,
                               "endpoint": None, "hex": "", "text": None, "t": time.time()}
        if isinstance(obj, (bytes, bytearray, memoryview)):
            msg["hex"], msg["text"] = _hex(obj), _text(obj)
        elif isinstance(obj, dict):
            msg.update(obj)
            if msg.get("type") not in ("data", "host_event"):
                msg["type"] = "data"
        else:
            msg["text"] = str(obj)
        emit(msg)

    def stop(self) -> None:
        """Request the end of the emulation."""
        self._worker.request_stop("script")


# ---------------------------------------------------------------------------
# Worker runtime
# ---------------------------------------------------------------------------
class Worker:
    def __init__(self, kind: str, params: Dict[str, Any], device: Any, board: Any,
                 module: Any = None):
        self.kind = kind
        self.params = params
        self.device = device
        self.board = board
        self.module = module
        self.connected = False
        self.stop_reason = "stop requested"
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.stop_evt: Optional[asyncio.Event] = None
        self.queue: Optional[asyncio.Queue] = None

    # -- stop -------------------------------------------------------------
    def request_stop(self, reason: str) -> None:
        self.stop_reason = reason
        if self.loop is not None and self.stop_evt is not None:
            try:
                self.loop.call_soon_threadsafe(self.stop_evt.set)
            except RuntimeError:
                pass

    # -- host-event hooks --------------------------------------------------
    def install_hooks(self) -> None:
        dev = self.device
        orig_reset = dev.handle_bus_reset

        def handle_bus_reset(*a, **kw):
            emit({"type": "host_event", "name": "bus_reset", "t": time.time()})
            return orig_reset(*a, **kw)

        dev.handle_bus_reset = handle_bus_reset

        backend = dev.backend
        orig_configured = getattr(backend, "configured", None)
        if orig_configured is not None:
            def configured(configuration, *a, **kw):
                emit({"type": "host_event", "name": "configured",
                      "configuration": getattr(configuration, "number", None), "t": time.time()})
                return orig_configured(configuration, *a, **kw)
            backend.configured = configured

        orig_set_address = getattr(backend, "set_address", None)
        if orig_set_address is not None:
            def set_address(address, *a, **kw):
                emit({"type": "host_event", "name": "set_address", "address": address, "t": time.time()})
                return orig_set_address(address, *a, **kw)
            backend.set_address = set_address

    # -- stdin ------------------------------------------------------------
    def _stdin_reader(self) -> None:
        stream = getattr(sys.stdin, "buffer", sys.stdin)
        try:
            while True:
                line = stream.readline()
                if not line:
                    break
                if isinstance(line, bytes):
                    line = line.decode("utf-8", errors="replace")
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    if not isinstance(msg, dict):
                        raise ValueError("not an object")
                except Exception as e:
                    emit({"type": "error", "code": "INVALID_ARGUMENT",
                          "message": f"Invalid JSON command: {e}", "hint": None, "fatal": False})
                    continue
                self.loop.call_soon_threadsafe(self.queue.put_nowait, msg)
        except Exception as e:  # pragma: no cover
            log.warning("stdin reader failed: %s", e)
        try:
            self.loop.call_soon_threadsafe(self.queue.put_nowait, {"cmd": "stop", "_eof": True})
        except RuntimeError:
            pass

    async def _command_task(self) -> None:
        while True:
            msg = await self.queue.get()
            cmd = str(msg.get("cmd", ""))
            if cmd == "stop":
                if msg.get("id") is not None:
                    emit({"type": "result", "id": msg.get("id"), "ok": True, "value": "stopping", "error": None})
                self.stop_reason = "stdin closed" if msg.get("_eof") else "stop command"
                self.stop_evt.set()
                continue
            asyncio.create_task(self._handle(msg))

    async def _handle(self, msg: Dict[str, Any]) -> None:
        cid = msg.get("id")
        cmd = str(msg.get("cmd", ""))
        args = msg.get("args") or {}
        try:
            if not isinstance(args, dict):
                raise WorkerError("INVALID_ARGUMENT", "args must be a JSON object.")
            value = await self._dispatch(cmd, args)
            emit({"type": "result", "id": cid, "ok": True, "value": value, "error": None})
        except Exception as e:
            log.warning("command %s failed: %s", cmd, e)
            # Send code / message / hint as separate fields so the runner can
            # rebuild the right CynthionMCPError subclass (error-code contract).
            try:
                err: Any = e if isinstance(e, WorkerError) else translate_exception(e)
                code = str(getattr(err, "code", None) or "HARDWARE")
                message = str(getattr(err, "message", None) or e)
                hint = getattr(err, "hint", None)
            except Exception:
                code, message, hint = "HARDWARE", f"{type(e).__name__}: {e}", None
            emit({"type": "result", "id": cid, "ok": False, "value": None,
                  "code": code, "error": message, "hint": hint})

    async def _dispatch(self, cmd: str, args: Dict[str, Any]) -> Any:
        dev = self.device
        # ---- common commands --------------------------------------------
        if cmd == "ping":
            return "pong"
        if cmd == "status":
            return {"connected": self.connected, "kind": self.kind,
                    "suggested_requests": len(getattr(dev, "_suggested_requests", None) or []),
                    "address": getattr(dev, "address", None),
                    "configured": getattr(dev, "configuration", None) is not None}
        if cmd == "board_op":
            from cynthion_mcp.board_io import apply_board_op
            op = args.get("op", args)
            # libgreat RPCs are blocking; they share the USB link with service_irqs,
            # which runs on this same loop thread, so calling inline keeps them serialised.
            return apply_board_op(self.board, op)
        if cmd == "unhandled_requests":
            return unhandled_requests(dev)
        if cmd == "descriptor":
            return dev.get_descriptor().hex()
        if cmd == "generate_code":
            return dev.generate_code(name=str(args.get("name", "Device")))
        if cmd in ("list_commands", "help"):
            return {"common": COMMON_COMMANDS, "kind": list(KINDS[self.kind]["commands"].keys())}

        # ---- keyboard ---------------------------------------------------
        if self.kind == "keyboard":
            if cmd == "type_string":
                text = args.get("text")
                if not isinstance(text, str):
                    raise WorkerError("INVALID_ARGUMENT", "type_string requires args.text (string).")
                duration = float(args.get("duration", 0.05))
                await dev.type_string(text, duration=duration)
                return {"typed": len(text)}
            if cmd == "key_combo":
                keys = args.get("keys") or []
                mods = args.get("modifiers") or []
                if isinstance(keys, (str, int)):
                    keys = [keys]
                if isinstance(mods, (str, int)):
                    mods = [mods]
                duration = float(args.get("duration", 0.05))
                resolved = [_resolve_key_ex(k) for k in keys]
                rk = [code for code, _implied in resolved]
                rm = [_resolve_modifier(m) for m in mods]
                # Shifted ASCII characters ('!', '@', ...) need SHIFT held.
                implied = [m for _code, m in resolved if m]
                for m in implied:
                    if m not in rm:
                        rm.append(m)
                if not rk and not rm:
                    raise WorkerError("INVALID_ARGUMENT", "key_combo requires at least one key or modifier.")
                try:
                    for m in rm:
                        dev.modifier_down(m)
                    for k in rk:
                        dev.key_down(k)
                    await asyncio.sleep(duration)
                finally:
                    dev.all_keys_up()
                    dev.all_modifiers_up()
                await asyncio.sleep(duration)
                return {"keys": [getattr(k, "name", k) for k in rk],
                        "modifiers": [getattr(m, "name", m) for m in rm]}
            if cmd == "all_keys_up":
                dev.all_keys_up()
                dev.all_modifiers_up()
                return True

        # ---- ftdi -------------------------------------------------------
        if self.kind == "ftdi" and cmd == "serial_write":
            data = args.get("data", "")
            if args.get("is_hex") or args.get("hex"):
                try:
                    payload: Any = bytes.fromhex(str(data).replace(" ", "").replace(":", ""))
                except ValueError as e:
                    raise WorkerError("INVALID_ARGUMENT", f"Invalid hex: {e}")
                dev.transmit(payload, adjust_endings=False)
                n = len(payload)
            else:
                payload = str(data)
                dev.transmit(payload, adjust_endings=bool(args.get("adjust_endings", False)))
                n = len(payload.encode("utf-8"))
            emit_data("ftdi", "in", None, payload.encode("utf-8") if isinstance(payload, str) else payload)
            return {"bytes": n}

        # ---- script -----------------------------------------------------
        if self.kind == "script" and self.module is not None:
            handler = getattr(self.module, "handle_command", None)
            if callable(handler):
                res = handler(dev, cmd, args)
                if inspect.isawaitable(res):
                    res = await res
                return res

        raise WorkerError("INVALID_ARGUMENT", f"Unknown command for '{self.kind}': {cmd!r}",
                          "Commands: " + ", ".join(COMMON_COMMANDS + list(KINDS[self.kind]["commands"].keys())))

    async def _watcher(self) -> None:
        from facedancer.errors import EndEmulation
        await self.stop_evt.wait()
        raise EndEmulation(self.stop_reason)

    async def _user_main(self) -> None:
        fn = getattr(self.module, "main", None)
        await fn(self.device, ScriptAPI(self))

    async def amain(self, speed: str) -> None:
        from facedancer.errors import EndEmulation
        self.loop = asyncio.get_running_loop()
        self.stop_evt = asyncio.Event()
        self.queue = asyncio.Queue()
        threading.Thread(target=self._stdin_reader, name="stdin-reader", daemon=True).start()

        # Connect (blocking libusb RPC, but nothing else runs yet).
        if self.kind in ("mass_storage", "proxy") or speed == "auto":
            # USBMassStorageDevice.connect() and USBProxyDevice.connect() take no speed.
            self.device.connect()
        else:
            from facedancer import DeviceSpeed
            self.device.connect(device_speed=DeviceSpeed.HIGH if speed == "high" else DeviceSpeed.FULL)
        self.connected = True
        eff_speed = speed
        if self.kind == "proxy":
            try:
                eff_speed = self.device.proxied_device.device_speed().name.lower()
            except Exception:
                pass
        elif speed == "auto":
            eff_speed = getattr(getattr(self.device, "device_speed", None), "name", "full").lower()
        emit({"type": "connected", "kind": self.kind, "speed": eff_speed,
              "vid": f"0x{int(getattr(self.device, 'vendor_id', 0) or 0):04x}",
              "pid": f"0x{int(getattr(self.device, 'product_id', 0) or 0):04x}",
              "board": board_summary(self.board)})

        tasks = [self.device.run(), self._command_task(), self._watcher()]
        if self.module is not None and inspect.iscoroutinefunction(getattr(self.module, "main", None)):
            tasks.append(self._user_main())
        try:
            await asyncio.gather(*tasks)
        except EndEmulation:
            pass
        finally:
            self.connected = False
            try:
                self.device.disconnect()
            except Exception as e:
                log.warning("disconnect failed: %s", e)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="cynthion_mcp.facedancer_worker",
                                description="Run one Facedancer emulated device on a Cynthion (JSON-lines protocol).")
    p.add_argument("--kind", required=True, choices=sorted(KINDS))
    p.add_argument("--params", default="{}", help="JSON object with kind-specific parameters")
    p.add_argument("--script", default=None, help="Python file for --kind script")
    p.add_argument("--speed", default="auto", choices=SPEEDS)
    return p.parse_args(argv)


def main(argv=None) -> int:
    global _PROTO
    _PROTO = sys.stdout
    sys.stdout = sys.stderr      # any library print() goes to the log pipe
    logging.basicConfig(stream=sys.stderr, level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    exit_code = 1
    reason = "exception"
    device = None
    board = None
    kind = "?"
    try:
        try:
            args = parse_args(argv)
        except SystemExit as e:
            emit({"type": "error", "code": "INVALID_ARGUMENT", "message": "Invalid arguments.",
                  "hint": None, "fatal": True})
            reason = "bad arguments"
            exit_code = int(e.code or 2) if isinstance(e.code, int) else 2
            return exit_code
        kind = args.kind
        emit({"type": "ready", "pid": os.getpid(), "kind": kind})

        try:
            params = json.loads(args.params or "{}")
            if not isinstance(params, dict):
                raise ValueError("params must be a JSON object")
        except ValueError as e:
            emit({"type": "error", "code": "INVALID_ARGUMENT", "message": f"Invalid --params: {e}",
                  "hint": None, "fatal": True})
            reason = "bad params"
            return 2

        # 1. Open the Moondancer board.
        try:
            import cynthion
            import cynthion.cynthion as cc
            cc.active_connections.clear()
            board = cynthion.Cynthion()
        except BaseException as e:
            if isinstance(e, KeyboardInterrupt):
                raise
            emit_error(e, fatal=True, code="NO_DEVICE",
                       hint="No Facedancer gateware detected. " + HINT_GATEWARE)
            reason = "board not found"
            return 2

        # 2. Check that the moondancer API is there.
        try:
            ok = board.supports_api("moondancer")
        except Exception:
            ok = False
        if not ok:
            emit({"type": "error", "code": "WRONG_MODE",
                  "message": "The Cynthion does not provide the 'moondancer' API.",
                  "hint": HINT_GATEWARE, "fatal": True})
            reason = "wrong mode"
            return 3

        # 3. Build device + backend.
        try:
            device, module = BUILDERS[kind](params, args.script)
            from facedancer.backends.moondancer import MoondancerApp
            device.backend = MoondancerApp(board, verbose=0, quirks=[])
        except BaseException as e:
            if isinstance(e, KeyboardInterrupt):
                raise
            if isinstance(e, WorkerError):
                emit({"type": "error", "code": e.code, "message": e.message, "hint": e.hint, "fatal": True})
            elif isinstance(e, SystemExit):
                emit({"type": "error", "code": "HARDWARE", "message": f"Operation aborted (sys.exit {e.code}).",
                      "hint": None, "fatal": True})
            else:
                emit_error(e, fatal=True)
            reason = "device setup failed"
            return 1

        worker = Worker(kind, params, device, board, module)
        worker.install_hooks()

        # 4. Run.
        asyncio.run(worker.amain(args.speed))
        reason = worker.stop_reason
        exit_code = 0
        return 0
    except KeyboardInterrupt:
        reason = "interrupted"
        exit_code = 0
        return 0
    except BaseException as e:   # includes SystemExit from proxy / user code
        if isinstance(e, WorkerError):
            emit({"type": "error", "code": e.code, "message": e.message, "hint": e.hint, "fatal": True})
        elif isinstance(e, SystemExit):
            emit({"type": "error", "code": "HARDWARE", "message": f"Operation aborted (sys.exit {e.code}).",
                  "hint": None, "fatal": True})
        else:
            log.exception("emulation failed")
            emit_error(e, fatal=True)
        reason = f"error: {type(e).__name__}: {e}"
        exit_code = 1
        return 1
    finally:
        emit({"type": "stopped", "reason": reason,
              "unhandled_requests": unhandled_requests(device) if device is not None else []})
        if board is not None:
            try:
                board.close()
            except Exception as e:
                log.debug("board.close failed: %s", e)


if __name__ == "__main__":
    _code = main()
    # Hard exit: the daemon stdin-reader thread is blocked in a buffered read;
    # normal interpreter finalisation then aborts with "_enter_buffered_busy"
    # (exit 0xC0000005 on Windows).  Everything useful is already emitted.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.flush()
        except Exception:
            pass
    os._exit(_code if isinstance(_code, int) else 1)
