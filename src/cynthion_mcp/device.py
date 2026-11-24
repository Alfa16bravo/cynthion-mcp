"""Apollo connection manager and non-invasive Cynthion device discovery.

Every third-party call below was checked against the installed sources of
apollo_fpga 1.1.1 (``apollo_fpga/__init__.py``, ``jtag.py``, ``ecp5.py``) and
pyusb 1.2.1. Heavy imports (apollo_fpga) are lazy so importing this module
never requires the hardware stack to be functional.
"""

from __future__ import annotations

import contextlib
import time
import warnings
from typing import Any, Iterable, Iterator

try:  # pyusb is allowed at module level by the design, but stay defensive.
    import usb.core
    import usb.util
except Exception:  # pragma: no cover - pyusb missing/broken
    usb = None  # type: ignore[assignment]

from . import common as _common
from .common import (
    ACTIVITY,
    CynthionMCPError,
    HardwareError,
    InvalidArgumentError,
    NoDeviceError,
    UnsupportedError,
    stdout_to_stderr,
    translate_exception,
)

# --------------------------------------------------------------------------
# Optional names from common (tolerate small naming differences).
# --------------------------------------------------------------------------
_TimeoutErr = (
    getattr(_common, "OperationTimeout", None)
    or getattr(_common, "TimeoutError_", None)
    or HardwareError
)
hw_lock = getattr(_common, "hw_lock", None)
HW_LOCK = getattr(_common, "HW_LOCK", None)

HINT_WINUSB = getattr(
    _common,
    "HINT_WINUSB",
    "On Windows, the WinUSB driver must be bound to the device (normally automatic "
    "via MS OS descriptors; otherwise use Zadig on 1d50:615c and 1d50:615b).",
)
HINT_PLUG = getattr(
    _common,
    "HINT_PLUG",
    "Plug in the Cynthion CONTROL port (left-side USB-C); on Windows check the WinUSB driver.",
)

try:
    logger = _common.logger  # type: ignore[attr-defined]
except AttributeError:  # pragma: no cover
    import logging

    logger = logging.getLogger("cynthion_mcp.device")


@contextlib.contextmanager
def _lock(timeout: float) -> Iterator[None]:
    """Acquire the global hardware lock (common.hw_lock or HW_LOCK)."""
    if hw_lock is not None:
        with hw_lock(timeout):
            yield
        return
    if HW_LOCK is None:
        yield
        return
    if not HW_LOCK.acquire(timeout=timeout):
        raise _common.BusyError(  # type: ignore[attr-defined]
            "The hardware is busy with another operation.", None
        )
    try:
        yield
    finally:
        HW_LOCK.release()


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
VID_GSG = 0x1D50
PID_APOLLO = 0x615C
PID_CYNTHION = 0x615B
VID_PIDCODES = 0x1209
PID_APOLLO_ALT = 0x0010

SUBCLASS_STUB = 0x00
SUBCLASS_ANALYZER = 0x10
SUBCLASS_MOONDANCER = 0x20

LED_PATTERN_IDLE = 500
LED_PATTERN_UPLOAD = 50

MODES = ("absent", "apollo", "analyzer", "facedancer", "gateware_stub", "unknown")

_DEFAULT_APOLLO_IDS = [(VID_GSG, PID_APOLLO), (VID_PIDCODES, PID_APOLLO_ALT)]
_DEFAULT_LUNA_IDS = (
    [(VID_GSG, PID_CYNTHION)]
    + [(VID_PIDCODES, i) for i in range(1, 6)]
    + [(VID_PIDCODES, 0x000F)]
)

# Preference order when several devices are enumerated (gateware first).
_MODE_PRIORITY = {"analyzer": 0, "facedancer": 1, "gateware_stub": 2, "apollo": 3, "unknown": 4}


def _apollo_ids() -> list[tuple[int, int]]:
    try:
        from apollo_fpga import ApolloDebugger

        return [tuple(x) for x in ApolloDebugger.APOLLO_USB_IDS]
    except Exception:
        return list(_DEFAULT_APOLLO_IDS)


def _luna_ids() -> list[tuple[int, int]]:
    try:
        from apollo_fpga import ApolloDebugger

        return [tuple(x) for x in ApolloDebugger.LUNA_USB_IDS]
    except Exception:
        return list(_DEFAULT_LUNA_IDS)


# --------------------------------------------------------------------------
# Hooks (monkeypatchable in tests)
# --------------------------------------------------------------------------
def _get_backend():
    """Return apollo_fpga's shared libusb1 backend (bundled DLL on Windows), or None."""
    try:
        from apollo_fpga import ApolloDebugger

        ApolloDebugger._init_backend()
        return ApolloDebugger.backend
    except Exception:
        return None


def _usb_find_all() -> list:
    """All pyusb devices whose VID/PID is a known Apollo or LUNA/Cynthion id."""
    if usb is None:
        return []
    ids = set(_apollo_ids()) | set(_luna_ids())
    try:
        found = usb.core.find(find_all=True, backend=_get_backend())
        return [d for d in found if (d.idVendor, d.idProduct) in ids]
    except usb.core.NoBackendError:
        return []
    except usb.core.USBError:
        return []


def _apollo_factory(force_offline: bool, device=None):
    from apollo_fpga import ApolloDebugger

    return ApolloDebugger(force_offline=force_offline, device=device)


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------
def _interfaces(dev) -> list[dict]:
    try:
        out = []
        for cfg in dev:
            for intf in cfg:
                out.append(
                    {
                        "number": int(intf.bInterfaceNumber),
                        "alt": int(intf.bAlternateSetting),
                        "cls": int(intf.bInterfaceClass),
                        "subclass": int(intf.bInterfaceSubClass),
                        "protocol": int(intf.bInterfaceProtocol),
                    }
                )
        return out
    except Exception:
        return []


def _norm_interface(i: Any) -> dict:
    """Accept an interface dict, a (cls, subclass, protocol) or a
    (number, cls, subclass, protocol) tuple."""
    if isinstance(i, dict):
        return i
    t = tuple(i)
    if len(t) == 3:
        return {"cls": t[0], "subclass": t[1], "protocol": t[2]}
    if len(t) >= 4:
        return {"number": t[0], "cls": t[1], "subclass": t[2], "protocol": t[3]}
    return {}


def classify(vid: Any, pid: int | None = None, interfaces: Iterable[Any] | None = None) -> str:
    """Map VID/PID + interface descriptors to one of MODES (never 'absent').

    Either ``classify(vid, pid, interfaces)`` or ``classify(pyusb_device)``.
    """
    if pid is None and hasattr(vid, "idVendor"):
        dev = vid
        vid, pid = int(dev.idVendor), int(dev.idProduct)
        if interfaces is None:
            interfaces = _interfaces(dev)
    if (vid, pid) in set(_apollo_ids()) | set(_DEFAULT_APOLLO_IDS):
        return "apollo"
    vendor = [d for d in (_norm_interface(i) for i in (interfaces or [])) if d.get("cls") == 0xFF]
    if any(i.get("subclass") == SUBCLASS_ANALYZER for i in vendor):
        return "analyzer"
    if any(i.get("subclass") == SUBCLASS_MOONDANCER for i in vendor):
        return "facedancer"
    if any(i.get("subclass") == SUBCLASS_STUB for i in vendor):
        return "gateware_stub"
    return "unknown"


def _safe_str(fn) -> str | None:
    try:
        value = fn()
        return None if value is None else str(value)
    except Exception:
        return None


def describe_usb_device(dev) -> dict:
    """JSON-friendly description of a pyusb device (no vendor requests sent)."""
    vid = int(getattr(dev, "idVendor", 0) or 0)
    pid = int(getattr(dev, "idProduct", 0) or 0)
    bcd = int(getattr(dev, "bcdDevice", 0) or 0)
    major, minor = bcd >> 8, bcd & 0xFF
    interfaces = _interfaces(dev)
    info: dict[str, Any] = {
        "vid": f"0x{vid:04x}",
        "pid": f"0x{pid:04x}",
        "vid_int": vid,
        "pid_int": pid,
        "bcd_device": f"0x{bcd:04x}",
        "revision": f"r{major}.{minor}" if major < 0xFE else None,
        "revision_tuple": [major, minor],
        "manufacturer": _safe_str(lambda: dev.manufacturer),
        "product": _safe_str(lambda: dev.product),
        "serial": _safe_str(lambda: dev.serial_number),
        "bus": getattr(dev, "bus", None),
        "address": getattr(dev, "address", None),
        "interfaces": interfaces,
        "mode": classify(vid, pid, interfaces),
    }
    if info["manufacturer"] is None and info["product"] is None and info["serial"] is None:
        info["error"] = (
            "Cannot read USB string descriptors (access denied or driver missing). " + HINT_WINUSB
        )
    return info


def list_devices() -> dict:
    """Non-invasive enumeration of every Apollo / Cynthion gateware device. Never raises."""
    try:
        raw = _usb_find_all()
        devs = []
        for d in raw:
            try:
                devs.append(describe_usb_device(d))
            finally:
                try:
                    usb.util.dispose_resources(d)
                except Exception:
                    pass
        if devs:
            mode = sorted(devs, key=lambda x: _MODE_PRIORITY.get(x["mode"], 9))[0]["mode"]
        else:
            mode = "absent"
        return {"ok": True, "count": len(devs), "mode": mode, "devices": devs}
    except Exception as e:  # pragma: no cover - defensive
        return {"ok": True, "count": 0, "mode": "absent", "devices": [], "warning": str(e)}


def current_mode(serial: str | None = None) -> str:
    """Current mode of the (first / given-serial) Cynthion, see MODES."""
    info = list_devices()
    devs = info["devices"]
    if serial:
        devs = [d for d in devs if d.get("serial") == serial]
    if not devs:
        return "absent"
    return sorted(devs, key=lambda x: _MODE_PRIORITY.get(x["mode"], 9))[0]["mode"]


def wait_for_mode(
    expected: str | Iterable[str],
    timeout_s: float = 10.0,
    poll_s: float = 0.5,
    serial: str | None = None,
) -> str:
    """Poll current_mode() until it is in `expected`. Blocking (worker threads only)."""
    wanted = {expected} if isinstance(expected, str) else set(expected)
    deadline = time.monotonic() + max(0.0, timeout_s)
    while True:
        mode = current_mode(serial)
        if mode in wanted:
            return mode
        if time.monotonic() >= deadline:
            label = "/".join(sorted(wanted))
            raise _TimeoutErr(
                f"The Cynthion did not appear in {label} mode within {timeout_s}s "
                f"(current mode: {mode})",
                HINT_WINUSB,
            )
        time.sleep(poll_s)


# --------------------------------------------------------------------------
# Apollo session
# --------------------------------------------------------------------------
def _find_apollo_by_serial(serial: str):
    from apollo_fpga import ApolloDebugger

    devs = ApolloDebugger._find_all_devices(
        ApolloDebugger.APOLLO_USB_IDS, ApolloDebugger._device_has_apollo_id
    )
    for d in devs:
        if _safe_str(lambda: d.serial_number) == serial:
            return d
    return None


@contextlib.contextmanager
def open_apollo(
    force_offline: bool = True,
    serial: str | None = None,
    check_activity: bool = True,
    lock_timeout: float = 30.0,
) -> Iterator[Any]:
    """Yield a connected apollo_fpga.ApolloDebugger; always closes it afterwards.

    force_offline=True requests a USB handoff from running gateware (this stops it).
    """
    with _lock(lock_timeout), stdout_to_stderr():
        if check_activity:
            ACTIVITY.check_free()
        device = None
        if serial:
            try:
                device = _find_apollo_by_serial(serial)
            except Exception as e:
                raise translate_exception(e) from e
            # If not in Apollo mode yet, let the factory handle the handoff and
            # verify the serial afterwards.
        try:
            dbg = _apollo_factory(force_offline, device)
        except CynthionMCPError:
            raise
        except BaseException as e:
            if isinstance(e, (KeyboardInterrupt, GeneratorExit)):
                raise
            raise translate_exception(e) from e
        try:
            if serial and _safe_str(lambda: dbg.serial_number) != serial:
                raise NoDeviceError(f"Cynthion {serial} not found", HINT_PLUG)
            try:
                yield dbg
            except CynthionMCPError:
                raise
            except Exception as e:
                raise translate_exception(e) from e
        finally:
            try:
                dbg.close()
            except Exception:
                pass


# --------------------------------------------------------------------------
# Info
# --------------------------------------------------------------------------
def platform_name(major: int, minor: int) -> str:
    return f"CynthionPlatformRev{major}D{minor}"


def _err_text(e: BaseException) -> str:
    try:
        if isinstance(e, CynthionMCPError):
            return e.format()
        return translate_exception(e).format()
    except Exception:
        return f"{type(e).__name__}: {e}"


def get_info(
    include_fpga: bool = False,
    include_flash: bool = False,
    force_offline: bool = False,
    serial: str | None = None,
) -> dict:
    """Detailed device information; Apollo is only queried when needed or requested."""
    base = list_devices()
    if base["count"] == 0:
        raise NoDeviceError("No Cynthion detected.", HINT_PLUG)

    mode = base["mode"]
    need_apollo = force_offline or include_fpga or include_flash or mode == "apollo"
    if not need_apollo:
        return {
            "ok": True,
            "mode": mode,
            "devices": base["devices"],
            "note": "Gateware running: Apollo info not read (use force_offline=true to "
            "query Apollo; this stops the gateware).",
        }

    result: dict[str, Any] = {"ok": True, "mode_before": mode, "devices": base["devices"]}
    errors: dict[str, str] = {}

    def grab(key: str, fn) -> None:
        try:
            result[key] = fn()
        except Exception as e:
            result[key] = None
            errors[key] = _err_text(e)

    effective_offline = True if mode != "apollo" else force_offline
    with open_apollo(force_offline=effective_offline, serial=serial) as dbg:
        grab("hardware_name", dbg.get_hardware_name)
        grab("compatibility", dbg.get_compatibility_string)
        grab("revision", lambda: [dbg.major, dbg.minor])
        grab("platform", lambda: platform_name(dbg.major, dbg.minor))
        grab("serial", lambda: dbg.serial_number)
        grab("manufacturer", lambda: dbg.device.manufacturer)
        grab("product", lambda: dbg.device.product)
        grab("firmware_version", dbg.get_firmware_version)
        grab("usb_api_version", dbg.get_usb_api_version_string)

        try:
            result["adc_reading"] = dbg.get_adc_reading()
        except Exception as e:
            result["adc_reading"] = None
            if type(e).__name__ != "USBAPIRequirement":
                errors["adc_reading"] = _err_text(e)

        if include_fpga:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                grab("fpga_type", dbg.get_fpga_type)
            if caught:
                result["jtag_warnings"] = [str(w.message) for w in caught]

        if include_flash:
            try:
                dbg.force_fpga_offline()
                with dbg.jtag as jtag:
                    prog = dbg.create_jtag_programmer(jtag)
                    mfg, full = prog.read_flash_id()
                    uid = prog.read_flash_uid()
                result["flash_manufacturer_id"] = f"0x{mfg:02x}"
                result["flash_id"] = f"0x{full:x}"
                result["flash_uid"] = f"{uid:016x}"
                if mfg == 0xFF:
                    errors["flash"] = "No flash memory detected (ID 0xFF)."
            except Exception as e:
                errors["flash"] = _err_text(e)
            try:
                dbg.soft_reset()
                dbg.allow_fpga_takeover_usb()
                result["gateware_restarted"] = True
            except Exception as e:
                result["gateware_restarted"] = False
                errors["restart"] = _err_text(e)
        elif effective_offline:
            result["note"] = (
                "The FPGA was taken offline; call reconfigure_fpga() to restart the gateware."
            )

    if errors:
        result["errors"] = errors
    return result


# --------------------------------------------------------------------------
# Control
# --------------------------------------------------------------------------
def set_led_pattern(pattern: int) -> dict:
    """Set Apollo's LED pattern (500 = idle, 50 = upload)."""
    if not isinstance(pattern, int) or not 0 <= pattern <= 0xFFFF:
        raise InvalidArgumentError("pattern must be an integer between 0 and 65535.", None)
    with open_apollo(force_offline=True) as dbg:
        dbg.set_led_pattern(pattern)
    return {"ok": True, "pattern": pattern}


def reconfigure(wait: bool = True, timeout_s: float = 10.0) -> dict:
    """Reboot the FPGA from SPI flash and hand the CONTROL port back to the gateware."""
    with open_apollo(force_offline=True) as dbg:
        dbg.soft_reset()
        dbg.allow_fpga_takeover_usb()
    if wait:
        time.sleep(1.0)
        mode = wait_for_mode([m for m in MODES if m != "absent"], timeout_s)
    else:
        mode = current_mode()
    return {"ok": True, "mode": mode}


def force_offline() -> dict:
    """Hold the FPGA unconfigured so Apollo owns JTAG and the CONTROL port."""
    with open_apollo(force_offline=True) as dbg:
        dbg.force_fpga_offline()
    return {"ok": True, "mode": "apollo"}


def jtag_scan() -> dict:
    """Enumerate the JTAG chain (does not change FPGA configuration beyond the handoff)."""
    with open_apollo(force_offline=True) as dbg:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with dbg.jtag as jtag:
                devs = jtag.enumerate()
        out = []
        for d in devs:
            try:
                idcode = f"0x{d.idcode():08x}"
            except Exception:
                idcode = None
            out.append(
                {
                    "idcode": idcode,
                    "description": _safe_str(d.description),
                    "device": getattr(d, "DEVICE", None),
                }
            )
    result: dict[str, Any] = {"ok": True, "devices": out}
    if caught:
        result["warnings"] = [str(w.message) for w in caught]
    if not out:
        result["note"] = "No JTAG device detected (try force_fpga_offline)."
    return result


def _register_op(fn, address: int, value: int | None = None):
    if not isinstance(address, int) or not 0 <= address <= 0xFF:
        raise InvalidArgumentError("address must be an integer between 0 and 255.", None)
    with open_apollo(force_offline=True) as dbg:
        try:
            with dbg.jtag:
                res = fn(dbg)
        except OSError as e:
            if "autonegotiate" in str(e):
                raise UnsupportedError(
                    "The running gateware does not expose a JTAG register interface", None
                ) from e
            raise
        finally:
            try:
                dbg.allow_fpga_takeover_usb()
            except Exception:
                pass
    return res


def register_read(address: int) -> dict:
    """Read a gateware debug register over JTAG (e.g. selftest gateware)."""
    value = _register_op(lambda dbg: dbg.registers.register_read(address), address)
    value = int(value)
    return {"ok": True, "address": address, "value": value, "value_hex": f"0x{value:08x}"}


def register_write(address: int, value: int) -> dict:
    """Write a gateware debug register over JTAG."""
    if not isinstance(value, int) or value < 0 or value > 0xFFFFFFFF:
        raise InvalidArgumentError("value must be an unsigned 32-bit integer.", None)
    _register_op(lambda dbg: dbg.registers.register_write(address, value), address)
    return {"ok": True, "address": address, "value": value}


__all__ = [
    "list_devices",
    "current_mode",
    "wait_for_mode",
    "open_apollo",
    "get_info",
    "set_led_pattern",
    "reconfigure",
    "force_offline",
    "jtag_scan",
    "register_read",
    "register_write",
    "platform_name",
    "classify",
    "describe_usb_device",
    "VID_GSG",
    "PID_APOLLO",
    "PID_CYNTHION",
    "VID_PIDCODES",
    "PID_APOLLO_ALT",
    "SUBCLASS_STUB",
    "SUBCLASS_ANALYZER",
    "SUBCLASS_MOONDANCER",
    "LED_PATTERN_IDLE",
    "LED_PATTERN_UPLOAD",
    "MODES",
    "HINT_WINUSB",
    "HINT_PLUG",
]
