"""Gateware (FPGA bitstream), SPI flash, Apollo MCU firmware and selftest management.

Every hardware call here mirrors what the installed ``cynthion`` 0.2.5 CLI
(``cynthion/commands/util.py``) and ``apollo_fpga`` 1.1.1 CLI do, but:

* bundled assets are resolved without ``sys.exit`` (the cynthion helpers exit),
* stdout is kept clean (``ECP5_JTAGProgrammer.read_flash`` prints every page,
  the selftest framework prints with prompt_toolkit, fwup/tqdm print progress),
* errors are raised as :class:`cynthion_mcp.common.CynthionMCPError` subclasses.

All public functions are synchronous and blocking: the server runs them through
``common.run_blocking``. Heavy third-party packages are imported lazily.
"""

from __future__ import annotations

import inspect
import logging
import re
import time
from pathlib import Path
from typing import Any, Optional

from . import common as _common
from .common import (
    CynthionMCPError,
    HardwareError,
    InvalidArgumentError,
    ProgressFn,
    UnsupportedError,
    capture_stdout,
    noop_progress,
    require_confirm,
    resolve_input_file,
    resolve_output_file,
    sha256_hex,
    stdout_to_stderr,
)
from .device import current_mode, open_apollo, platform_name, wait_for_mode

log = logging.getLogger("cynthion_mcp.gateware")

__all__ = [
    "TARGETS",
    "SOC_FIRMWARE_FLASHADDR",
    "FLASH_SIZE",
    "TARGET_MODE",
    "assets_dir",
    "list_bundled_assets",
    "bitstream_path",
    "soc_firmware_path",
    "apollo_firmware_path",
    "run_gateware",
    "configure_bitstream",
    "flash_gateware",
    "flash_file",
    "read_flash",
    "erase_flash",
    "flash_info",
    "update_apollo_firmware",
    "run_selftest",
]

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

TARGETS = ("analyzer", "facedancer", "selftest")

try:  # cynthion/commands/util.py: SOC_FIRMWARE_FLASHADDR = 0x000b0000
    from cynthion.commands.util import SOC_FIRMWARE_FLASHADDR  # type: ignore
except Exception:  # pragma: no cover - broken/missing cynthion install
    SOC_FIRMWARE_FLASHADDR = 0x000B0000

FLASH_SIZE = 4 * 1024 * 1024  # apollo CLI flash-read default (4 MiB)
FLASH_PAGE_SIZE = 256  # ECP5CommandBasedProgrammer.SPI_FLASH_PAGE_SIZE

# Mode device.current_mode() reports once each target gateware is running.
# The selftest gateware has no USB function: Apollo stays enumerated.
TARGET_MODE = {"analyzer": "analyzer", "facedancer": "facedancer", "selftest": "apollo"}

APOLLO_VID, APOLLO_PID = 0x1D50, 0x615C  # cynthion.shared.usb bVendorId/bProductId.apollo

_PLATFORM_RE = re.compile(r"^CynthionPlatformRev(\d+)D(\d+)$")

_FACEDANCER_HINT = (
    "The facedancer gateware needs the moondancer.bin SoC firmware in SPI flash "
    f"(offset 0x{SOC_FIRMWARE_FLASHADDR:06x}): rerun run_gateware(target='facedancer', "
    "update_soc_firmware=true). On Windows, also check the WinUSB driver."
)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def _timestamp_slug() -> str:
    fn = getattr(_common, "timestamp_slug", None)
    if callable(fn):
        try:
            return fn()
        except Exception:
            pass
    return time.strftime("%Y%m%d_%H%M%S")


def _check_hw_free() -> None:
    """Refuse FPGA handoff/reconfiguration while a capture or emulation owns the USB device."""
    activity = getattr(_common, "ACTIVITY", None)
    if activity is not None and hasattr(activity, "check_free"):
        activity.check_free()


def _hw_lock():
    lock = getattr(_common, "HW_LOCK", None)
    if lock is None:
        import contextlib
        return contextlib.nullcontext()
    return lock


def _validate_target(target: str) -> str:
    if target not in TARGETS:
        raise InvalidArgumentError(
            f"Unknown target: {target!r}. Valid values: {', '.join(TARGETS)}."
        )
    return target


def _file_entry(p: Path) -> Optional[dict]:
    if p.is_file():
        return {"path": str(p), "size": p.stat().st_size}
    return None


def _wait_any_mode(timeout_s: float) -> str:
    """Poll until some Cynthion mode other than 'absent' is visible (or timeout)."""
    deadline = time.monotonic() + max(0.0, timeout_s)
    mode = "absent"
    while True:
        try:
            mode = current_mode()
        except Exception:  # transient enumeration errors during re-enumeration
            mode = "absent"
        if mode != "absent" or time.monotonic() >= deadline:
            return mode
        time.sleep(0.25)


# --------------------------------------------------------------------------
# Assets (no hardware needed)
# --------------------------------------------------------------------------

def assets_dir() -> Path:
    """Directory holding the bitstreams/firmware shipped in the cynthion wheel."""
    try:
        import cynthion
    except Exception as exc:
        raise UnsupportedError(
            f"cynthion package unavailable: {exc}",
            "Install it: pip install cynthion",
        ) from exc
    return Path(cynthion.cynthion_assets_directory())


def list_bundled_assets() -> dict[str, Any]:
    """List apollo.bin, moondancer.bin and the per-revision bitstreams. Never touches hardware."""
    root = assets_dir()
    platforms: dict[str, Any] = {}
    if root.is_dir():
        for d in sorted(root.iterdir()):
            m = _PLATFORM_RE.match(d.name)
            if not (m and d.is_dir()):
                continue
            bitstreams = {}
            for target in TARGETS:
                entry = _file_entry(d / f"{target}.bit")
                if entry:
                    bitstreams[target] = entry
            platforms[d.name] = {
                "revision": f"r{int(m.group(1))}.{int(m.group(2))}",
                "bitstreams": bitstreams,
            }
    return {
        "ok": True,
        "assets_dir": str(root),
        "apollo_firmware": _file_entry(root / "apollo.bin"),
        "soc_firmware": _file_entry(root / "moondancer.bin"),
        "soc_firmware_flash_offset": f"0x{SOC_FIRMWARE_FLASHADDR:06x}",
        "platforms": platforms,
    }


def bitstream_path(target: str, major: int, minor: int) -> Path:
    """Bundled bitstream for ``target`` on hardware revision r{major}.{minor}."""
    _validate_target(target)
    p = assets_dir() / platform_name(major, minor) / f"{target}.bit"
    if not p.is_file():
        raise UnsupportedError(
            f"No bundled {target} bitstream for revision r{major}.{minor}",
            "Update the cynthion package or use configure_bitstream(path=...).",
        )
    return p


def soc_firmware_path() -> Path:
    p = assets_dir() / "moondancer.bin"
    if not p.is_file():
        raise UnsupportedError(
            "SoC firmware moondancer.bin not found in the cynthion assets",
            "Reinstall the cynthion package (pip install --force-reinstall cynthion).",
        )
    return p


def apollo_firmware_path() -> Path:
    p = assets_dir() / "apollo.bin"
    if not p.is_file():
        raise UnsupportedError(
            "Apollo firmware apollo.bin not found in the cynthion assets",
            "Reinstall the cynthion package or pass path=... to an apollo.bin.",
        )
    return p


# --------------------------------------------------------------------------
# Internal primitives (take an open ApolloDebugger; call inside open_apollo)
# --------------------------------------------------------------------------

def _configure(dbg, data: bytes) -> None:
    """Volatile SRAM configuration (= cynthion util.run_bitstream)."""
    with stdout_to_stderr():
        with dbg.jtag as jtag:
            dbg.create_jtag_programmer(jtag).configure(data)
        # let the gateware take over the shared CONTROL USB port
        dbg.allow_fpga_takeover_usb()


def _flash(dbg, data: bytes, offset: int) -> None:
    """Write ``data`` to SPI flash at ``offset`` (= util.flash_bitstream / flash_soc_firmware, no reset)."""
    if offset < 0 or offset % FLASH_PAGE_SIZE:
        raise InvalidArgumentError(
            f"Offset 0x{offset:x} must be a multiple of {FLASH_PAGE_SIZE} bytes."
        )
    if not data:
        raise InvalidArgumentError("Empty data: nothing to write to flash.")
    if offset + len(data) > FLASH_SIZE:
        raise InvalidArgumentError(
            f"Write past end of flash: offset 0x{offset:x} + {len(data)} bytes > {FLASH_SIZE} bytes."
        )
    with stdout_to_stderr():
        dbg.force_fpga_offline()
        with dbg.jtag as jtag:
            dbg.create_jtag_programmer(jtag).flash(data, offset=offset)


def _reboot(dbg) -> None:
    """FPGA reloads its gateware from SPI flash, then may take over USB."""
    dbg.soft_reset()
    dbg.allow_fpga_takeover_usb()


def _clear_cynthion_cache() -> None:
    """Drop cynthion.Cynthion()'s cached board objects (stale after a gateware change)."""
    try:
        import cynthion.cynthion as cc

        for board in list(cc.active_connections.values()):
            try:
                board.close()
            except Exception:
                pass
        cc.active_connections.clear()
    except Exception:
        pass


# --------------------------------------------------------------------------
# Public operations
# --------------------------------------------------------------------------

def run_gateware(
    target: str,
    update_soc_firmware: bool = True,
    wait: bool = True,
    timeout_s: float = 15.0,
    serial: Optional[str] = None,
    progress: ProgressFn = noop_progress,
) -> dict[str, Any]:
    """Load a bundled gateware into FPGA SRAM (volatile), like ``cynthion run <target>``."""
    _validate_target(target)
    _check_hw_free()
    t0 = time.monotonic()
    soc = False
    with open_apollo(force_offline=True, serial=serial) as dbg:
        rev = (dbg.major, dbg.minor)
        bit = bitstream_path(target, *rev)
        progress(0, 3, "Handoff Apollo OK")
        if target == "facedancer" and update_soc_firmware:
            _flash(dbg, soc_firmware_path().read_bytes(), SOC_FIRMWARE_FLASHADDR)
            soc = True
            progress(1, 3, "SoC firmware moondancer.bin written to flash")
        else:
            progress(1, 3, "Loading bitstream")
        _configure(dbg, bit.read_bytes())
        progress(2, 3, "Bitstream loaded")
    _clear_cynthion_cache()

    mode = None
    if wait:
        time.sleep(1.0)
        try:
            mode = wait_for_mode(TARGET_MODE[target], timeout_s)
        except CynthionMCPError as err:
            if target == "facedancer" and not getattr(err, "hint", None):
                err.hint = _FACEDANCER_HINT
            elif target == "facedancer":
                err.hint = f"{err.hint} {_FACEDANCER_HINT}"
            raise
    progress(3, 3, "Done")
    return {
        "ok": True,
        "target": target,
        "bitstream": str(bit),
        "revision": f"r{rev[0]}.{rev[1]}",
        "soc_firmware_flashed": soc,
        "mode": mode,
        "elapsed_s": round(time.monotonic() - t0, 2),
        "volatile": True,
        "note": "SRAM configuration: lost at power-off; reconfigure_fpga() reloads from flash.",
    }


def configure_bitstream(path: str, wait: bool = False, timeout_s: float = 10.0,
                        serial: Optional[str] = None) -> dict[str, Any]:
    """Load an arbitrary .bit file into FPGA SRAM (volatile), like ``apollo configure``."""
    src = resolve_input_file(path, max_size=FLASH_SIZE)
    data = src.read_bytes()
    _check_hw_free()
    with open_apollo(force_offline=True, serial=serial) as dbg:
        _configure(dbg, data)
    _clear_cynthion_cache()
    mode = None
    if wait:
        time.sleep(0.5)
        mode = _wait_any_mode(timeout_s)
    return {"ok": True, "path": str(src), "size": len(data), "sha256": sha256_hex(data), "mode": mode}


def flash_gateware(target: str, confirm: bool = False, serial: Optional[str] = None,
                   progress: ProgressFn = noop_progress) -> dict[str, Any]:
    """Persistently write a bundled gateware to SPI flash, like ``cynthion flash <target>``."""
    _validate_target(target)
    require_confirm(confirm, f"write the {target} gateware to SPI flash (persistent)")
    _check_hw_free()
    soc = False
    with open_apollo(force_offline=True, serial=serial) as dbg:
        rev = (dbg.major, dbg.minor)
        bit = bitstream_path(target, *rev)
        data = bit.read_bytes()
        progress(0, 3, "Handoff Apollo OK")
        if target == "facedancer":
            _flash(dbg, soc_firmware_path().read_bytes(), SOC_FIRMWARE_FLASHADDR)
            soc = True
        progress(1, 3, "Writing bitstream to flash")
        _flash(dbg, data, 0)
        progress(2, 3, "Rebooting the FPGA from flash")
        _reboot(dbg)
    _clear_cynthion_cache()

    mode = None
    warning = None
    time.sleep(1.0)
    try:
        mode = wait_for_mode(TARGET_MODE[target], 15)
    except CynthionMCPError as err:
        warning = f"Flash written but the expected mode did not appear: {err.format() if hasattr(err, 'format') else err}"
        log.warning(warning)
    progress(3, 3, "Done")
    out = {
        "ok": True,
        "target": target,
        "bitstream": str(bit),
        "revision": f"r{rev[0]}.{rev[1]}",
        "written": len(data),
        "sha256": sha256_hex(data),
        "soc_firmware_flashed": soc,
        "mode": mode,
    }
    if warning:
        out["warning"] = warning
    return out


def flash_file(path: str, offset: int = 0, confirm: bool = False, reboot: bool = True,
               serial: Optional[str] = None, progress: ProgressFn = noop_progress) -> dict[str, Any]:
    """Write any file to SPI flash at ``offset`` (multiple of 256), like ``apollo flash-program``."""
    src = resolve_input_file(path, max_size=FLASH_SIZE)
    data = src.read_bytes()
    require_confirm(
        confirm,
        f"write {len(data)} bytes of {src.name} to SPI flash at offset 0x{offset:x} (persistent)",
    )
    _check_hw_free()
    with open_apollo(force_offline=True, serial=serial) as dbg:
        progress(0, 2, "Writing to flash")
        # apollo CLI ensure_unconfigured(): clear FPGA SRAM before programming flash
        with stdout_to_stderr():
            dbg.force_fpga_offline()
            with dbg.jtag as jtag:
                dbg.create_jtag_programmer(jtag).unconfigure()
        _flash(dbg, data, offset)
        progress(1, 2, "Write complete")
        if reboot:
            _reboot(dbg)
    _clear_cynthion_cache()
    progress(2, 2, "Done")
    return {"ok": True, "path": str(src), "offset": offset, "size": len(data),
            "sha256": sha256_hex(data), "rebooted": bool(reboot)}


def read_flash(output_path: str, length: Optional[int] = None, offset: int = 0,
               serial: Optional[str] = None, progress: ProgressFn = noop_progress) -> dict[str, Any]:
    """Dump SPI flash to a file, like ``apollo flash-read``. The FPGA is rebooted from flash afterwards."""
    if offset < 0 or offset % FLASH_PAGE_SIZE:
        raise InvalidArgumentError(
            f"Offset 0x{offset:x} must be a multiple of {FLASH_PAGE_SIZE} bytes."
        )
    if length is None:
        length = FLASH_SIZE - offset
    if not (0 < length <= FLASH_SIZE - offset):
        raise InvalidArgumentError(
            f"Invalid length: {length} (max {FLASH_SIZE - offset} bytes from 0x{offset:x})."
        )
    out = resolve_output_file(output_path, f"cynthion_flash_{_timestamp_slug()}.bin")
    _check_hw_free()
    with open_apollo(force_offline=True, serial=serial) as dbg:
        progress(0, 2, f"Reading {length} bytes")
        try:
            dbg.force_fpga_offline()
            # ECP5_JTAGProgrammer.read_flash() print()s every page: capture it.
            with dbg.jtag as jtag, capture_stdout():
                data = dbg.create_jtag_programmer(jtag).read_flash(length, offset=offset)
        finally:
            try:
                _reboot(dbg)
            except Exception as exc:  # do not mask the read error
                log.warning("Reboot after flash read failed: %s", exc)
    _clear_cynthion_cache()
    data = bytes(data)
    out.write_bytes(data)
    progress(2, 2, "Done")
    return {"ok": True, "path": str(out), "offset": offset, "length": len(data), "sha256": sha256_hex(data)}


def erase_flash(confirm: bool = False, serial: Optional[str] = None) -> dict[str, Any]:
    """Chip-erase the whole SPI flash, like ``apollo flash-erase``."""
    require_confirm(
        confirm,
        "erase the ENTIRE SPI flash (gateware + SoC firmware); the Cynthion will have no gateware at boot",
    )
    _check_hw_free()
    with open_apollo(force_offline=True, serial=serial) as dbg:
        with stdout_to_stderr():
            dbg.force_fpga_offline()
            with dbg.jtag as jtag:
                programmer = dbg.create_jtag_programmer(jtag)
                programmer.unconfigure()
                programmer.erase_flash()
    _clear_cynthion_cache()
    return {"ok": True, "note": "Use flash_gateware('analyzer', confirm=true) to restore."}


def flash_info(serial: Optional[str] = None) -> dict[str, Any]:
    """JEDEC ID and 64-bit unique ID of the SPI configuration flash, like ``apollo flash-info``."""
    _check_hw_free()
    try:
        from apollo_fpga.commands.cli import JEDEC_MANUFACTURERS, JEDEC_PARTS  # dict[int, str]
    except Exception:
        JEDEC_MANUFACTURERS, JEDEC_PARTS = {}, {}

    with open_apollo(force_offline=True, serial=serial) as dbg:
        try:
            with stdout_to_stderr():
                dbg.force_fpga_offline()
                with dbg.jtag as jtag:
                    programmer = dbg.create_jtag_programmer(jtag)
                    mfg, full = programmer.read_flash_id()
                    uid = programmer.read_flash_uid()
        finally:
            try:
                _reboot(dbg)
            except Exception as exc:
                log.warning("Reboot after flash-info failed: %s", exc)
    _clear_cynthion_cache()
    if mfg == 0xFF:
        raise HardwareError("SPI flash not detected", "Check the board; try force_fpga_offline, then retry.")
    return {
        "ok": True,
        "manufacturer_id": f"0x{mfg:02x}",
        "manufacturer": JEDEC_MANUFACTURERS.get(mfg),
        "part_id": f"0x{full:06x}",
        "part": JEDEC_PARTS.get(full),
        "uid_hex": f"{uid:016x}",
    }


def update_apollo_firmware(path: Optional[str] = None, confirm: bool = False,
                           serial: Optional[str] = None,
                           progress: ProgressFn = noop_progress) -> dict[str, Any]:
    """Reflash the Apollo debug MCU over DFU (= cynthion util.flash_mcu_firmware)."""
    require_confirm(confirm, "reflash the Apollo microcontroller over DFU")
    src = resolve_input_file(path) if path else apollo_firmware_path()
    fw = src.read_bytes()
    if not fw:
        raise InvalidArgumentError("Empty firmware.")
    _check_hw_free()

    with stdout_to_stderr():
        with open_apollo(force_offline=True, serial=serial) as dbg:
            major, minor = dbg.major, dbg.minor
            if major == 0 and minor < 6:
                raise UnsupportedError("MCU update not supported for r0.x < r0.6")
            # Release the Apollo debugger before DFU takes the device (open_apollo tolerates a double close).
            dbg.close()

            import usb.util  # noqa: F401  (pyusb, used by fwup)
            from fwup.dfu import DFUTarget

            kwargs: dict[str, Any] = {"idVendor": APOLLO_VID, "idProduct": APOLLO_PID}
            try:  # reuse apollo_fpga's bundled libusb backend (needed on Windows)
                from apollo_fpga import ApolloDebugger

                ApolloDebugger._init_backend()
                if getattr(ApolloDebugger, "backend", None) is not None:
                    kwargs["backend"] = ApolloDebugger.backend
            except Exception:
                pass

            try:
                board = DFUTarget(**kwargs)  # sends DFU_DETACH and waits for the DFU-mode re-enumeration
            except Exception as exc:
                raise HardwareError(
                    f"Apollo DFU target not found: {exc}",
                    "On Windows, Apollo's DFU mode also needs the WinUSB driver (Zadig).",
                ) from exc
            total = board.size_to_program(fw)
            progress(0, total, "DFU")
            board.program(fw, status_callback=lambda written, _total: progress(written, total, "DFU"))
            board.run_user_program()
            progress(total, total, "Done")

    return {"ok": True, "path": str(src), "size": len(fw), "sha256": sha256_hex(fw)}


def run_selftest(restore_after: bool = True, serial: Optional[str] = None,
                 progress: ProgressFn = noop_progress) -> dict[str, Any]:
    """Load the selftest gateware and run cynthion's StandaloneTester checks (PHYs, HyperRAM, debug module)."""
    _check_hw_free()
    with open_apollo(force_offline=True, serial=serial) as dbg:
        rev = (dbg.major, dbg.minor)
        _configure(dbg, bitstream_path("selftest", *rev).read_bytes())
    _clear_cynthion_cache()
    progress(1, 7, "Selftest bitstream loaded")
    time.sleep(1.0)  # the selftest gateware has no USB function: Apollo stays enumerated

    from cynthion.selftest.host import StandaloneTester

    results: list[dict[str, Any]] = []
    restored = False
    output = ""
    with _hw_lock(), capture_stdout() as buf:
        # No force_offline here: forcing the FPGA offline would kill the gateware under test.
        with open_apollo(force_offline=False, serial=serial) as dut:
            tester = StandaloneTester(dut)
            tester.dut = dut
            tests = [
                m for attr, m in inspect.getmembers(tester, inspect.ismethod) if attr.startswith("test_")
            ]
            try:
                with dut.jtag:
                    for i, method in enumerate(tests):
                        name = method.__name__  # @named_test sets readable names
                        try:
                            method(dut)  # ApolloSelfTestCase._run_as_test_case calls method(dut)
                            results.append({"name": name, "status": "pass", "detail": None})
                        except AssertionError as exc:
                            results.append({"name": name, "status": "fail", "detail": str(exc)})
                        except Exception as exc:
                            results.append({"name": name, "status": "error", "detail": repr(exc)})
                        progress(2 + i, 2 + len(tests), name)
            finally:
                if restore_after:
                    try:
                        _reboot(dut)
                        restored = True
                    except Exception as exc:
                        log.warning("Restoring flash gateware after selftest failed: %s", exc)
        output = buf.getvalue() if hasattr(buf, "getvalue") else ""
    _clear_cynthion_cache()

    passed = sum(r["status"] == "pass" for r in results)
    failed = sum(r["status"] == "fail" for r in results)
    errors = sum(r["status"] == "error" for r in results)
    return {
        "ok": True,
        "revision": f"r{rev[0]}.{rev[1]}",
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "all_passed": bool(results) and failed == 0 and errors == 0,
        "results": results,
        "restored": restored,
        "output": output[-4000:],
    }
