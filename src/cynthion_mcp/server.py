"""FastMCP server exposing a Great Scott Gadgets Cynthion (LUNA / Apollo) to an LLM.

Transport: stdio by default (``python -m cynthion_mcp``), optionally streamable-http.

Design rules (see package README):
  * every tool is ``async``; blocking USB / JTAG work runs in a worker thread via
    ``common.run_blocking`` so the MCP event loop is never blocked;
  * every failure is translated by ``common.translate_exception`` and surfaced as a
    ``ToolError("[CODE] message ...")`` (isError=True for the client);
  * stdout is reserved for JSON-RPC: ``main()`` redirects ``sys.stdout`` to stderr and
    hands the real stdout to the MCP stdio transport.
"""

import functools
import importlib.metadata
import inspect
import json
import logging
import math
import os
import platform
import sys
import threading
import time
from contextlib import asynccontextmanager
from typing import Annotated, Any, Literal

# Allow ``python path/to/server.py`` (no package context) as well as ``-m cynthion_mcp``.
if not __package__:  # pragma: no cover - only for direct script execution
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import anyio
import anyio.to_thread
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import Field

from cynthion_mcp import (
    __version__,
    analyzer,
    board_io,
    common,
    device,
    facedancer_runner,
    gateware,
    gateware_build,
    usbclass,
    usbdecode,
)

# ---------------------------------------------------------------------------
# Annotation presets
# ---------------------------------------------------------------------------

RO = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
MUT = ToolAnnotations(readOnlyHint=False, destructiveHint=False, openWorldHint=False)
DES = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=False)

GatewareTarget = Literal["analyzer", "facedancer", "selftest"]
CaptureSpeed = Literal["auto", "high", "full", "low"]
ClassLayer = Literal["control", "hid", "cdc", "msc", "serial", "raw"]

INSTRUCTIONS = """\
Cynthion MCP server: drives a Great Scott Gadgets Cynthion (ECP5 FPGA + Apollo debug MCU, LUNA gateware).

DEVICE MODES (see server_status / list_devices, field "mode"):
- "absent": no Cynthion visible on USB. Call the diagnose_connection prompt, check the CONTROL port cable and the WinUSB driver.
- "apollo": only the Apollo debugger (1d50:615c) is enumerated; FPGA unconfigured or running USB-less gateware (selftest).
- "analyzer": USB analyzer gateware is running (1d50:615b, interface subclass 0x10). Use the analyzer_* tools.
- "facedancer": Moondancer/Facedancer gateware + SoC firmware is running (1d50:615b, subclass 0x20). Use facedancer_* and board I/O tools.
- "gateware_stub": custom gateware exposing only the Apollo stub interface.

RULES:
- Only ONE owner of the USB device at a time. A running analyzer capture or Facedancer emulation blocks every tool that
  hands off to Apollo, reconfigures or reflashes the FPGA ([BUSY] error). Stop it first (analyzer_stop / facedancer_stop).
- Apollo/JTAG tools (device_info with force_offline, jtag_*, flash_*, configure_bitstream, run_gateware) stop the running
  gateware. reconfigure_fpga reboots the gateware stored in SPI flash (the analyzer by default).
- run_gateware / configure_bitstream are volatile (SRAM, lost at power-off). flash_gateware / flash_file / erase_flash /
  update_apollo_firmware are PERSISTENT and DESTRUCTIVE: they require confirm=true and you MUST ask the human first.
- Analyzer workflow: analyzer_start -> analyzer_status / analyzer_read / analyzer_transactions (poll) -> analyzer_stop
  -> analyzer_summary / analyzer_export_pcap. analyzer_capture does a bounded start/wait/stop in one call.
  Capture plugs: TARGET-C = host side, TARGET-A = device under test, CONTROL = your PC.
- After a capture, analyzer_decode_classes decodes the buffer at class level (standard requests and descriptors, HID
  reports/keys, CDC-ACM, mass-storage SCSI, CH34x/FTDI/CP210x serial data). A capture started mid-session misses the
  enumeration: pass hints keyed by device address, e.g. {"8": "ch340"} or {"5": {"vid": 6790, "pid": 29987}}.
- Facedancer workflow: facedancer_start(kind=...) -> facedancer_command / facedancer_type_text / facedancer_serial_write
  -> facedancer_events / facedancer_logs -> facedancer_stop. The emulated device appears on the TARGET-C port.
- Board I/O tools (board_info, led_set, gpio_list, gpio_read, gpio_write, board_debug_log) REQUIRE facedancer mode
  (Moondancer firmware). In any other mode they fail with [WRONG_MODE]: switch with run_gateware(target='facedancer').
- Custom gateware workflow: gateware_toolchain_status (yosys / nextpnr-ecp5 / ecppack available?) -> build_gateware
  (Amaranth .py design -> .bit; never touches the board, may take minutes) -> configure_bitstream(path=<bitstream>)
  to load it into FPGA SRAM. build_gateware(elaborate_only=true) checks a design without the toolchain.
- Errors start with a code in brackets: [NO_DEVICE], [WRONG_MODE], [BUSY], [INVALID_ARGUMENT], [CONFIRMATION_REQUIRED],
  [DRIVER], [HARDWARE], [UNSUPPORTED], [TIMEOUT], [BUILD_FAILED] (design or toolchain error: read the log tail).
- If no device is detected, use the diagnose_connection prompt.
"""

log = logging.getLogger("cynthion_mcp.server")


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(server: FastMCP):
    common.setup_logging(os.environ.get("CYNTHION_MCP_LOG_LEVEL", "INFO"))
    log.info("cynthion-mcp %s started (no hardware access at startup)", __version__)
    try:
        yield {}
    finally:
        with anyio.CancelScope(shield=True):
            for fn in (analyzer.CAPTURE.shutdown, facedancer_runner.RUNNER.shutdown):
                try:
                    await common.run_blocking(fn)
                except BaseException as exc:  # noqa: BLE001 - best effort on shutdown
                    log.warning("shutdown %s: %r", getattr(fn, "__qualname__", fn), exc)


mcp = FastMCP("cynthion", instructions=INSTRUCTIONS, lifespan=lifespan)


# ---------------------------------------------------------------------------
# Bridging helpers
# ---------------------------------------------------------------------------


def _to_tool_error(exc: BaseException) -> ToolError:
    err = common.translate_exception(exc)
    text = err.format()
    common.logger.warning(text)
    return ToolError(text)


def _guard(fn):
    """Decorator: turn any non-cancellation exception raised in a tool body into a formatted ToolError."""

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        try:
            return await fn(*args, **kwargs)
        except (anyio.get_cancelled_exc_class(), KeyboardInterrupt, ToolError):
            raise
        except BaseException as exc:  # noqa: BLE001 - includes SystemExit from library helpers
            raise _to_tool_error(exc) from exc

    return wrapper


def _make_progress_fn(ctx: Context):
    """Build a thread-safe progress callback (called from worker threads) forwarding to ctx.report_progress."""

    def pfn(progress: float, total: float | None = None, message: str | None = None) -> None:
        try:
            anyio.from_thread.run(ctx.report_progress, float(progress), total, message)
        except Exception:  # noqa: BLE001 - progress is best effort (no token, closed loop...)
            pass

    return pfn


def _accepts_kw(fn, name: str) -> bool:
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False
    return name in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())


async def _hw(fn, *args, ctx: Context | None = None, progress: bool = False, **kw):
    """Run a blocking hardware function in a worker thread; translate errors into ToolError."""
    if progress and ctx is not None and _accepts_kw(fn, "progress"):
        kw["progress"] = _make_progress_fn(ctx)
    try:
        return await common.run_blocking(fn, *args, **kw)
    except (anyio.get_cancelled_exc_class(), KeyboardInterrupt):
        raise
    except BaseException as exc:  # noqa: BLE001
        raise _to_tool_error(exc) from exc


async def _soft(fn, *args, **kw):
    """Same as _hw without progress; used for pure / non-hardware functions."""
    try:
        return await common.run_blocking(fn, *args, **kw)
    except (anyio.get_cancelled_exc_class(), KeyboardInterrupt):
        raise
    except BaseException as exc:  # noqa: BLE001
        raise _to_tool_error(exc) from exc


async def _report(ctx: Context | None, progress: float, total: float | None = None, message: str | None = None) -> None:
    if ctx is None:
        return
    try:
        await ctx.report_progress(progress, total, message)
    except Exception:  # noqa: BLE001 - no request context (direct call) or no progress token
        pass


def _ok(d: Any) -> dict[str, Any]:
    if isinstance(d, dict):
        out = dict(d)
        out.setdefault("ok", True)
        return out
    return {"ok": True, "result": d}


# ---------------------------------------------------------------------------
# Status implementation (never raises for missing hardware)
# ---------------------------------------------------------------------------

_PACKAGES = {
    "cynthion": "cynthion",
    "apollo_fpga": "apollo-fpga",
    "facedancer": "facedancer",
    "luna": "luna-usb",
    "mcp": "mcp",
    "pyusb": "pyusb",
}


def _status_impl() -> dict[str, Any]:
    packages: dict[str, str | None] = {}
    for key, dist in _PACKAGES.items():
        try:
            packages[key] = importlib.metadata.version(dist)
        except Exception:  # noqa: BLE001
            packages[key] = None

    result: dict[str, Any] = {
        "ok": True,
        "server_version": __version__,
        "packages": packages,
        "platform": f"{platform.system()} {platform.release()} / Python {platform.python_version()}",
        "mode": "absent",
        "devices": [],
    }
    try:
        devs = device.list_devices()
        result["mode"] = devs.get("mode", "absent")
        result["devices"] = devs.get("devices", [])
    except BaseException as exc:  # noqa: BLE001
        result["mode"] = "unknown"
        result["devices_error"] = common.translate_exception(exc).format()
    try:
        result["capture"] = analyzer.CAPTURE.status()
    except BaseException as exc:  # noqa: BLE001
        result["capture"] = {"error": common.translate_exception(exc).format()}
    try:
        result["facedancer"] = facedancer_runner.RUNNER.status()
    except BaseException as exc:  # noqa: BLE001
        result["facedancer"] = {"error": common.translate_exception(exc).format()}
    return result


# ===========================================================================
# A. General / discovery
# ===========================================================================


@mcp.tool(annotations=RO)
@_guard
async def server_status() -> dict[str, Any]:
    """Overall server state: package versions, platform, detected Cynthion mode and devices, analyzer capture
    status and Facedancer emulation status. Never fails when no hardware is connected."""
    return await _soft(_status_impl)


@mcp.tool(annotations=RO)
@_guard
async def list_devices() -> dict[str, Any]:
    """Non-invasively enumerate Cynthion-related USB devices (Apollo 1d50:615c, gateware 1d50:615b...) with
    their mode, strings, revision and interfaces. Does not touch the FPGA."""
    return _ok(await _soft(device.list_devices))


@mcp.tool(annotations=MUT)
@_guard
async def device_info(
    include_fpga: Annotated[bool, Field(description="Also identify the FPGA over JTAG (e.g. LFE5U-12F).")] = False,
    include_flash: Annotated[bool, Field(description="Also read SPI flash JEDEC ID and unique ID (takes the FPGA offline).")] = False,
    force_offline: Annotated[bool, Field(description="Hand the CONTROL port back to Apollo if gateware owns it (stops the running gateware).")] = False,
    serial: Annotated[str | None, Field(description="Select a board by Apollo serial number when several are connected.")] = None,
) -> dict[str, Any]:
    """Detailed Apollo/Cynthion info: hardware name and revision, serial, firmware and USB API versions, ADC.
    force_offline / include_flash / include_fpga may stop the running gateware (use reconfigure_fpga to restore)."""
    if force_offline or include_flash or include_fpga:
        common.ACTIVITY.check_free()
    return _ok(
        await _hw(
            device.get_info,
            include_fpga=include_fpga,
            include_flash=include_flash,
            force_offline=force_offline,
            serial=serial,
        )
    )


@mcp.tool(annotations=RO)
@_guard
async def list_bundled_assets() -> dict[str, Any]:
    """List the gateware bitstreams (per board revision) and firmware images bundled with the installed
    cynthion package. No hardware needed."""
    return _ok(await _soft(gateware.list_bundled_assets))


@mcp.tool(annotations=RO)
@_guard
async def get_logs(
    lines: Annotated[int, Field(description="Number of most recent log lines to return.", ge=1, le=2000)] = 200,
    level: Annotated[
        Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL", "debug", "info", "warning", "error", "critical"],
        Field(description="Minimum log level."),
    ] = "INFO",
) -> dict[str, Any]:
    """Return recent server and library log lines (cynthion_mcp, apollo_fpga, facedancer, cynthion)."""
    lvl = logging.getLevelName(level.upper())
    if not isinstance(lvl, int):
        lvl = logging.INFO
    return {"ok": True, "lines": list(common.LOG_RING.get(lines, lvl))}


# ===========================================================================
# B. Apollo / FPGA control
# ===========================================================================


@mcp.tool(annotations=MUT)
@_guard
async def set_led_pattern(
    pattern: Annotated[int, Field(description="Apollo LED pattern number (500 = idle, 50 = upload).", ge=0, le=65535)],
) -> dict[str, Any]:
    """Set the Apollo debug-MCU LED pattern. Requires Apollo to own the CONTROL port (hands off from gateware)."""
    common.ACTIVITY.check_free()
    return _ok(await _hw(device.set_led_pattern, pattern))


@mcp.tool(annotations=MUT)
@_guard
async def reconfigure_fpga(
    wait: Annotated[bool, Field(description="Wait for the device to re-enumerate and report the new mode.")] = True,
) -> dict[str, Any]:
    """Reboot the FPGA from SPI flash (soft reset + allow gateware USB takeover). Restores the flashed gateware
    (analyzer by default) and stops whatever was running."""
    common.ACTIVITY.check_free()
    return _ok(await _hw(device.reconfigure, wait=wait))


@mcp.tool(annotations=MUT)
@_guard
async def force_fpga_offline() -> dict[str, Any]:
    """Hold the FPGA offline so Apollo owns JTAG and the CONTROL USB port. Stops the running gateware."""
    common.ACTIVITY.check_free()
    return _ok(await _hw(device.force_offline))


@mcp.tool(annotations=MUT)
@_guard
async def jtag_scan() -> dict[str, Any]:
    """Enumerate the JTAG chain through Apollo and return IDCODEs (0x21111043 = LFE5U-12F). Needs Apollo
    to own the port: if gateware is running it is handed off (its USB disappears; use reconfigure_fpga or
    run_gateware to get it back). Does not alter the FPGA configuration or flash."""
    common.ACTIVITY.check_free()
    return _ok(await _hw(device.jtag_scan))


@mcp.tool(annotations=MUT)
@_guard
async def jtag_register_read(
    address: Annotated[int, Field(description="Debug register address (gateware-defined).", ge=0, le=255)],
) -> dict[str, Any]:
    """Read a gateware debug register over the JTAG/SPI register bridge (only for gateware that exposes one,
    e.g. selftest). May hand off from gateware."""
    common.ACTIVITY.check_free()
    return _ok(await _hw(device.register_read, address))


@mcp.tool(annotations=MUT)
@_guard
async def jtag_register_write(
    address: Annotated[int, Field(description="Debug register address (gateware-defined).", ge=0, le=255)],
    value: Annotated[int, Field(description="32-bit value to write.", ge=0, le=0xFFFFFFFF)],
) -> dict[str, Any]:
    """Write a gateware debug register over the JTAG register bridge (e.g. selftest register 2 = LEDs)."""
    common.ACTIVITY.check_free()
    return _ok(await _hw(device.register_write, address, value))


# ===========================================================================
# C. Gateware / flash
# ===========================================================================


@mcp.tool(annotations=MUT)
@_guard
async def run_gateware(
    ctx: Context,
    target: Annotated[GatewareTarget, Field(description="Bundled gateware to load into FPGA SRAM.")],
    update_soc_firmware: Annotated[
        bool, Field(description="facedancer only: write moondancer.bin to SPI flash at 0xB0000 first (required once).")
    ] = True,
    wait: Annotated[bool, Field(description="Wait for USB re-enumeration in the new mode.")] = True,
    timeout_s: Annotated[float, Field(description="Re-enumeration timeout in seconds.", ge=1, le=120)] = 15,
) -> dict[str, Any]:
    """Load a bundled gateware (analyzer, facedancer or selftest) matching the board revision into FPGA SRAM.
    Volatile (lost on power cycle); stops the running gateware. facedancer may also write SoC firmware to flash."""
    common.ACTIVITY.check_free()
    return _ok(
        await _hw(
            gateware.run_gateware,
            target,
            update_soc_firmware=update_soc_firmware,
            wait=wait,
            timeout_s=timeout_s,
            ctx=ctx,
            progress=True,
        )
    )


@mcp.tool(annotations=MUT)
@_guard
async def configure_bitstream(
    ctx: Context,
    path: Annotated[str, Field(description="Path to an ECP5 .bit file on this machine.")],
    wait: Annotated[bool, Field(description="Wait for USB re-enumeration afterwards.")] = False,
) -> dict[str, Any]:
    """Load an arbitrary bitstream file into FPGA SRAM over JTAG (volatile). Stops the running gateware."""
    common.ACTIVITY.check_free()
    return _ok(await _hw(gateware.configure_bitstream, path, wait=wait, ctx=ctx, progress=True))


@mcp.tool(annotations=DES)
@_guard
async def flash_gateware(
    ctx: Context,
    target: Annotated[GatewareTarget, Field(description="Bundled gateware to write persistently to SPI flash.")],
    confirm: Annotated[bool, Field(description="Must be true; ask the user before setting it.")] = False,
) -> dict[str, Any]:
    """PERSISTENT: write a bundled gateware to SPI flash so it boots at power-on (facedancer also writes the SoC
    firmware). Requires confirm=true after asking the user. Reboots the FPGA afterwards."""
    if confirm:
        common.ACTIVITY.check_free()
    return _ok(await _hw(gateware.flash_gateware, target, confirm=confirm, ctx=ctx, progress=True))


@mcp.tool(annotations=DES)
@_guard
async def flash_file(
    ctx: Context,
    path: Annotated[str, Field(description="File to write to SPI flash (bitstream or firmware image).")],
    offset: Annotated[int, Field(description="Flash byte offset, multiple of 256 (0 = bitstream, 0xB0000 = SoC firmware).", ge=0, le=0xFFFFFF)] = 0,
    confirm: Annotated[bool, Field(description="Must be true; ask the user before setting it.")] = False,
    reboot: Annotated[bool, Field(description="Soft-reset the FPGA afterwards so it boots the new image.")] = True,
) -> dict[str, Any]:
    """PERSISTENT: write a file to the SPI flash at the given offset. Overwrites existing content; requires
    confirm=true after asking the user."""
    if confirm:
        common.ACTIVITY.check_free()
    return _ok(
        await _hw(gateware.flash_file, path, offset=offset, confirm=confirm, reboot=reboot, ctx=ctx, progress=True)
    )


@mcp.tool(annotations=MUT)
@_guard
async def read_flash(
    ctx: Context,
    output_path: Annotated[str, Field(description="Where to save the dump on this machine.")],
    length: Annotated[int | None, Field(description="Bytes to read (default: up to 4 MiB minus offset).", ge=1, le=0x1000000)] = None,
    offset: Annotated[int, Field(description="Start offset, multiple of 256.", ge=0, le=0xFFFFFF)] = 0,
) -> dict[str, Any]:
    """Dump SPI flash content to a file. Stops the running gateware; the FPGA is rebooted from flash afterwards."""
    common.ACTIVITY.check_free()
    return _ok(await _hw(gateware.read_flash, output_path, length=length, offset=offset, ctx=ctx, progress=True))


@mcp.tool(annotations=DES)
@_guard
async def erase_flash(
    ctx: Context,
    confirm: Annotated[bool, Field(description="Must be true; ask the user before setting it.")] = False,
) -> dict[str, Any]:
    """PERSISTENT and DESTRUCTIVE: erase the whole SPI flash (gateware and SoC firmware). The FPGA will boot
    unconfigured until reflashed. Requires confirm=true after asking the user."""
    if confirm:
        common.ACTIVITY.check_free()
    return _ok(await _hw(gateware.erase_flash, confirm=confirm, ctx=ctx, progress=True))


@mcp.tool(annotations=MUT)
@_guard
async def flash_info() -> dict[str, Any]:
    """Read the SPI flash JEDEC manufacturer/part and 64-bit unique ID over JTAG. Takes the FPGA offline
    (use reconfigure_fpga to restore the gateware)."""
    common.ACTIVITY.check_free()
    return _ok(await _hw(gateware.flash_info))


@mcp.tool(annotations=DES)
@_guard
async def update_apollo_firmware(
    ctx: Context,
    path: Annotated[str | None, Field(description="Apollo firmware .bin (default: bundled apollo.bin).")] = None,
    confirm: Annotated[bool, Field(description="Must be true; ask the user before setting it.")] = False,
) -> dict[str, Any]:
    """PERSISTENT: update the Apollo debug MCU firmware over DFU. Do not unplug during the update. Requires
    confirm=true after asking the user."""
    if confirm:
        common.ACTIVITY.check_free()
    return _ok(await _hw(gateware.update_apollo_firmware, path, confirm=confirm, ctx=ctx, progress=True))


@mcp.tool(annotations=MUT)
@_guard
async def run_selftest(
    ctx: Context,
    restore_after: Annotated[bool, Field(description="Reboot the flashed gateware once tests are done.")] = True,
) -> dict[str, Any]:
    """Load the selftest gateware and run the hardware self-tests (debug module, PHYs, HyperRAM).
    Stops the running gateware."""
    common.ACTIVITY.check_free()
    return _ok(await _hw(gateware.run_selftest, restore_after=restore_after, ctx=ctx, progress=True))


# ===========================================================================
# D. USB analyzer
# ===========================================================================


@mcp.tool(annotations=RO)
@_guard
async def analyzer_info() -> dict[str, Any]:
    """Query the analyzer gateware: protocol version, supported speeds, decoded state register, serial.
    Requires analyzer mode (run_gateware target=analyzer)."""
    return _ok(await _hw(analyzer.CAPTURE.info))


async def _ensure_analyzer(ctx: Context | None) -> None:
    mode = await _hw(device.current_mode)
    if mode == "analyzer":
        return
    if mode == "absent":
        raise common.NoDeviceError(
            "No Cynthion detected: neither the analyzer gateware (1d50:615b) nor Apollo (1d50:615c) is present.",
            hint="Plug in the Cynthion CONTROL port; on Windows, check the WinUSB driver.",
        )
    if facedancer_runner.RUNNER.is_running():
        raise common.BusyError(
            "A Facedancer emulation is running; cannot load the analyzer gateware.",
            hint="Call facedancer_stop first.",
        )
    await _report(ctx, 0, None, "Loading the analyzer gateware")
    await _hw(gateware.run_gateware, "analyzer", ctx=ctx, progress=True)


def _capture_config(
    speed: str,
    buffer_packets: int,
    duration_s: float | None,
    include_sof_in_buffer: bool,
    vbus_from_target_c: bool | None,
    vbus_from_control_host: bool | None,
    vbus_from_aux: bool | None,
    discharge_target_a: bool | None,
):
    return analyzer.CaptureConfig(
        speed=speed,
        buffer_packets=buffer_packets,
        duration_s=duration_s,
        include_sof_in_buffer=include_sof_in_buffer,
        vbus_from_target_c=vbus_from_target_c,
        vbus_from_control_host=vbus_from_control_host,
        vbus_from_aux=vbus_from_aux,
        discharge_target_a=discharge_target_a,
    )


@mcp.tool(annotations=MUT)
@_guard
async def analyzer_start(
    ctx: Context,
    speed: Annotated[CaptureSpeed, Field(description="Bus speed to capture; auto detects it (r0.6+ boards).")] = "auto",
    auto_load_gateware: Annotated[bool, Field(description="Load the analyzer gateware first if another mode is active.")] = True,
    buffer_packets: Annotated[int, Field(description="Ring buffer size in records.", ge=1000, le=5_000_000)] = 200_000,
    duration_s: Annotated[float | None, Field(description="Auto-stop after this many seconds (None = run until analyzer_stop).", ge=0.1, le=3600)] = None,
    include_sof_in_buffer: Annotated[bool, Field(description="Keep SOF packets in the buffer (high volume at FS/HS).")] = True,
    vbus_from_target_c: Annotated[bool | None, Field(description="Power control: feed VBUS from TARGET-C (None = default pass-through).")] = None,
    vbus_from_control_host: Annotated[bool | None, Field(description="Power control: feed VBUS from the CONTROL host.")] = None,
    vbus_from_aux: Annotated[bool | None, Field(description="Power control: feed VBUS from the AUX port.")] = None,
    discharge_target_a: Annotated[bool | None, Field(description="Power control: discharge TARGET-A VBUS.")] = None,
    include_linestate: Annotated[bool, Field(description="Keep LINESTATE_* bus events in the buffer (very verbose: ~8 per packet). Counted in status either way.")] = False,
) -> dict[str, Any]:
    """Start a background USB capture between TARGET-C (host) and TARGET-A (device). Loads the analyzer gateware
    if needed (stops other gateware). Poll with analyzer_status/analyzer_read, end with analyzer_stop."""
    if auto_load_gateware:
        await _ensure_analyzer(ctx)
    cfg = _capture_config(
        speed, buffer_packets, duration_s, include_sof_in_buffer,
        vbus_from_target_c, vbus_from_control_host, vbus_from_aux, discharge_target_a,
    )
    cfg.include_linestate = include_linestate
    status = await _hw(analyzer.CAPTURE.start, cfg)
    return {"ok": True, "status": status}


@mcp.tool(annotations=MUT)
@_guard
async def analyzer_stop() -> dict[str, Any]:
    """Stop the running capture, drain the remaining data and keep the buffer for reading/export."""
    return {"ok": True, "status": await _hw(analyzer.CAPTURE.stop)}


@mcp.tool(annotations=RO)
@_guard
async def analyzer_status() -> dict[str, Any]:
    """Capture status: running flag, speed, packet/event/byte counters, buffer usage, errors."""
    return _ok(await _soft(analyzer.CAPTURE.status))


@mcp.tool(annotations=RO)
@_guard
async def analyzer_read(
    start_seq: Annotated[int | None, Field(description="First record sequence number (None = oldest available).", ge=0)] = None,
    limit: Annotated[int, Field(description="Maximum records to return.", ge=1, le=2000)] = 100,
    kinds: Annotated[list[Literal["packet", "event"]] | None, Field(description="Record kinds to include (default both).")] = None,
    pids: Annotated[list[str] | None, Field(description="Only these PIDs, e.g. ['SETUP','DATA0','IN'].")] = None,
    address: Annotated[int | None, Field(description="Only tokens/transactions for this device address.", ge=0, le=127)] = None,
    endpoint: Annotated[int | None, Field(description="Only this endpoint number.", ge=0, le=15)] = None,
    include_sof: Annotated[bool, Field(description="Include SOF packets.")] = False,
    include_nak: Annotated[bool, Field(description="Include NAK handshakes.")] = True,
    only_errors: Annotated[bool, Field(description="Only records with invalid PID or bad CRC.")] = False,
    raw: Annotated[bool, Field(description="Include raw packet bytes as hex.")] = False,
) -> dict[str, Any]:
    """Read decoded capture records (packets with PID/address/endpoint/data/CRC check, and bus events) from the
    buffer. Use next_seq for incremental polling. Works during and after a capture."""
    flt = usbdecode.RecordFilter(
        kinds=set(kinds) if kinds else None,
        pids={p.upper() for p in pids} if pids else None,
        address=address,
        endpoint=endpoint,
        include_sof=include_sof,
        include_nak=include_nak,
        only_errors=only_errors,
    )
    return _ok(await _soft(analyzer.CAPTURE.read, start_seq=start_seq, limit=limit, flt=flt, raw=raw))


@mcp.tool(annotations=RO)
@_guard
async def analyzer_transactions(
    start_seq: Annotated[int | None, Field(description="First packet sequence number (None = oldest).", ge=0)] = None,
    limit: Annotated[int, Field(description="Maximum transactions to return.", ge=1, le=2000)] = 100,
    address: Annotated[int | None, Field(description="Only this device address.", ge=0, le=127)] = None,
    endpoint: Annotated[int | None, Field(description="Only this endpoint number.", ge=0, le=15)] = None,
    include_sof: Annotated[bool, Field(description="Include SOF packets.")] = False,
    include_nak: Annotated[bool, Field(description="Include NAKed transactions.")] = False,
    decode_setup: Annotated[bool, Field(description="Decode SETUP data as standard control requests.")] = True,
) -> dict[str, Any]:
    """Group captured packets into transactions (token + data + handshake), decoding SETUP requests."""
    return _ok(
        await _soft(
            analyzer.CAPTURE.transactions,
            start_seq=start_seq,
            limit=limit,
            address=address,
            endpoint=endpoint,
            include_sof=include_sof,
            include_nak=include_nak,
            decode_setup=decode_setup,
        )
    )


@mcp.tool(annotations=RO)
@_guard
async def analyzer_summary() -> dict[str, Any]:
    """Statistics of the buffered capture: packets per PID, devices/endpoints seen with byte counts, events,
    detected speed, duration and CRC errors."""
    return _ok(await _soft(analyzer.CAPTURE.summary))


@mcp.tool(annotations=MUT)
@_guard
async def analyzer_export_pcap(
    path: Annotated[str | None, Field(description="Output .pcap path (default: cynthion_capture_<timestamp>.pcap).")] = None,
    nanosecond: Annotated[bool, Field(description="Use nanosecond timestamps.")] = True,
    include_sof: Annotated[bool, Field(description="Include SOF packets.")] = True,
) -> dict[str, Any]:
    """Write the buffered capture to a pcap file (LINKTYPE_USB_2_0 = 288, opens in Wireshark/Packetry).
    Also available as resource cynthion://capture/last.pcap."""
    res = _ok(await _soft(analyzer.CAPTURE.export_pcap, path=path, nanosecond=nanosecond, include_sof=include_sof))
    res.setdefault("linktype", 288)
    res.setdefault("resource_uri", "cynthion://capture/last.pcap")
    return res


@mcp.tool(annotations=MUT)
@_guard
async def analyzer_clear() -> dict[str, Any]:
    """Discard the buffered capture. Refused while a capture is running."""
    await _soft(analyzer.CAPTURE.clear)
    return {"ok": True}


@mcp.tool(annotations=MUT)
@_guard
async def analyzer_capture(
    ctx: Context,
    seconds: Annotated[float, Field(description="Capture duration in seconds.", ge=0.1, le=120)],
    speed: Annotated[CaptureSpeed, Field(description="Bus speed to capture.")] = "auto",
    auto_load_gateware: Annotated[bool, Field(description="Load the analyzer gateware first if needed.")] = True,
    export_pcap_path: Annotated[str | None, Field(description="If set, also export the capture to this pcap path.")] = None,
) -> dict[str, Any]:
    """Bounded one-shot capture: start, wait `seconds` (with progress), stop, and return status + summary
    (optionally exporting a pcap). Loads the analyzer gateware if needed."""
    if auto_load_gateware:
        await _ensure_analyzer(ctx)
    cfg = _capture_config(speed, 200_000, None, True, None, None, None, None)
    await _hw(analyzer.CAPTURE.start, cfg)
    stopped = False
    try:
        t0 = time.monotonic()
        for _ in range(max(1, math.ceil(seconds / 0.5))):
            remaining = seconds - (time.monotonic() - t0)
            if remaining <= 0:
                break
            await anyio.sleep(min(0.5, remaining))
            elapsed = min(seconds, time.monotonic() - t0)
            try:
                st = analyzer.CAPTURE.status()
                packets = st.get("packets", st.get("packet_count", 0)) if isinstance(st, dict) else 0
            except Exception:  # noqa: BLE001
                packets = 0
            await _report(ctx, elapsed, seconds, f"{packets} packets")
        with anyio.CancelScope(shield=True):
            status = await _hw(analyzer.CAPTURE.stop)
        stopped = True
    finally:
        if not stopped:
            with anyio.CancelScope(shield=True):
                try:
                    await common.run_blocking(analyzer.CAPTURE.stop)
                except BaseException as exc:  # noqa: BLE001
                    log.warning("analyzer_capture: stop after failure: %r", exc)
    summary = await _soft(analyzer.CAPTURE.summary)
    result: dict[str, Any] = {"ok": True, "status": status, "summary": summary}
    n_packets = summary.get("packets", 0) if isinstance(summary, dict) else 0
    if not n_packets:
        result["warning"] = (
            "No USB packets seen on the target bus. Check the wiring: the host (PC) must be plugged into "
            "TARGET-C and the device under test into TARGET-A (by default VBUS passes from TARGET-C to TARGET-A; "
            "without a host on TARGET-C the device is neither powered nor enumerated). Unplug/replug the device "
            "during the capture to see the enumeration."
        )
        if export_pcap_path:
            result["pcap"] = {"ok": False, "skipped": "empty capture, pcap not written"}
        return result
    if export_pcap_path:
        result["pcap"] = await _soft(analyzer.CAPTURE.export_pcap, path=export_pcap_path, nanosecond=True, include_sof=True)
    return result


@mcp.tool(annotations=MUT)
@_guard
async def analyzer_test_device(
    connect: Annotated[bool, Field(description="Connect (true) or disconnect the built-in test device on AUX.")] = True,
    speed: Annotated[Literal["high", "full", "low"], Field(description="Speed of the test device.")] = "high",
) -> dict[str, Any]:
    """Control the analyzer's built-in USB test device on the AUX port (1209:000a, r0.6+). Useful to verify a
    capture by wiring AUX to TARGET-A."""
    return _ok(await _hw(analyzer.CAPTURE.test_device, connect=connect, speed=speed))


def _decode_classes_impl(
    start_seq: int | None,
    limit: int,
    address: int | None,
    endpoint: int | None,
    layers: list[str] | None,
    hints: dict[str, Any] | None,
) -> dict[str, Any]:
    """Class-level decode of the WHOLE buffer (the decoder is stateful: descriptors seen early drive the
    interpretation of later traffic), then filter and paginate the resulting items."""
    records = analyzer.CAPTURE.snapshot(None)
    txns = usbdecode.group_transactions(
        records, include_sof=False, include_nak=False, decode_setup_packets=True, include_events=True,
    )
    try:
        decoded = usbclass.decode_transactions(txns, hints)
    except ValueError as exc:
        raise common.InvalidArgumentError(
            f"invalid hints: {exc}",
            hint='Example: {"8": "ch340"}, {"5": {"vid": 6790, "pid": 29987}} or {"5": {"2": "cdc"}}.',
        ) from exc
    wanted = set(layers) if layers else None
    result_note: str | None = None
    matching = [
        it for it in decoded["items"]
        if (start_seq is None or (it.get("seq") is not None and it["seq"] >= start_seq))
        and (address is None or it.get("addr") == address)
        and (endpoint is None or it.get("ep") == endpoint)
        and (wanted is None or it.get("layer") in wanted)
    ]
    items = matching[:limit]
    truncated = len(matching) > limit
    if truncated:
        next_seq = matching[limit].get("seq")
    elif records:
        next_seq = records[-1].seq + 1
        # While capturing, items still open at the end of the buffer (control transfer without status
        # stage, MSC data without CSW, serial run inside the merge window) are reported in partial form
        # under the seq of their FIRST transaction. Resume at that seq so the next page returns them
        # completed instead of filtering them out (the partial item is then reported again, updated).
        pending = decoded.get("pending_start_seq")
        if pending is not None and pending < next_seq and analyzer.CAPTURE.is_running():
            next_seq = max(pending, start_seq or 0)
            result_note = "Items starting at next_seq were still open; the next page repeats them, updated."
    else:
        next_seq = start_seq
    result: dict[str, Any] = {
        "ok": True,
        "count": len(items),
        "total_matching": len(matching),
        "truncated": truncated,
        "next_seq": next_seq,
        "items": items,
        "devices": decoded["devices"],
    }
    if result_note:
        result["note"] = result_note
    if not records:
        result["note"] = "Capture buffer is empty: run analyzer_capture (or analyzer_start then analyzer_stop) first."
    return result


@mcp.tool(annotations=RO)
@_guard
async def analyzer_decode_classes(
    start_seq: Annotated[int | None, Field(description="Only items starting at or after this record sequence number (None = all). Use next_seq to page.", ge=0)] = None,
    limit: Annotated[int, Field(description="Maximum items to return.", ge=1, le=2000)] = 200,
    address: Annotated[int | None, Field(description="Only this device address.", ge=0, le=127)] = None,
    endpoint: Annotated[int | None, Field(description="Only this endpoint number.", ge=0, le=15)] = None,
    layers: Annotated[list[ClassLayer] | None, Field(description="Only these layers (default all): control, hid, cdc, msc, serial, raw.")] = None,
    hints: Annotated[
        dict[str, Any] | None,
        Field(description=(
            "Class hints keyed by device address, for captures that missed the enumeration. Values: a driver name "
            "('cdc', 'serial', 'ch340'/'ch34x', 'ftdi', 'cp210x', 'hid', 'keyboard', 'mouse', 'msc', 'raw'), "
            "{'vid': ..., 'pid': ...}, {'driver': ...}, or per endpoint {'2': 'cdc', '0x81': 'keyboard'}."
        )),
    ] = None,
) -> dict[str, Any]:
    """Decode the captured traffic at USB class level: standard control requests and descriptors (device model per
    address), HID reports (keys, mouse), CDC-ACM line coding / serial state, mass-storage CBW/SCSI/CSW, and serial
    data of CDC-ACM / CH34x / FTDI / CP210x adapters. Always decodes the whole buffer, then filters and pages
    (next_seq). Works during and after a capture; no hardware access. During a capture, next_seq points at the
    first item still open (e.g. a control transfer waiting for its status stage), so that item is returned again,
    completed, by the next page."""
    return await _soft(_decode_classes_impl, start_seq, limit, address, endpoint, layers, hints)


def _decode_hex_packet(hex_bytes: str) -> dict[str, Any]:
    data = common.parse_hex_bytes(hex_bytes)
    res = dict(usbdecode.decode_packet(data))
    # DATA0 with exactly 8 payload bytes (PID + 8 + CRC16) looks like a SETUP data stage.
    if len(data) == 11 and (data[0] & 0x0F) == 0x3:
        try:
            res["setup"] = usbdecode.decode_setup(bytes(data[1:9]))
        except Exception as exc:  # noqa: BLE001
            res["setup_error"] = str(exc)
    res.setdefault("ok", True)
    return res


@mcp.tool(annotations=RO)
@_guard
async def decode_usb_packet(
    hex_bytes: Annotated[str, Field(description="Raw USB packet as hex (PID first, CRC included), e.g. '2d0010'.")],
) -> dict[str, Any]:
    """Decode one raw USB 2.0 packet: PID, address/endpoint/frame, payload, CRC5/CRC16 check, and SETUP
    request decoding for 8-byte DATA0 payloads. No hardware needed."""
    return await _soft(_decode_hex_packet, hex_bytes)


# ===========================================================================
# E. Facedancer (Moondancer)
# ===========================================================================


@mcp.tool(annotations=RO)
@_guard
async def facedancer_list_device_kinds() -> dict[str, Any]:
    """Describe the device kinds facedancer_start can emulate (keyboard, ftdi, mass_storage, proxy, script),
    their parameters and supported commands."""
    return {
        "ok": True,
        "kinds": facedancer_runner.KIND_SPECS,
        "common_commands": getattr(facedancer_runner, "COMMON_COMMANDS", []),
    }


@mcp.tool(annotations=MUT)
@_guard
async def facedancer_start(
    ctx: Context,
    kind: Annotated[
        Literal["keyboard", "ftdi", "mass_storage", "proxy", "script"],
        Field(description="Device to emulate on the TARGET-C port."),
    ],
    params: Annotated[dict[str, Any] | None, Field(description="Kind-specific parameters (see facedancer_list_device_kinds).")] = None,
    script_path: Annotated[str | None, Field(description="kind=script: Python file defining the USBDevice to emulate.")] = None,
    auto_load_gateware: Annotated[bool, Field(description="Load the facedancer gateware (and SoC firmware) first if needed.")] = True,
    ready_timeout_s: Annotated[float, Field(description="Seconds to wait for the emulation to be connected.", ge=1, le=120)] = 15,
) -> dict[str, Any]:
    """Start emulating a USB device with Facedancer in a background worker process. Loads the facedancer gateware
    if needed (stops other gateware, writes SoC firmware to flash). Stop with facedancer_stop."""
    if facedancer_runner.RUNNER.is_running():
        raise common.BusyError(
            "A Facedancer emulation is already running.", hint="Call facedancer_stop before starting another one."
        )
    mode = await _hw(device.current_mode)
    if mode == "absent":
        raise common.NoDeviceError(
            "No Cynthion detected.",
            hint="Plug in the Cynthion CONTROL port; on Windows, check the WinUSB driver.",
        )
    if auto_load_gateware and mode != "facedancer":
        common.ACTIVITY.check_free()
        await _report(ctx, 0, None, "Loading the Facedancer gateware")
        await _hw(gateware.run_gateware, "facedancer", update_soc_firmware=True, ctx=ctx, progress=True)
    status = await _hw(facedancer_runner.RUNNER.start, kind, params or {}, script_path, ready_timeout_s)
    return {"ok": True, "status": status}


@mcp.tool(annotations=MUT)
@_guard
async def facedancer_command(
    command: Annotated[str, Field(description="Command name supported by the running kind (see facedancer_list_device_kinds).")],
    args: Annotated[dict[str, Any] | None, Field(description="Command arguments.")] = None,
    timeout_s: Annotated[float, Field(description="Reply timeout in seconds.", ge=0.1, le=600)] = 30,
) -> dict[str, Any]:
    """Send a command to the running emulated device (e.g. key_down, type_string, serial_write, status) and
    return its result."""
    return _ok(await _hw(facedancer_runner.RUNNER.send_command, command, args or {}, timeout_s))


@mcp.tool(annotations=MUT)
@_guard
async def facedancer_type_text(
    text: Annotated[str, Field(description="Text to type on the target host through the emulated keyboard.")],
    duration: Annotated[float, Field(description="Key press duration in seconds.", ge=0.001, le=2)] = 0.05,
) -> dict[str, Any]:
    """Type text on the target host with the emulated keyboard (kind=keyboard must be running)."""
    timeout = max(30.0, len(text) * duration * 3 + 10)
    return _ok(
        await _hw(facedancer_runner.RUNNER.send_command, "type_string", {"text": text, "duration": duration}, timeout)
    )


@mcp.tool(annotations=MUT)
@_guard
async def facedancer_serial_write(
    data: Annotated[str, Field(description="Data to send to the host through the emulated FTDI serial port.")],
    hex: Annotated[bool, Field(description="Interpret data as hex bytes.")] = False,
) -> dict[str, Any]:
    """Send data from the emulated FTDI serial adapter to the target host (kind=ftdi must be running)."""
    reply = await _hw(facedancer_runner.RUNNER.send_command, "serial_write", {"data": data, "is_hex": hex}, 30)
    out = _ok(reply)
    value = out.get("result")
    if isinstance(value, dict) and "bytes" in value:
        out["bytes"] = value["bytes"]
    elif isinstance(value, int):
        out["bytes"] = value
    return out


@mcp.tool(annotations=RO)
@_guard
async def facedancer_status() -> dict[str, Any]:
    """Status of the Facedancer worker: running, kind, connected, pid, uptime, exit code, last error."""
    return _ok(await _soft(facedancer_runner.RUNNER.status))


@mcp.tool(annotations=RO)
@_guard
async def facedancer_logs(
    lines: Annotated[int, Field(description="Maximum lines to return.", ge=1, le=2000)] = 100,
    since_seq: Annotated[int | None, Field(description="Only lines after this sequence number.", ge=0)] = None,
) -> dict[str, Any]:
    """Log output of the Facedancer worker process (facedancer library logs, stdout/stderr)."""
    return _ok(await _soft(facedancer_runner.RUNNER.logs, lines, since_seq))


@mcp.tool(annotations=RO)
@_guard
async def facedancer_events(
    since_seq: Annotated[int | None, Field(description="Only events after this sequence number.", ge=0)] = None,
    limit: Annotated[int, Field(description="Maximum events to return.", ge=1, le=5000)] = 200,
    types: Annotated[list[str] | None, Field(description="Only these events. Matches the event type (data, host_event, connected, ready, error, stopped), a host_event name (bus_reset, configured, set_address), a data source (e.g. ftdi, proxy, script) or the emulation kind (keyboard, ftdi...).")] = None,
) -> dict[str, Any]:
    """Events emitted by the emulation: type 'data' (received / proxied data, field 'source'), 'host_event' (field 'name': bus_reset, configured, set_address), connected, error, stopped."""
    return _ok(await _soft(facedancer_runner.RUNNER.events, since_seq, limit, types))


@mcp.tool(annotations=MUT)
@_guard
async def facedancer_stop(
    timeout_s: Annotated[float, Field(description="Seconds to wait for a clean shutdown before killing.", ge=0.5, le=60)] = 5,
) -> dict[str, Any]:
    """Stop the emulation (disconnects the emulated device) and report unhandled control requests."""
    return _ok(await _hw(facedancer_runner.RUNNER.stop, timeout_s))


# ===========================================================================
# F. Board I/O (Moondancer firmware)
# ===========================================================================


_BOARD_SWITCH_HINT = "switch with run_gateware(target='facedancer')"


async def _require_facedancer_mode() -> None:
    """Board I/O talks to the Moondancer firmware: refuse early with an explicit [WRONG_MODE] in any other mode."""
    mode = await _hw(device.current_mode)
    if mode in ("facedancer", "unknown"):
        return  # "unknown": let the real open report the precise driver / permission problem
    if mode == "absent":
        raise common.NoDeviceError(
            "No Cynthion detected; the board tools (LED, GPIO, board_info) require facedancer mode.",
            hint=common.HINT_FACEDANCER,
        )
    raise common.WrongModeError(
        "The board tools (board_info, led_set, gpio_*, board_debug_log) require facedancer mode "
        f"(Moondancer firmware); current mode: {mode!r} -> {_BOARD_SWITCH_HINT}.",
        hint="First stop any running capture (analyzer_stop), then run_gateware(target='facedancer').",
    )


async def _board(op: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    runner = facedancer_runner.RUNNER
    forward = runner.board_op if runner.is_running() else None
    if forward is None:
        await _require_facedancer_mode()
    return _ok(await _hw(board_io.run_board_op, {"op": op, **(args or {})}, forward=forward))


@mcp.tool(annotations=RO)
@_guard
async def board_info() -> dict[str, Any]:
    """Moondancer board info (name, firmware version, serial, part id, libgreat APIs). Requires facedancer mode."""
    return await _board("info")


@mcp.tool(annotations=MUT)
@_guard
async def led_set(
    index: Annotated[int, Field(description="FPGA user LED index.", ge=0, le=5)],
    state: Annotated[Literal["on", "off", "toggle"], Field(description="New LED state.")],
) -> dict[str, Any]:
    """Drive one of the 6 FPGA LEDs through the Moondancer firmware. Requires facedancer mode."""
    return await _board("led", {"index": index, "state": state})


@mcp.tool(annotations=RO)
@_guard
async def gpio_list() -> dict[str, Any]:
    """List the GPIO pins available through Moondancer (PMOD A pins A1-A4, A7-A10 and USER button).
    Requires facedancer mode."""
    return await _board("gpio_list")


@mcp.tool(annotations=MUT)
@_guard
async def gpio_read(
    pin: Annotated[str, Field(description="Pin name, e.g. 'A1' or 'USER' (user button).")],
) -> dict[str, Any]:
    """Configure a pin as input and read it. 'USER' reads the user button. Requires facedancer mode."""
    return await _board("gpio_read", {"pin": pin})


@mcp.tool(annotations=MUT)
@_guard
async def gpio_write(
    pin: Annotated[str, Field(description="Pin name, e.g. 'A1'.")],
    value: Annotated[bool, Field(description="Output level.")],
) -> dict[str, Any]:
    """Configure a pin as push-pull output and drive it high or low. Requires facedancer mode."""
    return await _board("gpio_write", {"pin": pin, "value": value})


@mcp.tool(annotations=RO)
@_guard
async def board_debug_log(
    max_length: Annotated[int, Field(description="Maximum characters to read.", ge=1, le=65536)] = 4096,
    clear: Annotated[bool, Field(description="Clear the firmware debug ring after reading.")] = False,
) -> dict[str, Any]:
    """Read the Moondancer firmware debug ring buffer (dmesg). Requires facedancer mode."""
    return await _board("debug_ring", {"max_length": max_length, "clear": clear})


# ===========================================================================
# G. Custom gateware build (no hardware access)
# ===========================================================================


@mcp.tool(annotations=RO)
@_guard
async def gateware_toolchain_status(
    probe_versions: Annotated[bool, Field(description="Run '<tool> --version' on native tools (slower).")] = True,
) -> dict[str, Any]:
    """Check the open-source ECP5 toolchain used by build_gateware (yosys, nextpnr-ecp5, ecppack): native installs
    (env overrides, PATH, OSS CAD Suite) or YoWASP packages. Never touches the board."""
    return _ok(await _soft(gateware_build.toolchain_status, probe_versions=probe_versions))


@mcp.tool(annotations=MUT)
@_guard
async def build_gateware(
    ctx: Context,
    source: Annotated[str, Field(description="Path to a Python (.py) file defining an Amaranth design.")],
    top: Annotated[str | None, Field(description="Top-level attribute (class, instance or zero-arg factory). Default: auto-detect top/Top/create_top() or the single Elaboratable.")] = None,
    platform_revision: Annotated[str | None, Field(description="Cynthion hardware revision, e.g. 'r1.4' (default r1.4).")] = None,
    output_dir: Annotated[str | None, Field(description="Build directory (default: a timestamped folder in the server output directory).")] = None,
    timeout_s: Annotated[float, Field(description="Kill the build after this many seconds.", ge=1, le=21600)] = 1800,
    extra_args: Annotated[
        dict[str, Any] | list[str] | str | None,
        Field(description="Amaranth toolchain overrides: dict, JSON object or ['key=value', ...], e.g. {'nextpnr_opts': '--seed 2', 'verbose': true}."),
    ] = None,
    elaborate_only: Annotated[bool, Field(description="Only elaborate and write the build plan (RTLIL, LPF, scripts); no toolchain needed.")] = False,
) -> dict[str, Any]:
    """Build an Amaranth design for the Cynthion ECP5 into a .bit bitstream in a subprocess (yosys -> nextpnr-ecp5
    -> ecppack), with progress. Never touches the board; load the result with configure_bitstream(path=<bitstream>).
    Design/toolchain failures are reported as [BUILD_FAILED] with the log tail."""
    # Deliberately no ACTIVITY.check_free(): the build only runs the toolchain and never opens the board, so it
    # may run during an analyzer capture or a Facedancer emulation.
    # Cancellable: on an MCP cancel the worker thread is abandoned and cancel_event makes it kill the runner tree
    # within ~1 s (which also releases the build lock), instead of waiting for the whole build.
    cancel_event = threading.Event()
    fn = functools.partial(
        gateware_build.build_gateware,
        source,
        top=top,
        platform_revision=platform_revision,
        output_dir=output_dir,
        timeout_s=timeout_s,
        extra_args=extra_args,
        elaborate_only=elaborate_only,
        progress=_make_progress_fn(ctx),
        cancel_event=cancel_event,
    )
    try:
        result = await anyio.to_thread.run_sync(fn, abandon_on_cancel=True)
    except (anyio.get_cancelled_exc_class(), KeyboardInterrupt):
        cancel_event.set()
        raise
    except BaseException as exc:  # noqa: BLE001
        raise _to_tool_error(exc) from exc
    return _ok(result)


# ===========================================================================
# Resources
# ===========================================================================


@mcp.resource("cynthion://status", name="status", mime_type="application/json",
              description="Server, device and activity status (same as server_status).")
async def status_resource() -> str:
    return json.dumps(await common.run_blocking(_status_impl), default=str, indent=2)


@mcp.resource("cynthion://assets", name="assets", mime_type="application/json",
              description="Bundled gateware and firmware assets.")
async def assets_resource() -> str:
    return json.dumps(await common.run_blocking(gateware.list_bundled_assets), default=str, indent=2)


@mcp.resource("cynthion://capture/last.pcap", name="last_capture_pcap", mime_type="application/vnd.tcpdump.pcap",
              description="Current analyzer buffer as a pcap file (LINKTYPE_USB_2_0).")
async def capture_pcap_resource() -> bytes:
    return bytes(await common.run_blocking(analyzer.CAPTURE.last_pcap_bytes))


@mcp.resource("cynthion://logs", name="logs", mime_type="text/plain", description="Last 500 server log lines.")
async def logs_resource() -> str:
    return "\n".join(common.LOG_RING.get(500))


# ===========================================================================
# Prompts
# ===========================================================================


@mcp.prompt()
def capture_usb_traffic(target_description: str) -> str:
    """Step-by-step guide to capture and analyse USB traffic of a device with the Cynthion analyzer."""
    return f"""Capture and analyse the USB traffic of: {target_description}

1. Call server_status. If mode is "absent", run the diagnose_connection prompt and stop.
2. Explain the wiring to the user: PC -> CONTROL port of the Cynthion; the host of the device under test -> TARGET-C;
   the device under test -> TARGET-A. Ask them to confirm.
3. Call analyzer_start (speed="auto" unless the user knows the speed; it loads the analyzer gateware if needed).
4. Ask the user to plug in / use the device. Poll analyzer_status, then analyzer_read or analyzer_transactions
   (use next_seq for incremental reads, include_sof=false to reduce noise).
5. Call analyzer_stop when done, then analyzer_summary for an overview (devices, endpoints, PIDs, CRC errors).
6. Decode enumeration with analyzer_transactions(endpoint=0, decode_setup=true); look for GET_DESCRIPTOR requests.
7. Call analyzer_export_pcap and give the user the path (opens in Wireshark or Packetry).
For a short fixed-length capture, analyzer_capture(seconds=...) does steps 3-5 in one call."""


@mcp.prompt()
def emulate_keyboard(text: str) -> str:
    """Guide to emulate a USB keyboard with Facedancer and type text on the target host."""
    return f"""Emulate a USB keyboard with the Cynthion and type the following text on the target host:
{text!r}

1. Call server_status. If mode is "absent", run diagnose_connection and stop. If an analyzer capture is running,
   ask the user whether to stop it (analyzer_stop).
2. Tell the user to connect the target host to the TARGET-C port (and the PC to CONTROL). Ask for confirmation,
   because the keystrokes will be typed into whatever window has focus on the target.
3. Call facedancer_start(kind="keyboard") (it loads the facedancer gateware and SoC firmware if needed).
4. Check facedancer_status until connected is true (facedancer_events shows the host enumerating the keyboard).
5. Call facedancer_type_text(text=...) with the text above.
6. Call facedancer_stop. Optionally call reconfigure_fpga to go back to the gateware stored in flash."""


@mcp.prompt()
def diagnose_connection() -> str:
    """Checklist to diagnose why no Cynthion is detected."""
    return """Diagnose the Cynthion connection:

1. Call server_status and list_devices. Note the mode and any error fields.
2. If no device is listed:
   - The PC must be connected to the CONTROL port (USB-C on the left, next to the LEDs), with a data cable, not
     a charge-only cable. Try another cable / port, avoid unpowered hubs.
   - Windows: open Device Manager. "Cynthion Apollo Debugger" (1d50:615c) and the gateware (1d50:615b) must use the
     WinUSB driver. If they show with a warning or another driver, install WinUSB with Zadig.
   - Linux: install the udev rules (cynthion setup) and replug.
3. If mode is "unknown": the device is visible but descriptors cannot be read -> driver/permission problem (see step 2).
4. If mode is "apollo": the debugger works, the FPGA has no USB gateware. Use run_gateware or reconfigure_fpga.
5. If mode is "gateware_stub": custom gateware is running; device_info(force_offline=true) hands control to Apollo.
6. Call device_info to read firmware version and hardware revision, then get_logs(level="DEBUG") for details.
Report the findings to the user."""


# ===========================================================================
# Entry point
# ===========================================================================


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(prog="cynthion-mcp", description="MCP server for the Great Scott Gadgets Cynthion")
    parser.add_argument("--log-level", default=os.environ.get("CYNTHION_MCP_LOG_LEVEL", "INFO"))
    parser.add_argument("--transport", choices=("stdio", "streamable-http"), default="stdio")
    args = parser.parse_args()
    os.environ["CYNTHION_MCP_LOG_LEVEL"] = args.log_level

    # Reserve the real stdout for JSON-RPC; every stray print() from libraries goes to stderr.
    real_stdout = sys.stdout
    sys.stdout = sys.stderr
    common.setup_logging(args.log_level)

    if args.transport == "streamable-http":
        mcp.run("streamable-http")
        return

    from io import TextIOWrapper

    from mcp.server.stdio import stdio_server

    async def _run() -> None:
        out = anyio.wrap_file(TextIOWrapper(real_stdout.buffer, encoding="utf-8"))
        async with stdio_server(stdout=out) as (read_stream, write_stream):
            await mcp._mcp_server.run(
                read_stream,
                write_stream,
                mcp._mcp_server.create_initialization_options(),
            )

    anyio.run(_run)


if __name__ == "__main__":
    main()
