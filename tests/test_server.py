"""End-to-end tests of the Cynthion MCP server through an in-memory MCP client.

These tests are written for a machine WITHOUT a Cynthion plugged in. Tests whose
expectations depend on the hardware being absent are skipped automatically when
a device is detected (server_status reports a mode other than "absent").
"""

from __future__ import annotations

import base64
import json
import os
import queue
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcp.shared.memory import create_connected_server_and_client_session  # noqa: E402
from mcp.types import BlobResourceContents, CallToolResult, TextContent  # noqa: E402

from cynthion_mcp.server import mcp  # noqa: E402


PCAP_MAGICS = {
    bytes.fromhex("4d3cb2a1"),  # 0xA1B23C4D little-endian (nanosecond timestamps)
    bytes.fromhex("d4c3b2a1"),  # 0xA1B2C3D4 little-endian (microsecond timestamps)
}

EXPECTED_TOOLS = {
    "server_status", "list_devices", "device_info", "list_bundled_assets", "get_logs",
    "set_led_pattern", "reconfigure_fpga", "force_fpga_offline", "jtag_scan",
    "jtag_register_read", "jtag_register_write",
    "run_gateware", "configure_bitstream", "flash_gateware", "flash_file", "read_flash",
    "erase_flash", "flash_info", "update_apollo_firmware", "run_selftest",
    "analyzer_info", "analyzer_start", "analyzer_stop", "analyzer_status", "analyzer_read",
    "analyzer_transactions", "analyzer_summary", "analyzer_export_pcap", "analyzer_clear",
    "analyzer_capture", "analyzer_test_device", "decode_usb_packet",
    "facedancer_list_device_kinds", "facedancer_start", "facedancer_command",
    "facedancer_type_text", "facedancer_serial_write", "facedancer_status",
    "facedancer_logs", "facedancer_events", "facedancer_stop",
    "board_info", "led_set", "gpio_list", "gpio_read", "gpio_write", "board_debug_log",
    "analyzer_decode_classes", "gateware_toolchain_status", "build_gateware",
}

DESTRUCTIVE_TOOLS = {"erase_flash", "flash_gateware", "flash_file", "update_apollo_firmware"}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# --------------------------------------------------------------------------- helpers

def _text(result: CallToolResult) -> str:
    return "\n".join(c.text for c in result.content if isinstance(c, TextContent))


def _structured(result: CallToolResult) -> dict[str, Any]:
    if result.structuredContent is not None:
        return result.structuredContent
    # Fallback: unstructured JSON text.
    return json.loads(_text(result))


async def _skip_if_hardware(client) -> None:
    res = await client.call_tool("server_status", {})
    if res.isError:
        return
    mode = _structured(res).get("mode")
    if mode != "absent":
        pytest.skip(f"a Cynthion seems to be connected (mode={mode!r}); test expects no hardware")


def _assert_error_code(result: CallToolResult, code: str) -> None:
    text = _text(result)
    assert result.isError is True, f"expected an error, got: {text!r}"
    assert f"[{code}]" in text, f"expected [{code}] in error text, got: {text!r}"


# --------------------------------------------------------------------------- tools

@pytest.mark.anyio
async def test_list_tools_contains_catalogue():
    async with create_connected_server_and_client_session(mcp) as client:
        tools = (await client.list_tools()).tools
        names = {t.name for t in tools}
        missing = EXPECTED_TOOLS - names
        assert not missing, f"missing tools: {sorted(missing)}"


@pytest.mark.anyio
async def test_tool_annotations():
    async with create_connected_server_and_client_session(mcp) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        for name in DESTRUCTIVE_TOOLS:
            ann = tools[name].annotations
            assert ann is not None, f"{name} has no annotations"
            assert ann.destructiveHint is True, f"{name} should be destructive"
        ann = tools["list_devices"].annotations
        assert ann is not None and ann.readOnlyHint is True


@pytest.mark.anyio
async def test_server_status_without_hardware():
    async with create_connected_server_and_client_session(mcp) as client:
        res = await client.call_tool("server_status", {})
        assert res.isError is False, _text(res)
        data = _structured(res)
        assert data.get("ok") is True
        if data.get("mode") != "absent":
            pytest.skip(f"hardware connected (mode={data.get('mode')!r})")
        assert data["mode"] == "absent"


@pytest.mark.anyio
async def test_list_bundled_assets():
    async with create_connected_server_and_client_session(mcp) as client:
        res = await client.call_tool("list_bundled_assets", {})
        assert res.isError is False, _text(res)
        assert _structured(res).get("ok") is True


@pytest.mark.anyio
async def test_decode_usb_packet_ack():
    async with create_connected_server_and_client_session(mcp) as client:
        res = await client.call_tool("decode_usb_packet", {"hex_bytes": "d2"})
        assert res.isError is False, _text(res)
        assert _structured(res)["pid"] == "ACK"


@pytest.mark.anyio
async def test_device_info_no_device():
    async with create_connected_server_and_client_session(mcp) as client:
        await _skip_if_hardware(client)
        res = await client.call_tool("device_info", {})
        assert res.isError is True
        assert _text(res).startswith("Error executing tool")
        _assert_error_code(res, "NO_DEVICE")


@pytest.mark.anyio
async def test_analyzer_start_no_device():
    async with create_connected_server_and_client_session(mcp) as client:
        await _skip_if_hardware(client)
        res = await client.call_tool("analyzer_start", {"auto_load_gateware": True})
        _assert_error_code(res, "NO_DEVICE")


@pytest.mark.anyio
async def test_facedancer_start_no_device():
    async with create_connected_server_and_client_session(mcp) as client:
        await _skip_if_hardware(client)
        res = await client.call_tool("facedancer_start", {"kind": "keyboard"})
        _assert_error_code(res, "NO_DEVICE")


@pytest.mark.anyio
async def test_erase_flash_requires_confirmation():
    async with create_connected_server_and_client_session(mcp) as client:
        res = await client.call_tool("erase_flash", {})
        _assert_error_code(res, "CONFIRMATION_REQUIRED")


@pytest.mark.anyio
async def test_analyzer_status_idle():
    async with create_connected_server_and_client_session(mcp) as client:
        res = await client.call_tool("analyzer_status", {})
        assert res.isError is False, _text(res)
        data = _structured(res)
        assert data.get("state") == "idle"


# --------------------------------------------------------------------------- class decoder / gateware build / board mode

def _token(pid_byte: int, addr: int, ep: int) -> bytes:
    from cynthion_mcp import usbdecode

    v = addr | (ep << 7)
    v |= usbdecode.crc5_usb(v & 0x7FF) << 11
    return bytes([pid_byte, v & 0xFF, v >> 8])


def _data(pid_byte: int, payload: bytes) -> bytes:
    from cynthion_mcp import usbdecode

    return bytes([pid_byte]) + payload + usbdecode.crc16_usb(payload).to_bytes(2, "little")


def _fake_records() -> list:
    """SET_ADDRESS(9) on address 0, then CDC serial traffic on address 9 (OUT "hi" on EP2, IN "ok" on EP1)."""
    from cynthion_mcp import usbdecode

    recs: list = []
    ticks = 0

    def pkt(raw: bytes, gap_us: float = 5.0) -> None:
        nonlocal ticks
        ticks += int(gap_us * 60)
        recs.append(usbdecode.Record(len(recs), "packet", ticks, raw))

    def txn(pid: int, addr: int, ep: int, data_pid: int | None, payload: bytes | None, hs: int | None = 0xD2) -> None:
        pkt(_token(pid, addr, ep), 10)
        if data_pid is not None:
            pkt(_data(data_pid, payload or b""))
        if hs is not None:
            pkt(bytes([hs]))

    txn(0x2D, 0, 0, 0xC3, bytes([0x00, 0x05, 9, 0, 0, 0, 0, 0]))  # SETUP SET_ADDRESS 9
    txn(0x69, 0, 0, 0x4B, b"")                                    # status stage: IN ZLP
    pkt(_token(0xE1, 9, 2), 100_000)                              # 100 ms later: bulk OUT EP2 "hi"
    pkt(_data(0xC3, b"hi"))
    pkt(bytes([0xD2]))
    pkt(_token(0x69, 9, 1), 100_000)                              # 100 ms later: bulk IN EP1 "ok"
    pkt(_data(0xC3, b"ok"))
    pkt(bytes([0xD2]))
    return recs


@pytest.fixture
def fake_buffer(monkeypatch):
    from cynthion_mcp import analyzer

    recs = _fake_records()
    monkeypatch.setattr(analyzer.CAPTURE, "snapshot", lambda start_seq=None: list(recs))
    return recs


@pytest.mark.anyio
async def test_analyzer_decode_classes_with_hints(fake_buffer):
    async with create_connected_server_and_client_session(mcp) as client:
        res = await client.call_tool("analyzer_decode_classes", {"hints": {"9": "cdc"}})
        assert res.isError is False, _text(res)
        data = _structured(res)
        assert data["ok"] is True
        layers = [it["layer"] for it in data["items"]]
        assert "control" in layers and "serial" in layers, data["items"]
        assert data["count"] == len(data["items"]) == data["total_matching"]
        assert data["truncated"] is False
        assert data["next_seq"] == fake_buffer[-1].seq + 1
        assert "9" in data["devices"]
        texts = [it["details"].get("text") for it in data["items"] if it["layer"] == "serial"]
        assert "hi" in texts and "ok" in texts

        # Filters: layer + address + endpoint.
        res = await client.call_tool(
            "analyzer_decode_classes",
            {"hints": {"9": "cdc"}, "layers": ["serial"], "address": 9, "endpoint": 2},
        )
        data = _structured(res)
        assert data["count"] == 1 and data["items"][0]["details"]["text"] == "hi"

        # Pagination: limit=1 truncates, next_seq resumes at the next item.
        res = await client.call_tool("analyzer_decode_classes", {"hints": {"9": "cdc"}, "limit": 1})
        page1 = _structured(res)
        assert page1["count"] == 1 and page1["truncated"] is True and page1["total_matching"] >= 3
        res = await client.call_tool(
            "analyzer_decode_classes", {"hints": {"9": "cdc"}, "limit": 1, "start_seq": page1["next_seq"]}
        )
        page2 = _structured(res)
        assert page2["items"][0]["seq"] == page1["next_seq"] > page1["items"][0]["seq"]


@pytest.mark.anyio
async def test_analyzer_decode_classes_bad_hints(fake_buffer):
    async with create_connected_server_and_client_session(mcp) as client:
        res = await client.call_tool("analyzer_decode_classes", {"hints": {"9": "not_a_class"}})
        _assert_error_code(res, "INVALID_ARGUMENT")


@pytest.mark.anyio
async def test_analyzer_decode_classes_empty_buffer():
    async with create_connected_server_and_client_session(mcp) as client:
        res = await client.call_tool("analyzer_decode_classes", {})
        assert res.isError is False, _text(res)
        data = _structured(res)
        assert data["count"] == 0 and data["items"] == [] and data["truncated"] is False
        assert "note" in data


@pytest.mark.anyio
async def test_gateware_toolchain_status_mocked(monkeypatch):
    from cynthion_mcp import gateware_build

    seen: dict[str, Any] = {}

    def fake_status(probe_versions: bool = True) -> dict[str, Any]:
        seen["probe_versions"] = probe_versions
        return {"ready": False, "tools": {}, "missing": ["yosys"], "hint": "install"}

    monkeypatch.setattr(gateware_build, "toolchain_status", fake_status)
    async with create_connected_server_and_client_session(mcp) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
        assert tools["gateware_toolchain_status"].annotations.readOnlyHint is True
        res = await client.call_tool("gateware_toolchain_status", {"probe_versions": False})
        assert res.isError is False, _text(res)
        data = _structured(res)
        assert data["ok"] is True and data["ready"] is False and data["missing"] == ["yosys"]
        assert seen["probe_versions"] is False


@pytest.mark.anyio
async def test_build_gateware_mocked_ignores_hardware_lock(monkeypatch, tmp_path):
    from cynthion_mcp import common, gateware_build

    # Pretend the board is owned by a running capture: build_gateware must not care.
    common.ACTIVITY.register("analyzer_capture", lambda: True, "capture running", "analyzer_stop")
    calls: list[dict[str, Any]] = []

    def fake_build(source, top=None, platform_revision=None, output_dir=None, timeout_s=1800,
                   extra_args=None, progress_cb=None, *, name=None, elaborate_only=False, progress=None,
                   cancel_event=None):
        calls.append(dict(source=source, top=top, platform_revision=platform_revision, output_dir=output_dir,
                          timeout_s=timeout_s, extra_args=extra_args, elaborate_only=elaborate_only,
                          progress=progress, cancel_event=cancel_event))
        if progress is not None:
            progress(50.0, 100.0, "half")
        return {"bitstream": str(tmp_path / "top.bit"), "platform": "CynthionPlatformRev1D4"}

    monkeypatch.setattr(gateware_build, "build_gateware", fake_build)
    async with create_connected_server_and_client_session(mcp) as client:
        res = await client.call_tool("build_gateware", {
            "source": str(tmp_path / "design.py"), "top": "Top", "platform_revision": "r1.4",
            "timeout_s": 60, "extra_args": {"verbose": True}, "elaborate_only": True,
        })
        assert res.isError is False, _text(res)
        data = _structured(res)
        assert data["ok"] is True and data["bitstream"].endswith("top.bit")
    assert len(calls) == 1
    c = calls[0]
    assert c["top"] == "Top" and c["platform_revision"] == "r1.4" and c["timeout_s"] == 60
    assert c["extra_args"] == {"verbose": True} and c["elaborate_only"] is True
    assert callable(c["progress"])
    assert c["cancel_event"] is not None and not c["cancel_event"].is_set()


@pytest.mark.anyio
async def test_build_gateware_failure_is_build_failed(monkeypatch, tmp_path):
    from cynthion_mcp import gateware_build

    def failing_build(*_a, **_kw):
        raise gateware_build.BuildError("nextpnr failed: unrouted nets")

    monkeypatch.setattr(gateware_build, "build_gateware", failing_build)
    async with create_connected_server_and_client_session(mcp) as client:
        res = await client.call_tool("build_gateware", {"source": str(tmp_path / "design.py")})
        _assert_error_code(res, "BUILD_FAILED")
        assert "unrouted nets" in _text(res)


@pytest.mark.anyio
@pytest.mark.parametrize("tool,args", [
    ("led_set", {"index": 0, "state": "on"}),
    ("gpio_read", {"pin": "A1"}),
    ("gpio_write", {"pin": "A1", "value": True}),
    ("gpio_list", {}),
    ("board_info", {}),
])
async def test_board_tools_wrong_mode(monkeypatch, tool, args):
    from cynthion_mcp import board_io, device

    def must_not_open(*_a, **_kw):
        raise AssertionError("board must not be opened outside facedancer mode")

    monkeypatch.setattr(device, "current_mode", lambda serial=None: "analyzer")
    monkeypatch.setattr(board_io, "run_board_op", must_not_open)
    async with create_connected_server_and_client_session(mcp) as client:
        res = await client.call_tool(tool, args)
        _assert_error_code(res, "WRONG_MODE")
        assert "switch with run_gateware(target='facedancer')" in _text(res)


@pytest.mark.anyio
async def test_board_tools_absent_is_no_device():
    async with create_connected_server_and_client_session(mcp) as client:
        await _skip_if_hardware(client)
        res = await client.call_tool("led_set", {"index": 0, "state": "on"})
        _assert_error_code(res, "NO_DEVICE")


def test_instructions_mention_new_workflows():
    from cynthion_mcp.server import INSTRUCTIONS

    for needle in ("[BUILD_FAILED]", "gateware_toolchain_status", "build_gateware", "configure_bitstream",
                   "analyzer_decode_classes", "hints", "run_gateware(target='facedancer')", "[WRONG_MODE]"):
        assert needle in INSTRUCTIONS, needle


# --------------------------------------------------------------------------- resources / prompts

@pytest.mark.anyio
async def test_pcap_resource_has_magic():
    from pydantic import AnyUrl

    async with create_connected_server_and_client_session(mcp) as client:
        res = await client.read_resource(AnyUrl("cynthion://capture/last.pcap"))
        assert res.contents, "resource returned no contents"
        blob = res.contents[0]
        assert isinstance(blob, BlobResourceContents), f"expected a blob, got {type(blob).__name__}"
        data = base64.b64decode(blob.blob)
        assert data[:4] in PCAP_MAGICS, f"bad pcap magic: {data[:4].hex()}"


@pytest.mark.anyio
async def test_prompts_listed():
    async with create_connected_server_and_client_session(mcp) as client:
        names = {p.name for p in (await client.list_prompts()).prompts}
        for expected in ("capture_usb_traffic", "emulate_keyboard", "diagnose_connection"):
            assert expected in names, f"missing prompt {expected}"


# --------------------------------------------------------------------------- stdio cleanliness

@pytest.mark.slow
def test_stdio_stdout_is_pure_jsonrpc():
    """Run `python -m cynthion_mcp` over real stdio and check stdout only carries JSON-RPC."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    proc = subprocess.Popen(
        [sys.executable, "-m", "cynthion_mcp"],
        cwd=str(ROOT),
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    lines: "queue.Queue[bytes | None]" = queue.Queue()

    def _reader() -> None:
        assert proc.stdout is not None
        for raw in iter(proc.stdout.readline, b""):
            lines.put(raw)
        lines.put(None)

    threading.Thread(target=_reader, daemon=True).start()

    def _send(msg: dict[str, Any]) -> None:
        assert proc.stdin is not None
        proc.stdin.write((json.dumps(msg) + "\n").encode("utf-8"))
        proc.stdin.flush()

    collected: list[bytes] = []
    responses: dict[Any, dict[str, Any]] = {}

    def _wait_for(req_id: int, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while req_id not in responses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"no response to request {req_id}; stdout so far: {collected!r}")
            try:
                raw = lines.get(timeout=remaining)
            except queue.Empty:
                continue
            if raw is None:
                raise AssertionError(f"server exited early; stdout: {collected!r}")
            collected.append(raw)
            if not raw.strip():
                continue
            msg = json.loads(raw.decode("utf-8"))  # any non-JSON line fails the test here
            if "id" in msg:
                responses[msg["id"]] = msg

    try:
        _send({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "0"},
            },
        })
        _wait_for(1, 60)
        assert "result" in responses[1], responses[1]
        _send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        _send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        _wait_for(2, 60)
        tool_names = {t["name"] for t in responses[2]["result"]["tools"]}
        assert "server_status" in tool_names
    finally:
        try:
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)

    # Drain whatever was written before exit and validate every line.
    while True:
        try:
            raw = lines.get(timeout=1)
        except queue.Empty:
            break
        if raw is None:
            break
        collected.append(raw)
    for raw in collected:
        if raw.strip():
            json.loads(raw.decode("utf-8"))


@pytest.mark.anyio
async def test_analyzer_decode_classes_live_paging_keeps_open_control_transfer(monkeypatch):
    """While capturing, a control transfer without status stage must come back completed on the next page."""
    from cynthion_mcp import analyzer, usbdecode

    recs: list = []

    def txn(*raws: bytes) -> None:
        for raw in raws:
            recs.append(usbdecode.Record(len(recs), "packet", len(recs) * 600, raw))

    dev_desc = bytes([18, 1, 0x00, 0x02, 0, 0, 0, 64, 0x6D, 0x04, 0x1C, 0xC3, 0x10, 0x01, 1, 2, 0, 1])
    txn(_token(0x2D, 0, 0), _data(0xC3, bytes([0x80, 6, 0, 1, 0, 0, 18, 0])), bytes([0xD2]))
    txn(_token(0x69, 0, 0), _data(0x4B, dev_desc), bytes([0xD2]))
    first_len = len(recs)
    view = {"n": first_len}
    monkeypatch.setattr(analyzer.CAPTURE, "snapshot", lambda start_seq=None: list(recs[:view["n"]]))
    monkeypatch.setattr(analyzer.CAPTURE, "is_running", lambda: True)
    async with create_connected_server_and_client_session(mcp) as client:
        page1 = _structured(await client.call_tool("analyzer_decode_classes", {}))
        assert "[incomplete]" in page1["items"][0]["summary"]
        assert page1["next_seq"] == 0  # resume at the open SETUP, not after the buffer
        txn(_token(0xE1, 0, 0), _data(0x4B, b""), bytes([0xD2]))  # status stage arrives
        view["n"] = len(recs)
        page2 = _structured(await client.call_tool("analyzer_decode_classes", {"start_seq": page1["next_seq"]}))
        done = [it for it in page2["items"] if it["layer"] == "control"]
        assert done and done[0]["details"]["status"] == "ACK"
        assert page2["next_seq"] == recs[-1].seq + 1
