"""Tests for the Facedancer subprocess runner (no hardware required).

Most tests drive ``FacedancerRunner`` with a FAKE worker script written to
``tmp_path``. The fake speaks the same JSON-lines protocol as
``cynthion_mcp.facedancer_worker`` (see the docstring of facedancer_runner):

  parent -> child : {"id": N, "cmd": "...", "args": {...}}
  child  -> parent: {"type": "ready"|"connected"|"result"|"error"|"stopped"|"data"|"log", ...}

One slow smoke test runs the REAL worker with no Cynthion attached and checks
that it reports a fatal NO_DEVICE error, then ``stopped``, then exits non-zero.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

import cynthion_mcp.facedancer_runner as fr
from cynthion_mcp.common import (
    InvalidArgumentError,
    NoDeviceError,
    WrongModeError,
)

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

STDERR_JUNK = "FAKE-WORKER stderr junk: Traceback-looking noise 12345"

# --------------------------------------------------------------------------
# Fake worker script
# --------------------------------------------------------------------------
FAKE_WORKER = textwrap.dedent(
    r'''
    import json, sys, time

    def emit(obj):
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    argv = sys.argv[1:]
    def opt(name, default=None):
        if name in argv:
            i = argv.index(name)
            if i + 1 < len(argv):
                return argv[i + 1]
        return default

    mode = opt("--fake-mode", "ok")
    kind = opt("--kind", "?")
    params = json.loads(opt("--params", "{}") or "{}")

    sys.stderr.write("STDERR_JUNK\n")
    sys.stderr.flush()

    if mode == "fatal":
        emit({"type": "error", "code": "NO_DEVICE",
              "message": "No Cynthion (fake)", "hint": "plug it in",
              "fatal": True})
        emit({"type": "stopped", "reason": "error", "unhandled_requests": []})
        sys.exit(2)

    emit({"type": "ready", "kind": kind, "params": params})
    emit({"type": "connected", "kind": kind, "vid": 0x610B, "pid": 0x4653,
          "speed": "full"})
    emit({"type": "data", "source": "fake", "direction": "out",
          "hex": "68656c6c6f"})

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        mid = msg.get("id")
        cmd = msg.get("cmd")
        args = msg.get("args") or {}
        if cmd == "stop":
            break
        if cmd == "ping":
            emit({"type": "result", "id": mid, "ok": True, "value": "pong"})
        elif cmd == "type_string":
            emit({"type": "result", "id": mid, "ok": True,
                  "value": len(args.get("text", ""))})
        elif cmd == "slow":
            time.sleep(float(args.get("seconds", 5)))
            emit({"type": "result", "id": mid, "ok": True, "value": "late"})
        else:
            emit({"type": "result", "id": mid, "ok": False,
                  "code": "INVALID_ARGUMENT",
                  "error": "unknown command %r" % (cmd,)})

    emit({"type": "stopped", "reason": "requested",
          "unhandled_requests": [{"request": "fake", "count": 1}]})
    sys.exit(0)
    '''
).replace("STDERR_JUNK", STDERR_JUNK)


@pytest.fixture
def fake_worker(tmp_path) -> Path:
    path = tmp_path / "fake_worker.py"
    path.write_text(FAKE_WORKER, encoding="utf-8")
    return path


def _make_runner(fake_worker: Path, mode: str = "ok") -> fr.FacedancerRunner:
    cmd = [sys.executable, "-u", str(fake_worker)]
    if mode != "ok":
        cmd += ["--fake-mode", mode]
    return fr.FacedancerRunner(worker_cmd=cmd)


@pytest.fixture
def runner(fake_worker):
    r = _make_runner(fake_worker)
    yield r
    try:
        if r.is_running():
            r.stop(3.0)
    except Exception:
        pass


def _wait_until(predicate, timeout: float = 5.0, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


def _log_texts(r: fr.FacedancerRunner) -> list[str]:
    return [item["text"] for item in r.logs(lines=5000)["lines"]]


# --------------------------------------------------------------------------
# Catalogue
# --------------------------------------------------------------------------
def test_kind_specs_keys():
    assert set(fr.KIND_SPECS) == {"keyboard", "ftdi", "mass_storage", "proxy", "script"}


# --------------------------------------------------------------------------
# Full life cycle with the fake worker
# --------------------------------------------------------------------------
def test_start_command_events_logs_stop(runner):
    st = runner.start(kind="keyboard", check_mode=False, ready_timeout_s=15)
    assert st["ok"] is True
    assert st["running"] is True
    assert st["connected"] is True
    assert st["kind"] == "keyboard"
    assert st["connect_info"]["kind"] == "keyboard"
    assert runner.is_running()

    # ping -> pong
    res = runner.send_command("ping")
    assert res == {"ok": True, "result": "pong"}

    # type_string -> len(text)
    res = runner.send_command("type_string", {"text": "hello world"})
    assert res["result"] == len("hello world")

    # worker-side error is translated to the matching exception class
    with pytest.raises(InvalidArgumentError):
        runner.send_command("does_not_exist", {})

    # asynchronous data event is buffered
    assert _wait_until(
        lambda: any(e.get("type") == "data" for e in runner.events()["events"])
    )
    events = runner.events()["events"]
    data_events = [e for e in events if e.get("type") == "data"]
    assert data_events and data_events[0]["hex"] == "68656c6c6f"
    assert all("seq" in e for e in events)
    assert runner.events(types=["data"])["events"] == data_events

    # child's stderr junk lands in the log ring (never on our stdout)
    assert _wait_until(lambda: any(STDERR_JUNK in t for t in _log_texts(runner)))

    # stop: cooperative exit with code 0
    out = runner.stop(timeout_s=5)
    assert out["ok"] is True
    assert out["exit_code"] == 0
    assert out["unhandled_requests"] == [{"request": "fake", "count": 1}]
    assert runner.is_running() is False
    st = runner.status()
    assert st["running"] is False
    assert st["exit_code"] == 0
    assert any(e.get("type") == "stopped" for e in runner.events()["events"])


def test_start_twice_is_busy(runner):
    runner.start(kind="keyboard", check_mode=False)
    from cynthion_mcp.common import BusyError

    with pytest.raises(BusyError):
        runner.start(kind="keyboard", check_mode=False)


def test_logs_and_events_since_seq(runner):
    runner.start(kind="ftdi", check_mode=False)
    assert _wait_until(lambda: len(runner.events()["events"]) >= 3)
    first = runner.events()
    assert runner.events(since_seq=first["next_seq"])["events"] == []
    logs = runner.logs(lines=10)
    assert runner.logs(since_seq=logs["next_seq"])["lines"] == []


# --------------------------------------------------------------------------
# Failure paths
# --------------------------------------------------------------------------
def test_start_fatal_no_device(fake_worker):
    r = _make_runner(fake_worker, mode="fatal")
    with pytest.raises(NoDeviceError) as excinfo:
        r.start(kind="keyboard", check_mode=False, ready_timeout_s=15)
    assert "fake" in str(excinfo.value) or "Cynthion" in str(excinfo.value)
    assert _wait_until(lambda: not r.is_running())
    st = r.status()
    assert st["running"] is False
    assert st["connected"] is False
    assert st["exit_code"] == 2


def test_start_check_mode_absent_does_not_spawn(fake_worker):
    # conftest's autouse ``no_usb`` makes enumeration return nothing.
    r = _make_runner(fake_worker)
    with pytest.raises(NoDeviceError):
        r.start(kind="keyboard", check_mode=True)
    assert r._proc is None
    assert r.is_running() is False


def test_start_check_mode_wrong_mode_does_not_spawn(fake_worker, monkeypatch,
                                                    fake_usb_device):
    import cynthion_mcp.device as device_mod

    analyzer = fake_usb_device(0x1D50, 0x615B, interfaces=[(0, 0xFF, 0x10, 0x01)])
    monkeypatch.setattr(device_mod, "_usb_find_all", lambda *a, **kw: [analyzer])
    r = _make_runner(fake_worker)
    with pytest.raises(WrongModeError):
        r.start(kind="keyboard", check_mode=True)
    assert r._proc is None


def test_send_command_when_not_running(fake_worker):
    r = _make_runner(fake_worker)
    with pytest.raises(WrongModeError):
        r.send_command("ping")


def test_stop_when_not_running_is_noop(fake_worker):
    r = _make_runner(fake_worker)
    out = r.stop()
    assert out["ok"] is True
    assert out["running"] is False


def test_unknown_kind(fake_worker):
    r = _make_runner(fake_worker)
    with pytest.raises(InvalidArgumentError):
        r.start(kind="toaster", check_mode=False)
    assert r._proc is None


def test_script_without_path(fake_worker):
    r = _make_runner(fake_worker)
    with pytest.raises(InvalidArgumentError):
        r.start(kind="script", check_mode=False)
    assert r._proc is None


def test_script_with_missing_file(fake_worker, tmp_path):
    r = _make_runner(fake_worker)
    with pytest.raises(InvalidArgumentError):
        r.start(kind="script", script_path=str(tmp_path / "nope.py"), check_mode=False)
    assert r._proc is None


# --------------------------------------------------------------------------
# Smoke test: the REAL worker without hardware
# --------------------------------------------------------------------------
def _cynthion_plugged() -> bool:
    """Ask a clean subprocess (conftest stubs pyusb in-process)."""
    probe = ("import usb.core,sys;"
             "sys.exit(0 if usb.core.find(idVendor=0x1d50) is not None else 1)")
    try:
        return subprocess.run([sys.executable, "-c", probe], timeout=15).returncode == 0
    except Exception:
        return False


@pytest.mark.slow
@pytest.mark.skipif(bool(os.environ.get("CYNTHION_MCP_SKIP_SLOW")),
                    reason="CYNTHION_MCP_SKIP_SLOW is set")
def test_real_worker_without_hardware_reports_no_device():
    if _cynthion_plugged():
        pytest.skip("a real Cynthion is connected: the worker would really emulate a device")
    worker_file = SRC / "cynthion_mcp" / "facedancer_worker.py"
    if not worker_file.is_file():
        pytest.skip("facedancer_worker.py not present")

    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(SRC)] + [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p]
    )
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["BACKEND"] = "cynthion"

    proc = subprocess.run(
        [sys.executable, "-u", "-m", "cynthion_mcp.facedancer_worker",
         "--kind", "keyboard"],
        input="",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        env=env,
        cwd=str(ROOT),
    )

    messages = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            pytest.fail(f"non-JSON line on worker stdout: {line!r}\n"
                        f"stderr:\n{proc.stderr[-2000:]}")
        if isinstance(obj, dict):
            messages.append(obj)

    diag = f"stdout messages: {messages!r}\nstderr tail:\n{proc.stderr[-2000:]}"
    types = [m.get("type") for m in messages]

    fatal = [m for m in messages
             if m.get("type") == "error" and m.get("code") == "NO_DEVICE" and m.get("fatal")]
    assert fatal, diag
    assert "stopped" in types, diag
    assert types.index("stopped") > messages.index(fatal[0]), diag
    assert "connected" not in types, diag
    assert proc.returncode != 0, diag


# --------------------------------------------------------------------------
# Real worker: error fields and key resolution (no hardware needed)
# --------------------------------------------------------------------------
def _run_handle(monkeypatch, worker, msg):
    import asyncio
    import cynthion_mcp.facedancer_worker as fw
    out = []
    monkeypatch.setattr(fw, "emit", out.append)
    asyncio.run(worker._handle(msg))
    return out[-1]


def test_worker_failure_keeps_code_and_hint(monkeypatch):
    import cynthion_mcp.facedancer_worker as fw
    w = fw.Worker("keyboard", {}, device=object(), board=None)
    res = _run_handle(monkeypatch, w, {"id": 1, "cmd": "key_combo", "args": {"keys": ["NOPE_KEY"]}})
    assert res["ok"] is False
    assert res["code"] == "INVALID_ARGUMENT"
    assert not res["error"].startswith("[")
    assert res["hint"]


def test_runner_maps_worker_code(runner):
    runner.start(kind="keyboard", check_mode=False, ready_timeout_s=15)
    with pytest.raises(InvalidArgumentError):
        runner.send_command("nope")


def test_key_combo_shifted_ascii_holds_shift(monkeypatch):
    pytest.importorskip("facedancer")
    import cynthion_mcp.facedancer_worker as fw
    from facedancer.classes.hid.keyboard import KeyboardKeys, KeyboardModifiers

    class Kbd:
        def __init__(self):
            self.mods, self.keys = [], []
        def modifier_down(self, m): self.mods.append(m)
        def key_down(self, k): self.keys.append(k)
        def all_keys_up(self): pass
        def all_modifiers_up(self): pass

    dev = Kbd()
    w = fw.Worker("keyboard", {}, device=dev, board=None)
    res = _run_handle(monkeypatch, w, {"id": 2, "cmd": "key_combo",
                                       "args": {"keys": ["!"], "duration": 0}})
    assert res["ok"] is True, res
    assert KeyboardModifiers.MOD_LEFT_SHIFT in dev.mods
    assert dev.keys == [KeyboardKeys.get_scancode_for_ascii("!")[1]]


def test_builtin_devices_keep_their_configurations():
    """Regression (real hardware, r1.4): a subclass of FTDIDevice lost its inner
    configuration classes and crashed on GET_DESCRIPTOR(CONFIGURATION)."""
    from cynthion_mcp import facedancer_worker as w
    for build in (w.build_ftdi, w.build_keyboard):
        dev, _ = build({}, None)
        assert 1 in dev.configurations, build.__name__
        dev.configurations[1].get_descriptor()


def test_ftdi_serial_rx_is_reported(monkeypatch):
    from cynthion_mcp import facedancer_worker as w
    seen = []
    monkeypatch.setattr(w, "emit_data", lambda *a, **k: seen.append(a))
    dev, _ = w.build_ftdi({}, None)
    dev.handle_serial_data_received(b"abc")
    assert seen == [("ftdi", "out", None, b"abc")]


def test_events_filter_matches_type_name_source_and_kind():
    r = fr.FacedancerRunner()
    r._append_event({"type": "data", "source": "ftdi", "direction": "out", "hex": "6869"})
    r._append_event({"type": "host_event", "name": "bus_reset"})
    r._append_event({"type": "connected", "kind": "keyboard"})
    assert [e["type"] for e in r.events(types=["data"])["events"]] == ["data"]
    assert [e["source"] for e in r.events(types=["ftdi"])["events"]] == ["ftdi"]
    assert [e["name"] for e in r.events(types=["bus_reset"])["events"]] == ["bus_reset"]
    assert [e["type"] for e in r.events(types=["keyboard"])["events"]] == ["connected"]
    assert r.events(types=["serial_rx"])["events"] == []
