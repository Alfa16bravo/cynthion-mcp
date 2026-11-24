"""Tests for cynthion_mcp.gateware_build / gateware_build_runner (no FPGA toolchain, no USB)."""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

from cynthion_mcp import common
from cynthion_mcp import gateware_build as gb
from cynthion_mcp import gateware_build_runner as runner

ROOT = Path(__file__).resolve().parent.parent
BLINKY = ROOT / "examples" / "blinky.py"


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_luna_platform(monkeypatch):
    """run_build sets LUNA_PLATFORM in os.environ; make monkeypatch restore it after each test."""
    monkeypatch.setenv("LUNA_PLATFORM", "cynthion.gateware.platform:CynthionPlatformRev1D4")


@pytest.fixture
def no_toolchain(monkeypatch, tmp_path):
    """Make every toolchain lookup fail: empty PATH, no env overrides, no OSS CAD Suite, no YoWASP."""
    empty = tmp_path / "empty_path"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    for var in ("YOSYS", "NEXTPNR_ECP5", "ECPPACK", "AMARANTH_ENV_TRELLIS",
                "OSS_CAD_SUITE", "OSS_CAD_SUITE_PATH", "OSS_CAD_SUITE_ROOT"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(gb, "_oss_cad_suite_roots", lambda: [])
    monkeypatch.setattr(
        gb, "_yowasp_packages",
        lambda: {d: {"importable": False, "version": None} for d in gb.YOWASP_MODULES},
    )
    return empty


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


def _resolve(module, top=None):
    """runner.resolve_top, silencing amaranth's UnusedElaboratable warning for the test instance."""
    name, inst = runner.resolve_top(module, top)
    try:
        inst._MustUse__silence = True
    except Exception:
        pass
    return name, inst


TWO_TOPS = """
    from amaranth import Elaboratable, Module, Signal

    class A(Elaboratable):
        def elaborate(self, platform):
            m = Module()
            s = Signal()
            m.d.sync += s.eq(~s)
            return m

    class B(A):
        pass
"""


# ---------------------------------------------------------------------------
# toolchain_status
# ---------------------------------------------------------------------------


def test_toolchain_status_nothing_found(no_toolchain):
    st = gb.toolchain_status()
    assert st["ready"] is False
    assert set(st["missing"]) == {"yosys", "nextpnr-ecp5", "ecppack"}
    for info in st["tools"].values():
        assert info["found"] is False and info["path"] is None
    assert "oss-cad-suite" in st["hint"].lower()
    assert "pip install yowasp-yosys yowasp-nextpnr-ecp5" in st["hint"]
    json.dumps(st)  # must be JSON serialisable


def test_toolchain_status_finds_tools_on_path(no_toolchain, monkeypatch):
    ext = ".bat" if sys.platform.startswith("win") else ""
    for tool in gb.TOOLS:
        f = no_toolchain / f"{tool}{ext}"
        f.write_text("@echo off\r\necho fake 1.0\r\n" if ext else "#!/bin/sh\necho fake 1.0\n")
        f.chmod(0o755)
    st = gb.toolchain_status(probe_versions=False)
    assert st["ready"] is True and st["missing"] == []
    assert all(i["source"] == "PATH" for i in st["tools"].values())
    assert "hint" not in st


def test_toolchain_env_override_bad_path(no_toolchain, monkeypatch):
    monkeypatch.setenv("YOSYS", r"Z:\nope\yosys.exe")
    st = gb.toolchain_status(probe_versions=False)
    assert st["tools"]["yosys"]["found"] is False
    assert "YOSYS" in st["tools"]["yosys"]["error"]


def test_toolchain_oss_cad_suite_dir(no_toolchain, monkeypatch, tmp_path):
    root = tmp_path / "oss-cad-suite"
    (root / "bin").mkdir(parents=True)
    (root / "lib").mkdir()
    ext = ".exe" if sys.platform.startswith("win") else ""
    for tool in gb.TOOLS:
        f = root / "bin" / f"{tool}{ext}"
        f.write_bytes(b"")
        f.chmod(0o755)
    monkeypatch.setattr(gb, "_oss_cad_suite_roots", lambda: [root])
    res = gb._resolve_toolchain()
    assert all(i["source"] == "oss-cad-suite" for i in res["tools"].values())
    env = gb._runner_env(res, "CynthionPlatformRev1D4")
    assert env["PATH"].split(gb.os.pathsep)[:2] == [str(root / "bin"), str(root / "lib")]
    assert env["YOSYS"].lower().startswith(str(root).lower())
    assert env["LUNA_PLATFORM"] == "cynthion.gateware.platform:CynthionPlatformRev1D4"


def test_toolchain_amaranth_env_script_counts_as_ready(no_toolchain, monkeypatch):
    monkeypatch.setenv("AMARANTH_ENV_TRELLIS", r"C:\somewhere\env.bat")
    st = gb.toolchain_status(probe_versions=False)
    assert st["ready"] is True and "note" in st


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------


def test_build_missing_source(tmp_path):
    with pytest.raises(common.InvalidArgumentError, match="not found"):
        gb.build_gateware(str(tmp_path / "nope.py"), elaborate_only=True)


def test_build_empty_source():
    with pytest.raises(common.InvalidArgumentError):
        gb.build_gateware("  ", elaborate_only=True)


def test_build_non_python_source(tmp_path):
    f = tmp_path / "design.v"
    f.write_text("module x; endmodule")
    with pytest.raises(common.InvalidArgumentError, match=r"\.py"):
        gb.build_gateware(str(f), elaborate_only=True)


@pytest.mark.parametrize("rev", ["r9.9", "banana", "2.0"])
def test_build_unknown_revision(rev):
    with pytest.raises(common.InvalidArgumentError, match="revision"):
        gb.build_gateware(str(BLINKY), platform_revision=rev, elaborate_only=True)


@pytest.mark.parametrize(
    "text,expected",
    [(None, (1, 4)), ("r1.4", (1, 4)), ("1.3", (1, 3)), ("1d2", (1, 2)),
     ("CynthionPlatformRev1D0", (1, 0)), ("rev0.6", (0, 6))],
)
def test_normalize_revision(text, expected):
    assert gb.normalize_revision(text) == expected


def test_build_invalid_top_identifier():
    with pytest.raises(common.InvalidArgumentError, match="identifier"):
        gb.build_gateware(str(BLINKY), top="not valid!", elaborate_only=True)


def test_build_bad_timeout():
    with pytest.raises(common.InvalidArgumentError, match="timeout"):
        gb.build_gateware(str(BLINKY), timeout_s=0, elaborate_only=True)


def test_extra_args_normalisation():
    assert gb._normalize_overrides(None) == {}
    assert gb._normalize_overrides({"nextpnr_opts": "--seed 3"}) == {"nextpnr_opts": "--seed 3"}
    assert gb._normalize_overrides(["synth_opts=-abc9", "verbose=1"]) == {"synth_opts": "-abc9", "verbose": "1"}
    assert gb._normalize_overrides('{"debug_verilog": true}') == {"debug_verilog": True}
    with pytest.raises(common.InvalidArgumentError, match="fixed by the Cynthion platform"):
        gb._normalize_overrides({"ecppack_opts": "--compress"})
    with pytest.raises(common.InvalidArgumentError):
        gb._normalize_overrides({"do_program": True})
    with pytest.raises(common.InvalidArgumentError):
        gb._normalize_overrides(["noequals"])


def test_build_name_sanitised():
    assert gb._sanitize_name("my-design v2") == "my_design_v2"
    assert gb._sanitize_name("1st") == "design_1st"


# ---------------------------------------------------------------------------
# Top auto-detection (runner helpers, in-process: no subprocess, no toolchain)
# ---------------------------------------------------------------------------


def test_resolve_top_blinky_auto():
    mod = runner.load_module(BLINKY)
    name, inst = _resolve(mod)
    assert name == "top"
    assert type(inst).__name__ == "Blinky"


def test_resolve_top_explicit_class():
    mod = runner.load_module(BLINKY)
    name, inst = _resolve(mod, "Blinky")
    assert name == "Blinky" and hasattr(inst, "elaborate")


def test_resolve_top_single_class(tmp_path):
    p = _write(tmp_path, "single.py", """
        from amaranth import Elaboratable, Module
        class OnlyOne(Elaboratable):
            def elaborate(self, platform):
                return Module()
    """)
    name, inst = _resolve(runner.load_module(p))
    assert name == "OnlyOne"


def test_resolve_top_factory(tmp_path):
    p = _write(tmp_path, "factory.py", """
        from amaranth import Elaboratable, Module
        class Param(Elaboratable):
            def __init__(self, width):
                self.width = width
            def elaborate(self, platform):
                return Module()
        class Other(Param):
            pass
        def create_top():
            return Param(8)
    """)
    name, inst = _resolve(runner.load_module(p))
    assert name == "create_top" and inst.width == 8


def test_resolve_top_ambiguous(tmp_path):
    p = _write(tmp_path, "two.py", TWO_TOPS)
    with pytest.raises(runner.RunnerError, match="Several") as ei:
        _resolve(runner.load_module(p))
    assert ei.value.code == "INVALID_ARGUMENT"
    assert "A" in ei.value.message and "B" in ei.value.message


def test_resolve_top_unknown_name():
    mod = runner.load_module(BLINKY)
    with pytest.raises(runner.RunnerError, match="not found") as ei:
        _resolve(mod, "DoesNotExist")
    assert "Blinky" in ei.value.message


def test_resolve_top_none(tmp_path):
    p = _write(tmp_path, "empty.py", "X = 1\n")
    with pytest.raises(runner.RunnerError, match="No top-level design"):
        _resolve(runner.load_module(p))


def test_resolve_top_class_needs_args(tmp_path):
    p = _write(tmp_path, "needs.py", """
        from amaranth import Elaboratable, Module
        class Needs(Elaboratable):
            def __init__(self, width):
                pass
            def elaborate(self, platform):
                return Module()
    """)
    with pytest.raises(runner.RunnerError, match="without arguments"):
        _resolve(runner.load_module(p))


def test_load_module_syntax_error(tmp_path):
    p = _write(tmp_path, "broken.py", "def oops(:\n")
    with pytest.raises(runner.RunnerError, match="Syntax error"):
        runner.load_module(p)


def test_runner_maps_tool_not_found(no_toolchain, tmp_path):
    """In-process: amaranth's ToolNotFound becomes an UNSUPPORTED RunnerError with the hint."""
    with pytest.raises(runner.RunnerError) as ei:
        runner.run_build(str(BLINKY), None, "r1.4", str(tmp_path / "out"), "blinky", {}, False)
    assert ei.value.code == "UNSUPPORTED"
    assert "yowasp" in ei.value.hint.lower()


# ---------------------------------------------------------------------------
# build_gateware: toolchain missing / result handling
# ---------------------------------------------------------------------------


def test_build_toolchain_missing_precheck(no_toolchain, monkeypatch, tmp_path):
    def boom(*a, **k):  # the subprocess must not even be started
        raise AssertionError("runner started although the toolchain is missing")

    monkeypatch.setattr(gb, "_run_runner", boom)
    with pytest.raises(common.UnsupportedError) as ei:
        gb.build_gateware(str(BLINKY), output_dir=str(tmp_path / "out"))
    text = ei.value.format()
    assert text.startswith("[UNSUPPORTED]")
    assert "yosys" in text and "nextpnr-ecp5" in text and "ecppack" in text
    assert "pip install yowasp-yosys yowasp-nextpnr-ecp5" in text


def test_build_success_result_shape(monkeypatch, tmp_path):
    """Mock the subprocess: check how a successful runner result is reported."""
    out = tmp_path / "out"
    fake_tools = {"tools": {t: {"found": True, "path": f"/x/{t}", "source": "PATH"} for t in gb.TOOLS}}
    monkeypatch.setattr(gb, "_require_toolchain", lambda: fake_tools)
    seen = {}

    def fake_run(cmd, env, cwd, timeout, log_path, watch_dir, name, cb, **_kw):
        seen.update(cmd=cmd, env=env, name=name, timeout=timeout)
        log_path.write_text("log\n")
        res = {"ok": True, "elaborate_only": False, "name": name, "top": "top",
               "platform": "CynthionPlatformRev1D3", "revision": "r1.3",
               "output_dir": str(watch_dir), "bitstream": str(watch_dir / f"{name}.bit"),
               "size_bytes": 123, "sha256": "ab" * 32, "fmax": [], "files": [], "duration_s": 1.0}
        return 0, f"{gb.RESULT_MARKER} {json.dumps(res)}\n", ["Info: done"], False

    monkeypatch.setattr(gb, "_run_runner", fake_run)
    progress = []
    r = gb.build_gateware(str(BLINKY), platform_revision="r1.3", output_dir=str(out),
                          extra_args={"nextpnr_opts": "--seed 2"}, timeout_s=60,
                          progress_cb=lambda *a: progress.append(a))
    assert r["bitstream"].endswith("blinky.bit") and r["size_bytes"] == 123
    assert r["log_tail"] == ["Info: done"]
    assert "configure_bitstream" in r["next_step"]
    assert r["toolchain"]["yosys"]["path"] == "/x/yosys"
    assert "--revision" in seen["cmd"] and "r1.3" in seen["cmd"]
    assert json.loads(seen["cmd"][seen["cmd"].index("--overrides") + 1]) == {"nextpnr_opts": "--seed 2"}
    assert seen["env"]["YOSYS"] == "/x/yosys"
    assert progress[0][0] == 1.0 and progress[-1][0] == 100.0


@pytest.mark.parametrize(
    "code,exc",
    [("INVALID_ARGUMENT", common.InvalidArgumentError), ("UNSUPPORTED", common.UnsupportedError),
     ("BUILD_FAILED", gb.BuildError)],
)
def test_build_runner_error_mapping(monkeypatch, tmp_path, code, exc):
    monkeypatch.setattr(gb, "_require_toolchain", lambda: {"tools": {}})
    res = {"ok": False, "error": {"code": code, "message": "boom", "hint": "do X"}}
    monkeypatch.setattr(
        gb, "_run_runner",
        lambda *a, **k: (2, f"{gb.RESULT_MARKER} {json.dumps(res)}\n", ["tail line"], False),
    )
    with pytest.raises(exc) as ei:
        gb.build_gateware(str(BLINKY), output_dir=str(tmp_path / "o"))
    assert "boom" in ei.value.message and ei.value.hint == "do X"


def test_build_timeout_and_crash(monkeypatch, tmp_path):
    monkeypatch.setattr(gb, "_require_toolchain", lambda: {"tools": {}})
    monkeypatch.setattr(gb, "_run_runner", lambda *a, **k: (None, "", ["nextpnr..."], True))
    with pytest.raises(common.OperationTimeout, match="exceeded"):
        gb.build_gateware(str(BLINKY), output_dir=str(tmp_path / "o"), timeout_s=5)
    monkeypatch.setattr(gb, "_run_runner", lambda *a, **k: (1, "garbage", ["Traceback"], False))
    with pytest.raises(gb.BuildError, match="without a result"):
        gb.build_gateware(str(BLINKY), output_dir=str(tmp_path / "o"))


def test_build_busy(monkeypatch, tmp_path):
    assert gb._BUILD_LOCK.acquire(blocking=False)
    try:
        with pytest.raises(common.BusyError):
            gb.build_gateware(str(BLINKY), output_dir=str(tmp_path / "o"), elaborate_only=True)
    finally:
        gb._BUILD_LOCK.release()


# ---------------------------------------------------------------------------
# Real subprocess runs (no toolchain needed)
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_runner_subprocess_fails_fast_without_tools(no_toolchain, monkeypatch, tmp_path):
    """Bypass the parent pre-check: the runner itself must report UNSUPPORTED + hint, cleanly."""
    monkeypatch.setattr(gb, "_require_toolchain", lambda: {"tools": {}})
    with pytest.raises(common.UnsupportedError) as ei:
        gb.build_gateware(str(BLINKY), output_dir=str(tmp_path / "out"), timeout_s=120)
    assert "toolchain" in ei.value.message.lower()
    assert "yowasp" in (ei.value.hint or "").lower()


@pytest.mark.slow
def test_runner_subprocess_unknown_top(tmp_path):
    with pytest.raises(common.InvalidArgumentError, match="NoSuchTop"):
        gb.build_gateware(str(BLINKY), top="NoSuchTop", output_dir=str(tmp_path / "out"),
                          elaborate_only=True, timeout_s=120)


@pytest.mark.slow
def test_elaborate_blinky_r1_4_subprocess(tmp_path):
    """Elaboration-only through the real runner subprocess: proves the r1.4 platform wiring."""
    out = tmp_path / "blinky_build"
    progress = []
    r = gb.build_gateware(str(BLINKY), output_dir=str(out), elaborate_only=True, timeout_s=300,
                          progress_cb=lambda *a: progress.append(a))
    assert r["platform"] == "CynthionPlatformRev1D4" and r["revision"] == "r1.4"
    assert r["top"] == "top" and r["bitstream"] is None
    for f in ("blinky.il", "blinky.lpf", "blinky.ys", "build_blinky.sh", "build_blinky.bat"):
        assert f in r["files"] and (out / f).is_file()
    lpf = (out / "blinky.lpf").read_text()
    for pin in ("E13", "C13", "B14", "A15", "D12", "C11", "A8"):  # LEDs + 60 MHz clock (r1.4)
        assert f'SITE "{pin}"' in lpf
    assert "synth_ecp5" in (out / "blinky.ys").read_text()
    assert Path(r["log_path"]).is_file()
    assert any("elaborate" in (a[2] or "") for a in progress)


@pytest.mark.slow
def test_elaborate_in_process_r1_4(tmp_path):
    """Same check without subprocess, via the runner's run_build helper."""
    r = runner.run_build(str(BLINKY), None, "r1.4", str(tmp_path / "o"), "blinky", {}, True)
    assert "blinky.il" in r["files"]
    rtlil = (tmp_path / "o" / "blinky.il").read_text()
    assert "module" in rtlil


# ---------------------------------------------------------------------------
# Regression tests: extra_args strings, progress thread, cancellation, version probe env
# ---------------------------------------------------------------------------


def test_extra_args_plain_string_values_with_spaces():
    assert gb._normalize_overrides("nextpnr_opts=--seed 3") == {"nextpnr_opts": "--seed 3"}
    assert gb._normalize_overrides("synth_opts=-abc9 -nowidelut nextpnr_opts=--seed 3") == {
        "synth_opts": "-abc9 -nowidelut", "nextpnr_opts": "--seed 3"}
    assert gb._normalize_overrides("a=1, b=2; c=x y") == {"a": "1", "b": "2", "c": "x y"}
    with pytest.raises(common.InvalidArgumentError):
        gb._normalize_overrides("noequals")


def _py_cmd(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_run_runner_reports_stage_progress_from_caller_thread(tmp_path):
    import threading

    code = ("import sys\n"
            f"for s in ('load', 'platform', 'elaborate'):\n"
            f"    print({gb.STAGE_MARKER!r} + ' ' + s, file=sys.stderr, flush=True)\n"
            "import time; time.sleep(1.5)\n"
            "print('done')\n")
    calls = []
    caller = threading.current_thread()
    rc, out, tail, timed_out = gb._run_runner(
        _py_cmd(code), dict(__import__("os").environ), tmp_path, 60, tmp_path / "b.log", tmp_path, "x",
        lambda p, t, m: calls.append((p, m, threading.current_thread())),
    )
    assert rc == 0 and not timed_out and "done" in out
    stage_calls = [c for c in calls if c[1].startswith("stage:")]
    assert [c[1] for c in stage_calls] == ["stage: load", "stage: platform", "stage: elaborate"]
    assert all(c[2] is caller for c in calls)  # never from the pump threads (anyio.from_thread needs this)
    assert "elaborate" in (tmp_path / "b.log").read_text()


def test_run_runner_cancel_event_kills_build(tmp_path):
    import threading
    import time as _time

    ev = threading.Event()
    threading.Timer(0.5, ev.set).start()
    t0 = _time.monotonic()
    rc, _out, _tail, timed_out = gb._run_runner(
        _py_cmd("import time; time.sleep(60)"), dict(__import__("os").environ), tmp_path, 120,
        tmp_path / "c.log", tmp_path, "x", None, cancel_event=ev,
    )
    assert _time.monotonic() - t0 < 30 and not timed_out and rc != 0
    assert "cancelled" in (tmp_path / "c.log").read_text()
    assert not gb._ACTIVE_PROCS


def test_build_cancelled_raises(monkeypatch, tmp_path):
    import threading

    monkeypatch.setattr(gb, "_require_toolchain", lambda: {"tools": {}})
    ev = threading.Event()

    def fake_run(*a, cancel_event=None, **k):
        cancel_event.set()
        return None, "", [], False

    monkeypatch.setattr(gb, "_run_runner", fake_run)
    with pytest.raises(gb.BuildError, match="cancelled"):
        gb.build_gateware(str(BLINKY), output_dir=str(tmp_path / "o"), cancel_event=ev)
    assert gb._BUILD_LOCK.acquire(blocking=False)
    gb._BUILD_LOCK.release()


def test_probe_version_uses_extra_path(monkeypatch):
    import os

    seen = {}

    class R:
        stdout = "Yosys 0.40\n"

    def fake_run(cmd, **kw):
        seen.update(kw)
        return R()

    monkeypatch.setattr(gb.subprocess, "run", fake_run)
    assert gb._probe_version("/x/yosys", extra_path=["/oss/bin", "/oss/lib"]) == "Yosys 0.40"
    assert seen["env"]["PATH"].split(os.pathsep)[:2] == ["/oss/bin", "/oss/lib"]
