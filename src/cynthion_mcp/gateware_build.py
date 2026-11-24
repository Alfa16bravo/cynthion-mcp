"""Build custom Amaranth gateware for the Cynthion (ECP5 LFE5U-12F) into a .bit file.

Public API:
  * :func:`toolchain_status` - locate yosys / nextpnr-ecp5 / ecppack (env overrides, PATH,
    OSS CAD Suite install dirs, YoWASP) without touching hardware.
  * :func:`build_gateware` - elaborate a user design for a Cynthion platform and run the
    open-source toolchain in a **subprocess** (``cynthion_mcp.gateware_build_runner``).

Nothing here opens USB and nothing is ever written to this process' stdout (reserved for
the MCP JSON-RPC stream): the runner's stdout carries only one JSON result line, its stderr is
captured into a log file and a ring buffer.

Stdlib only at import time; amaranth / cynthion are only imported by the runner subprocess.
"""

from __future__ import annotations

import atexit
import collections
import importlib.metadata
import importlib.util
import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import sysconfig
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

from .common import (
    BusyError,
    CynthionMCPError,
    HardwareError,
    InvalidArgumentError,
    OperationTimeout,
    UnsupportedError,
    timestamp_slug,
)
from .gateware_build_runner import (
    DEFAULT_REVISION,
    INSTALL_HINT,
    RESULT_MARKER,
    STAGE_MARKER,
    RunnerError,
    parse_revision,
    platform_class_name,
)

logger = logging.getLogger("cynthion_mcp.gateware_build")

ProgressCb = Callable[[float, Optional[float], Optional[str]], None]

#: Tools required by Amaranth's Trellis flow for ECP5, with their override env var and YoWASP name.
TOOLS: dict[str, dict[str, str]] = {
    "yosys": {"env": "YOSYS", "yowasp": "yowasp-yosys", "yowasp_pkg": "yowasp-yosys"},
    "nextpnr-ecp5": {"env": "NEXTPNR_ECP5", "yowasp": "yowasp-nextpnr-ecp5", "yowasp_pkg": "yowasp-nextpnr-ecp5"},
    "ecppack": {"env": "ECPPACK", "yowasp": "yowasp-ecppack", "yowasp_pkg": "yowasp-nextpnr-ecp5"},
}
YOWASP_MODULES = {"yowasp-yosys": "yowasp_yosys", "yowasp-nextpnr-ecp5": "yowasp_nextpnr_ecp5"}

#: Amaranth sources this script (if set) before running the toolchain; bypasses tool checks.
AMARANTH_ENV_VAR = "AMARANTH_ENV_TRELLIS"

#: Overrides that the Cynthion platform sets itself (passing them again raises TypeError).
FORBIDDEN_OVERRIDES = {"ecppack_opts"}

LOG_TAIL_LINES = 40
MAX_SOURCE_SIZE = 4 * 1024 * 1024

_BUILD_LOCK = threading.Lock()


class BuildError(CynthionMCPError):
    """The toolchain or the design itself failed (not a hardware problem)."""

    code = "BUILD_FAILED"


# =============================================================================
# Toolchain discovery
# =============================================================================


def _oss_cad_suite_roots() -> list[Path]:
    """Typical OSS CAD Suite install roots (existing ones only, env override first)."""
    cands: list[Path] = []
    for var in ("OSS_CAD_SUITE", "OSS_CAD_SUITE_PATH", "OSS_CAD_SUITE_ROOT"):
        v = os.environ.get(var)
        if v:
            cands.append(Path(v).expanduser())
    home = Path.home()
    if sys.platform.startswith("win"):
        for base in (
            os.environ.get("SystemDrive", "C:") + "\\",
            str(home),
            os.environ.get("LOCALAPPDATA", ""),
            os.environ.get("ProgramFiles", ""),
            "C:\\tools",
            str(home / "Downloads"),
            str(home / "Desktop"),
        ):
            if base:
                cands.append(Path(base) / "oss-cad-suite")
    else:
        cands += [
            home / "oss-cad-suite",
            home / ".local" / "oss-cad-suite",
            home / "opt" / "oss-cad-suite",
            Path("/opt/oss-cad-suite"),
            Path("/usr/local/oss-cad-suite"),
            Path("/opt/homebrew/oss-cad-suite"),
            home / "Downloads" / "oss-cad-suite",
        ]
    out: list[Path] = []
    seen: set[str] = set()
    for c in cands:
        # Accept both the suite root and its bin directory.
        root = c.parent if c.name.lower() == "bin" else c
        key = str(root).lower()
        if key in seen:
            continue
        seen.add(key)
        if (root / "bin").is_dir():
            out.append(root)
    return out


def _scripts_dirs() -> list[str]:
    """Directories where pip puts console scripts for this interpreter (for yowasp-*)."""
    dirs = []
    for scheme in (None, "nt_user" if os.name == "nt" else "posix_user"):
        try:
            d = sysconfig.get_path("scripts", scheme) if scheme else sysconfig.get_path("scripts")
        except (KeyError, ValueError):
            continue
        if d and os.path.isdir(d) and d not in dirs:
            dirs.append(d)
    exe_dir = os.path.dirname(sys.executable)
    for d in (exe_dir, os.path.join(exe_dir, "Scripts"), os.path.join(exe_dir, "bin")):
        if os.path.isdir(d) and d not in dirs:
            dirs.append(d)
    return dirs


def _yowasp_packages() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for dist, mod in YOWASP_MODULES.items():
        try:
            importable = importlib.util.find_spec(mod) is not None
        except (ImportError, ValueError):
            importable = False
        try:
            version: str | None = importlib.metadata.version(dist)
        except importlib.metadata.PackageNotFoundError:
            version = None
        out[dist] = {"importable": importable, "version": version}
    return out


def _probe_version(path: str, timeout: float = 15.0, extra_path: list[str] | None = None) -> str | None:
    """First non-empty line of ``<tool> --version`` (None on any failure).

    ``extra_path`` is prepended to PATH (OSS CAD Suite tools need its bin/ and lib/ for their DLLs)."""
    kwargs: dict[str, Any] = {}
    if extra_path:
        env = dict(os.environ)
        env["PATH"] = os.pathsep.join(list(extra_path) + [env.get("PATH", "")])
        kwargs["env"] = env
    old_mode = None
    if sys.platform.startswith("win"):
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        # No modal "DLL not found" box from the Windows loader: the child inherits the error mode.
        try:
            import ctypes

            sem_failcriticalerrors, sem_noopenfileerrorbox = 0x0001, 0x8000
            old_mode = ctypes.windll.kernel32.SetErrorMode(sem_failcriticalerrors | sem_noopenfileerrorbox)
            ctypes.windll.kernel32.SetErrorMode(old_mode | sem_failcriticalerrors | sem_noopenfileerrorbox)
        except Exception:
            old_mode = None
    try:
        proc = subprocess.run(
            [path, "--version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
            errors="replace",
            **kwargs,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        if old_mode is not None:
            try:
                import ctypes

                ctypes.windll.kernel32.SetErrorMode(old_mode)
            except Exception:
                pass
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if line:
            return line[:200]
    return None


def _locate_tool(tool: str, oss_roots: list[Path], yowasp_pkgs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    spec = TOOLS[tool]
    env_var = spec["env"]
    info: dict[str, Any] = {"found": False, "path": None, "source": None, "env_var": env_var,
                            "extra_path": []}

    override = os.environ.get(env_var)
    if override:
        p = shutil.which(override)
        info["env_override"] = override
        if p:
            info.update(found=True, path=p, source="env")
            return info
        info["error"] = f"{env_var}={override!r} does not point to an executable"

    p = shutil.which(tool)
    if p:
        info.update(found=True, path=p, source="PATH")
        return info

    for root in oss_roots:
        p = shutil.which(tool, path=str(root / "bin"))
        if p:
            # OSS CAD Suite executables need both bin/ and lib/ on PATH (DLLs on Windows).
            extra = [str(root / "bin")]
            if (root / "lib").is_dir():
                extra.append(str(root / "lib"))
            info.update(found=True, path=p, source="oss-cad-suite", extra_path=extra)
            return info

    yname = spec["yowasp"]
    if yowasp_pkgs.get(spec["yowasp_pkg"], {}).get("importable"):
        p = shutil.which(yname) or next(
            (q for q in (shutil.which(yname, path=d) for d in _scripts_dirs()) if q), None
        )
        if p:
            info.update(found=True, path=p, source="yowasp")
            return info
    return info


def _resolve_toolchain(probe_versions: bool = False) -> dict[str, Any]:
    oss_roots = _oss_cad_suite_roots()
    yowasp = _yowasp_packages()
    tools = {t: _locate_tool(t, oss_roots, yowasp) for t in TOOLS}
    if probe_versions:
        for t, info in tools.items():
            if not info["found"]:
                info["version"] = None
            elif info["source"] == "yowasp":
                # Running a YoWASP tool the first time compiles WebAssembly (slow): use metadata.
                info["version"] = "YoWASP " + str(yowasp.get(TOOLS[t]["yowasp_pkg"], {}).get("version"))
            else:
                info["version"] = _probe_version(info["path"], extra_path=info.get("extra_path"))
    return {"tools": tools, "oss_cad_suite_roots": [str(r) for r in oss_roots], "yowasp": yowasp}


def toolchain_status(probe_versions: bool = True) -> dict[str, Any]:
    """Report which ECP5 toolchain programs can be used for :func:`build_gateware`.

    Never touches hardware. ``probe_versions`` runs ``<tool> --version`` for native tools.
    """
    res = _resolve_toolchain(probe_versions=probe_versions)
    tools = res["tools"]
    env_script = os.environ.get(AMARANTH_ENV_VAR)
    missing = [t for t, i in tools.items() if not i["found"]]
    ready = not missing or bool(env_script)
    out: dict[str, Any] = {
        "ready": ready,
        "tools": {
            t: {k: i.get(k) for k in ("found", "path", "source", "version", "env_var", "env_override", "error")
                if k in i}
            for t, i in tools.items()
        },
        "missing": missing,
        "yowasp": res["yowasp"],
        "oss_cad_suite_roots": res["oss_cad_suite_roots"],
        "amaranth_env_script": env_script,
        "python": sys.executable,
    }
    if env_script and missing:
        out["note"] = (f"{AMARANTH_ENV_VAR} is set; Amaranth will source it before building, "
                       "so tool lookup is delegated to that script.")
    if not ready:
        out["hint"] = INSTALL_HINT
    return out


def _require_toolchain() -> dict[str, Any]:
    """Return the resolved tools or raise UnsupportedError with the install hint."""
    res = _resolve_toolchain(probe_versions=False)
    missing = [t for t, i in res["tools"].items() if not i["found"]]
    if missing and not os.environ.get(AMARANTH_ENV_VAR):
        details = "; ".join(
            f"{t}: {res['tools'][t].get('error') or 'not found'}" for t in missing
        )
        raise UnsupportedError(f"FPGA toolchain not available ({details}).", INSTALL_HINT)
    return res


# =============================================================================
# Argument handling
# =============================================================================

_NAME_RE = re.compile(r"[^A-Za-z0-9_]")


def _available_revisions() -> list[tuple[int, int]]:
    """Revisions for which the installed cynthion package has a platform file (no import)."""
    revs: list[tuple[int, int]] = []
    try:
        spec = importlib.util.find_spec("cynthion")
    except (ImportError, ValueError):
        spec = None
    for loc in (spec.submodule_search_locations or []) if spec else []:
        pdir = Path(loc) / "gateware" / "platform"
        for f in pdir.glob("cynthion_r*_*.py"):
            m = re.match(r"cynthion_r(\d+)_(\d+)\.py$", f.name)
            if m:
                revs.append((int(m.group(1)), int(m.group(2))))
    return sorted(set(revs))


def normalize_revision(platform_revision: str | None) -> tuple[int, int]:
    """Parse and validate a revision string; default is r1.4."""
    try:
        rev = parse_revision(platform_revision)
    except RunnerError as exc:
        raise InvalidArgumentError(exc.message) from exc
    known = _available_revisions()
    if known and rev not in known:
        raise InvalidArgumentError(
            f"Unknown Cynthion revision r{rev[0]}.{rev[1]}. Available: "
            + ", ".join(f"r{a}.{b}" for a, b in known)
        )
    return rev


def _resolve_source(source: str) -> Path:
    if source is None or not str(source).strip():
        raise InvalidArgumentError("source is empty: give the path of a Python file defining the design")
    p = Path(os.path.expandvars(str(source).strip().strip('"'))).expanduser()
    try:
        p = p.resolve()
    except OSError as exc:
        raise InvalidArgumentError(f"Invalid source path {source!r}: {exc}") from exc
    if not p.exists():
        raise InvalidArgumentError(f"Design source file not found: {p}")
    if not p.is_file():
        raise InvalidArgumentError(f"Design source is not a file: {p}")
    if p.stat().st_size > MAX_SOURCE_SIZE:
        raise InvalidArgumentError(f"Design source is too large (> {MAX_SOURCE_SIZE} bytes): {p}")
    return p


def _sanitize_name(stem: str) -> str:
    name = _NAME_RE.sub("_", stem).strip("_") or "top"
    if name[0].isdigit():
        name = "design_" + name
    return name[:64]


_OVERRIDE_SPLIT_RE = re.compile(r"[;\r\n]+|[\s,]+(?=[A-Za-z_][A-Za-z0-9_]*=)")


def _split_override_string(text: str) -> list[str]:
    """Split a non-JSON 'k=v k2=v2' string. Values may contain spaces ('nextpnr_opts=--seed 3'): a new entry
    starts only after ';', a newline, or whitespace/comma followed by 'identifier='. A leading piece without
    '=' is kept as is (and rejected later); later pieces without '=' cannot occur by construction."""
    parts = [p.strip().strip(",").strip() for p in _OVERRIDE_SPLIT_RE.split(text)]
    return [p for p in parts if p]


def _normalize_overrides(extra_args: Any) -> dict[str, Any]:
    """Accept a dict, a JSON object string, or an iterable of 'key=value' strings."""
    if extra_args is None or extra_args == "" or extra_args == [] or extra_args == {}:
        return {}
    if isinstance(extra_args, str):
        try:
            parsed = json.loads(extra_args)
        except json.JSONDecodeError:
            parsed = _split_override_string(extra_args)
        extra_args = parsed
    if isinstance(extra_args, Mapping):
        items = list(extra_args.items())
    elif isinstance(extra_args, Iterable):
        items = []
        for entry in extra_args:
            if not isinstance(entry, str) or "=" not in entry:
                raise InvalidArgumentError(
                    f"extra_args entry {entry!r} must be 'key=value' (e.g. 'nextpnr_opts=--seed 3')"
                )
            k, v = entry.split("=", 1)
            items.append((k.strip(), v.strip()))
    else:
        raise InvalidArgumentError("extra_args must be a dict, a JSON object or a list of 'key=value' strings")

    out: dict[str, Any] = {}
    for k, v in items:
        if not isinstance(k, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
            raise InvalidArgumentError(f"Invalid override name {k!r}")
        if k in FORBIDDEN_OVERRIDES:
            raise InvalidArgumentError(
                f"Override {k!r} is fixed by the Cynthion platform (--compress --freq 38.8) and cannot be changed."
            )
        if k in ("name", "build_dir", "do_build", "do_program", "program_opts"):
            raise InvalidArgumentError(f"{k!r} is controlled by build_gateware itself")
        if not isinstance(v, (str, int, float, bool)) and not (
            isinstance(v, list) and all(isinstance(x, str) for x in v)
        ):
            raise InvalidArgumentError(f"Override {k!r}: value must be a string, number, bool or list of strings")
        out[k] = v
    return out


def _default_output_dir(name: str) -> Path:
    base = os.environ.get("CYNTHION_MCP_OUTPUT_DIR") or (Path.home() / "cynthion_mcp")
    return Path(base).expanduser() / "gateware_builds" / f"{name}_{timestamp_slug()}"


def _resolve_output_dir(output_dir: str | None, name: str) -> Path:
    if output_dir is None or not str(output_dir).strip():
        p = _default_output_dir(name)
    else:
        p = Path(os.path.expandvars(str(output_dir).strip().strip('"'))).expanduser()
    try:
        p = p.resolve()
    except OSError as exc:
        raise InvalidArgumentError(f"Invalid output directory {output_dir!r}: {exc}") from exc
    if p.exists() and not p.is_dir():
        raise InvalidArgumentError(f"Output path exists and is not a directory: {p}")
    try:
        p.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise InvalidArgumentError(f"Cannot create output directory {p}: {exc}") from exc
    return p


# =============================================================================
# Subprocess plumbing
# =============================================================================


def _runner_env(toolchain: dict[str, Any] | None, plat_name: str) -> dict[str, str]:
    env = dict(os.environ)
    src_root = str(Path(__file__).resolve().parent.parent)
    env["PYTHONPATH"] = src_root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["LUNA_PLATFORM"] = f"cynthion.gateware.platform:{plat_name}"
    # Amaranth runs `cmd /c call build_<name>.bat` in the build dir without a
    # ".\" prefix.  With NoDefaultCurrentDirectoryInExePath set (Claude Code and
    # some hardened shells set it), cmd.exe no longer searches the current
    # directory and the build fails with "'build_x.bat' is not recognized".
    # Only this build subprocess is affected.
    for key in [k for k in env if k.lower() == "nodefaultcurrentdirectoryinexepath"]:
        del env[key]
    if toolchain:
        extra: list[str] = []
        for tool, info in toolchain["tools"].items():
            if info.get("found"):
                env[TOOLS[tool]["env"]] = info["path"]
                for d in info.get("extra_path") or []:
                    if d not in extra:
                        extra.append(d)
        if extra:
            env["PATH"] = os.pathsep.join(extra + [env.get("PATH", "")])
    return env


# Runner processes currently alive (killed on cancel and at server exit).
_ACTIVE_PROCS: set[subprocess.Popen] = set()
_ACTIVE_LOCK = threading.Lock()


def _kill_active_builds() -> None:
    """atexit hook: never leave a detached runner (and its yosys/nextpnr children) behind the server."""
    with _ACTIVE_LOCK:
        procs = list(_ACTIVE_PROCS)
    for proc in procs:
        try:
            _kill_tree(proc)
        except Exception:  # noqa: BLE001 - best effort at shutdown
            pass


atexit.register(_kill_active_builds)


def _windows_kill_on_close_job(proc: subprocess.Popen) -> Any:
    """Windows: put the runner in a Job object with KILL_ON_JOB_CLOSE so the whole tree dies with the server
    process, even when it crashes (the OS then closes the job handle). Returns the handle or None."""
    if not sys.platform.startswith("win"):
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class _IoCounters(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class _BasicLimits(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class _ExtendedLimits(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", _BasicLimits), ("IoInfo", _IoCounters),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        handle = getattr(proc, "_handle", None)
        if handle is None:
            return None
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        job = k32.CreateJobObjectW(None, None)
        if not job:
            return None
        info = _ExtendedLimits()
        info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        ok = k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))  # extended limits
        if ok:
            ok = k32.AssignProcessToJobObject(job, int(handle))
        if not ok:
            k32.CloseHandle(job)
            return None
        return job
    except Exception:  # noqa: BLE001 - optional hardening
        return None


def _close_job(job: Any) -> None:
    """Close the job handle (kills whatever the runner left behind in it)."""
    if job is None:
        return
    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle(job)
    except Exception:  # noqa: BLE001
        pass


def _kill_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if sys.platform.startswith("win"):
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except Exception:  # noqa: BLE001 - fall back to killing the direct child
        pass
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover
        pass


_STAGE_PROGRESS = {"load": 2, "platform": 4, "top": 6, "elaborate": 10, "build": 10, "done": 100}
_FILE_STAGES = (  # (file suffix produced, progress %, message)
    (".il", 15, "RTLIL written, running yosys synthesis"),
    (".json", 45, "Synthesis done, running nextpnr-ecp5 place & route"),
    (".config", 90, "Place & route done, running ecppack"),
    (".bit", 98, "Bitstream written"),
)


def _run_runner(
    cmd: list[str],
    env: dict[str, str],
    cwd: Path,
    timeout_s: float,
    log_path: Path,
    watch_dir: Path,
    name: str,
    progress_cb: ProgressCb | None,
    cancel_event: threading.Event | None = None,
) -> tuple[int | None, str, list[str], bool]:
    """Run the runner; returns (returncode, stdout_text, stderr_lines_tail, timed_out).

    Progress is only reported from THIS thread (the caller's worker thread): the server's progress callback
    uses anyio.from_thread.run, which fails from the plain pump threads. Setting ``cancel_event`` kills the
    process tree within ~1 s (the caller checks the event afterwards)."""
    kwargs: dict[str, Any] = {}
    if sys.platform.startswith("win"):
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0
        )
    else:
        kwargs["start_new_session"] = True

    tail: collections.deque[str] = collections.deque(maxlen=400)
    stdout_chunks: list[str] = []
    state: dict[str, Any] = {"pct": 0.0}
    stages: collections.deque[str] = collections.deque()  # filled by pump_stderr, reported by the poll loop
    log_lock = threading.Lock()
    log_closed = [False]

    def report(pct: float, msg: str) -> None:
        if pct <= state["pct"]:
            return
        state["pct"] = pct
        logger.info("build %s: %s", name, msg)
        if progress_cb is not None:
            try:
                progress_cb(float(pct), 100.0, msg)
            except Exception:  # noqa: BLE001 - progress is best effort
                pass

    def report_stages() -> None:
        while stages:
            stage = stages.popleft()
            report(_STAGE_PROGRESS.get(stage, state["pct"]), f"stage: {stage}")

    proc = subprocess.Popen(
        cmd, cwd=str(cwd), env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, **kwargs,
    )
    job = _windows_kill_on_close_job(proc)
    with _ACTIVE_LOCK:
        _ACTIVE_PROCS.add(proc)

    try:
        with open(log_path, "w", encoding="utf-8", errors="replace") as log_file:

            def log_write(text: str) -> None:
                # A pump may outlive the join below (a grandchild still holding the pipe): never write to
                # the closed log file.
                with log_lock:
                    if not log_closed[0]:
                        log_file.write(text)
                        log_file.flush()

            def pump_stderr() -> None:
                assert proc.stderr is not None
                for raw in iter(proc.stderr.readline, b""):
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    log_write(line + "\n")
                    if line.startswith(STAGE_MARKER):
                        # Only queued here: report() must run in the caller's (AnyIO worker) thread.
                        stages.append(line[len(STAGE_MARKER):].strip())
                        continue
                    tail.append(line)

            def pump_stdout() -> None:
                assert proc.stdout is not None
                stdout_chunks.append(proc.stdout.read().decode("utf-8", errors="replace"))

            threads = [threading.Thread(target=pump_stderr, daemon=True),
                       threading.Thread(target=pump_stdout, daemon=True)]
            for t in threads:
                t.start()

            start = time.monotonic()
            t_start_wall = time.time()
            timed_out = False
            cancelled = False
            while True:
                try:
                    proc.wait(timeout=1.0)
                    break
                except subprocess.TimeoutExpired:
                    pass
                report_stages()
                for suffix, pct, msg in _FILE_STAGES:
                    f = watch_dir / f"{name}{suffix}"
                    try:
                        if f.is_file() and f.stat().st_mtime >= t_start_wall - 1:
                            report(pct, msg)
                    except OSError:
                        pass
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    _kill_tree(proc)
                    break
                if time.monotonic() - start > timeout_s:
                    timed_out = True
                    _kill_tree(proc)
                    break
            for t in threads:
                t.join(timeout=5)
            report_stages()
            if timed_out:
                log_write(f"*** build killed after {timeout_s:.0f} s timeout ***\n")
            if cancelled:
                log_write("*** build cancelled ***\n")
            with log_lock:
                log_closed[0] = True
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE_PROCS.discard(proc)
        _close_job(job)

    return proc.returncode, "".join(stdout_chunks), list(tail), timed_out


def _parse_result(stdout_text: str) -> dict[str, Any] | None:
    for line in reversed(stdout_text.splitlines()):
        if line.startswith(RESULT_MARKER):
            try:
                value = json.loads(line[len(RESULT_MARKER):].strip())
            except json.JSONDecodeError:
                return None
            return value if isinstance(value, dict) else None
    return None


_ERROR_CLASSES: dict[str, type[CynthionMCPError]] = {
    "INVALID_ARGUMENT": InvalidArgumentError,
    "UNSUPPORTED": UnsupportedError,
    "TIMEOUT": OperationTimeout,
    "BUILD_FAILED": BuildError,
    "HARDWARE": HardwareError,
}


def _tail_text(lines: list[str], n: int = 25) -> str:
    return "\n".join(lines[-n:])


# =============================================================================
# Public: build
# =============================================================================


def build_gateware(
    source: str,
    top: str | None = None,
    platform_revision: str | None = None,
    output_dir: str | None = None,
    timeout_s: float = 1800,
    extra_args: Any = None,
    progress_cb: ProgressCb | None = None,
    *,
    name: str | None = None,
    elaborate_only: bool = False,
    progress: ProgressCb | None = None,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Build an Amaranth design for the Cynthion into a ``.bit`` bitstream (never touches hardware).

    ``source``: path to a Python file defining the design. ``top``: attribute name (class,
    instance or zero-arg factory); default auto-detects ``top``/``Top``/``create_top()`` or the
    single Elaboratable subclass. ``platform_revision``: e.g. 'r1.4' (default r1.4).
    ``extra_args``: Amaranth toolchain overrides, as a dict / JSON object / ['key=value', ...]
    (e.g. ``{"nextpnr_opts": "--seed 2", "synth_opts": "-abc9", "verbose": true}``).
    ``elaborate_only``: only elaborate and write the build plan (RTLIL, LPF, scripts); no
    toolchain needed. ``progress`` is an alias of ``progress_cb`` (server ``_hw`` convention).
    ``cancel_event``: set it (from any thread) to kill the running build's process tree (BuildError).
    """
    cb = progress_cb or progress
    src = _resolve_source(source)
    if src.suffix.lower() != ".py":
        raise InvalidArgumentError(f"Design source must be a Python (.py) file: {src}")
    try:
        timeout = float(timeout_s)
    except (TypeError, ValueError) as exc:
        raise InvalidArgumentError(f"timeout_s must be a number, got {timeout_s!r}") from exc
    if not (1 <= timeout <= 6 * 3600):
        raise InvalidArgumentError("timeout_s must be between 1 and 21600 seconds")
    if top is not None:
        top = str(top).strip() or None
        if top is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", top):
            raise InvalidArgumentError(f"top must be a Python identifier, got {top!r}")
    major, minor = normalize_revision(platform_revision)
    plat_name = platform_class_name(major, minor)
    overrides = _normalize_overrides(extra_args)
    build_name = _sanitize_name(name or src.stem)

    toolchain = None if elaborate_only else _require_toolchain()

    if not _BUILD_LOCK.acquire(blocking=False):
        raise BusyError("Another gateware build is already running; wait for it to finish.")
    try:
        out_dir = _resolve_output_dir(output_dir, build_name)
        log_path = out_dir / f"build_{build_name}.log"
        cmd = [
            sys.executable, "-m", "cynthion_mcp.gateware_build_runner",
            "--source", str(src),
            "--revision", f"r{major}.{minor}",
            "--output-dir", str(out_dir),
            "--name", build_name,
        ]
        if top:
            cmd += ["--top", top]
        if overrides:
            cmd += ["--overrides", json.dumps(overrides)]
        if elaborate_only:
            cmd.append("--elaborate-only")

        if cb is not None:
            try:
                cb(1.0, 100.0, f"Starting {'elaboration' if elaborate_only else 'build'} of {src.name} for {plat_name}")
            except Exception:  # noqa: BLE001
                pass

        t0 = time.monotonic()
        try:
            rc, stdout_text, tail, timed_out = _run_runner(
                cmd, _runner_env(toolchain, plat_name), src.parent, timeout, log_path, out_dir,
                build_name, cb, cancel_event=cancel_event,
            )
        except OSError as exc:
            raise BuildError(f"Could not start the build subprocess: {exc}") from exc
        duration = round(time.monotonic() - t0, 3)

        if cancel_event is not None and cancel_event.is_set():
            raise BuildError(f"Gateware build cancelled; the build process tree was killed. Log: {log_path}")

        if timed_out:
            raise OperationTimeout(
                f"Gateware build exceeded {timeout:.0f} s and was killed. Log: {log_path}\n"
                f"Last log lines:\n{_tail_text(tail)}",
                "Increase timeout_s, or simplify the design.",
            )

        result = _parse_result(stdout_text)
        if result is None:
            raise BuildError(
                f"Build subprocess exited with code {rc} without a result. Log: {log_path}\n"
                f"Last log lines:\n{_tail_text(tail)}"
            )
        if not result.get("ok"):
            err = result.get("error") or {}
            code = str(err.get("code") or "BUILD_FAILED")
            cls = _ERROR_CLASSES.get(code, BuildError)
            msg = str(err.get("message") or "Unknown build error")
            if code in ("BUILD_FAILED",) or (code == "UNSUPPORTED" and tail):
                msg += f"\nLog: {log_path}\nLast log lines:\n{_tail_text(tail)}"
            raise cls(msg, err.get("hint"))

        result.pop("ok", None)
        result.update(
            {
                "source": str(src),
                "log_path": str(log_path),
                "log_tail": tail[-LOG_TAIL_LINES:],
                "total_duration_s": duration,
                "overrides": overrides,
            }
        )
        if toolchain is not None:
            result["toolchain"] = {t: {"path": i.get("path"), "source": i.get("source")}
                                   for t, i in toolchain["tools"].items()}
        if result.get("bitstream"):
            result["next_step"] = (
                f"Load it into FPGA SRAM with configure_bitstream(path={result['bitstream']!r}) "
                "(volatile; reconfigure_fpga() restores the flash gateware)."
            )
        if cb is not None:
            try:
                cb(100.0, 100.0, "Done")
            except Exception:  # noqa: BLE001
                pass
        return result
    finally:
        _BUILD_LOCK.release()


__all__ = [
    "BuildError", "TOOLS", "toolchain_status", "build_gateware", "normalize_revision",
    "DEFAULT_REVISION", "INSTALL_HINT",
]
