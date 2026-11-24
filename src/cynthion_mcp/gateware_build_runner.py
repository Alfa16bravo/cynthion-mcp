"""Subprocess entry point that elaborates / builds an Amaranth design for a Cynthion platform.

Run by :func:`cynthion_mcp.gateware_build.build_gateware` as
``python -m cynthion_mcp.gateware_build_runner --source design.py ...`` so that a crash, a
hang or noisy output from the user's design or from the FPGA toolchain never reaches the MCP
server process.

Output protocol:
  * everything human-readable (Amaranth / toolchain output, user prints, stage markers) goes to
    **stderr**; file descriptor 1 is redirected to stderr at startup, so even the toolchain
    subprocesses spawned by Amaranth cannot write to the real stdout;
  * stage markers are stderr lines of the form ``@@STAGE@@ <name>``;
  * the single final result is written to the *original* stdout as one line
    ``@@RESULT@@ {json}``. On failure the JSON is ``{"ok": false, "error": {...}}``.

This module never opens USB: ``platform.build`` is always called with ``do_program=False``
and ``LUNA_PLATFORM`` is forced so that LUNA helpers never probe for a connected board.

Pure helpers (``resolve_top``, ``platform_class_name``, ``parse_revision``) are importable
without side effects and are unit-tested directly.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import inspect
import json
import os
import re
import sys
import time
import traceback
from pathlib import Path
from typing import Any

RESULT_MARKER = "@@RESULT@@"
STAGE_MARKER = "@@STAGE@@"

#: Names looked up (in order) when no explicit ``top`` is given.
DEFAULT_TOP_NAMES = ("top", "Top", "create_top", "make_top")

#: Default board revision (newest Cynthion platform shipped with cynthion 0.2.x).
DEFAULT_REVISION = (1, 4)

INSTALL_HINT = (
    "Install the open-source ECP5 toolchain: either the OSS CAD Suite "
    "(https://github.com/YosysHQ/oss-cad-suite-build/releases, put its 'bin' directory on PATH "
    "or set OSS_CAD_SUITE to its root), or the pure-Python YoWASP builds: "
    "`pip install yowasp-yosys yowasp-nextpnr-ecp5`. Individual tools can also be pointed to "
    "with the YOSYS, NEXTPNR_ECP5 and ECPPACK environment variables."
)


class RunnerError(Exception):
    """Error with a stable code, serialised in the JSON result."""

    def __init__(self, code: str, message: str, hint: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.hint = hint


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------

_REV_RE = re.compile(
    r"^\s*(?:cynthion\s*)?(?:cynthionplatformrev|rev|r)?\s*(\d+)\s*(?:[.d_,]|\s)\s*(\d+)\s*$",
    re.IGNORECASE,
)


def parse_revision(value: str | None) -> tuple[int, int]:
    """Parse 'r1.4', '1.4', '1d4', 'rev1.4', 'CynthionPlatformRev1D4' into (1, 4)."""
    if value is None or not str(value).strip():
        return DEFAULT_REVISION
    m = _REV_RE.match(str(value))
    if not m:
        raise RunnerError(
            "INVALID_ARGUMENT",
            f"Invalid platform revision {value!r} (expected e.g. 'r1.4', '1.4' or 'CynthionPlatformRev1D4').",
        )
    return int(m.group(1)), int(m.group(2))


def platform_class_name(major: int, minor: int) -> str:
    return f"CynthionPlatformRev{major}D{minor}"


def _is_elaboratable_class(obj: Any) -> bool:
    if not inspect.isclass(obj):
        return False
    try:
        from amaranth.hdl import Elaboratable  # lazy
    except Exception:  # pragma: no cover - amaranth always present with cynthion
        Elaboratable = None  # type: ignore[assignment]
    if Elaboratable is not None and issubclass(obj, Elaboratable):
        return obj is not Elaboratable and not inspect.isabstract(obj)
    return callable(getattr(obj, "elaborate", None))


def _is_elaboratable_instance(obj: Any) -> bool:
    return not inspect.isclass(obj) and callable(getattr(obj, "elaborate", None))


def module_candidates(module: Any) -> list[str]:
    """Elaboratable classes defined in ``module`` itself (not imported ones)."""
    out = []
    for name, obj in vars(module).items():
        if name.startswith("_"):
            continue
        if _is_elaboratable_class(obj) and getattr(obj, "__module__", None) == module.__name__:
            out.append(name)
    return out


def _instantiate(name: str, obj: Any) -> Any:
    """Turn a top attribute (instance / class / factory function) into an elaboratable instance."""
    if _is_elaboratable_instance(obj):
        return obj
    if _is_elaboratable_class(obj):
        try:
            return obj()
        except TypeError as exc:
            raise RunnerError(
                "INVALID_ARGUMENT",
                f"Top class {name!r} cannot be instantiated without arguments: {exc}",
                "Expose a zero-argument factory, e.g. `def create_top(): return MyTop(param=...)`, "
                "and pass top='create_top'.",
            ) from exc
    if callable(obj):
        try:
            result = obj()
        except TypeError as exc:
            raise RunnerError(
                "INVALID_ARGUMENT", f"Top factory {name!r} must be callable without arguments: {exc}"
            ) from exc
        if _is_elaboratable_instance(result):
            return result
        raise RunnerError(
            "INVALID_ARGUMENT",
            f"Top factory {name!r} returned {type(result).__name__}, not an Amaranth Elaboratable.",
        )
    raise RunnerError(
        "INVALID_ARGUMENT",
        f"{name!r} is a {type(obj).__name__}, not an Elaboratable class, instance or factory function.",
    )


def resolve_top(module: Any, top: str | None = None) -> tuple[str, Any]:
    """Find the top-level elaboratable in ``module``.

    Returns ``(resolved_name, elaboratable_instance)``. Resolution order without ``top``:
    module-level ``top`` / ``Top`` / ``create_top()`` / ``make_top()``, then the single
    Elaboratable subclass defined in the module.
    """
    if top is not None and str(top).strip():
        name = str(top).strip()
        if not hasattr(module, name):
            cands = module_candidates(module)
            raise RunnerError(
                "INVALID_ARGUMENT",
                f"Top {name!r} not found in {getattr(module, '__file__', module.__name__)}. "
                f"Elaboratable classes defined there: {cands or 'none'}.",
            )
        return name, _instantiate(name, getattr(module, name))

    for name in DEFAULT_TOP_NAMES:
        if hasattr(module, name):
            return name, _instantiate(name, getattr(module, name))

    cands = module_candidates(module)
    if len(cands) == 1:
        return cands[0], _instantiate(cands[0], getattr(module, cands[0]))
    if not cands:
        raise RunnerError(
            "INVALID_ARGUMENT",
            "No top-level design found: define a module-level `top` (class, instance or factory), "
            "`create_top()`, or exactly one amaranth Elaboratable subclass, or pass top='Name'.",
        )
    raise RunnerError(
        "INVALID_ARGUMENT",
        f"Several Elaboratable classes found ({', '.join(cands)}); pass top='<name>' to choose one.",
    )


def load_module(source: str | os.PathLike) -> Any:
    """Import a user Python file as a fresh module (its directory is put on sys.path)."""
    path = Path(source).resolve()
    if not path.is_file():
        raise RunnerError("INVALID_ARGUMENT", f"Design source file not found: {path}")
    if str(path.parent) not in sys.path:
        sys.path.insert(0, str(path.parent))
    mod_name = "cynthion_user_design_" + re.sub(r"\W", "_", path.stem)
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    if spec is None or spec.loader is None:
        raise RunnerError("INVALID_ARGUMENT", f"Cannot import {path} as a Python module.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    except SyntaxError as exc:
        raise RunnerError("INVALID_ARGUMENT", f"Syntax error in {path}: {exc}") from exc
    except RunnerError:
        raise
    except Exception as exc:
        raise RunnerError(
            "INVALID_ARGUMENT", f"Importing {path} failed: {type(exc).__name__}: {exc}"
        ) from exc
    return module


def get_platform_class(major: int, minor: int) -> type:
    import cynthion.gateware.platform as plat_mod  # lazy (pulls in amaranth + luna)

    name = platform_class_name(major, minor)
    cls = getattr(plat_mod, name, None)
    if cls is None:
        known = sorted(n for n in dir(plat_mod) if n.startswith("CynthionPlatformRev"))
        raise RunnerError(
            "INVALID_ARGUMENT",
            f"Unknown Cynthion revision r{major}.{minor} (no {name}). Known: {', '.join(known)}.",
        )
    return cls


# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------


def _stage(name: str) -> None:
    sys.stderr.write(f"{STAGE_MARKER} {name}\n")
    sys.stderr.flush()


def _fmax_lines(tim_path: Path, limit: int = 12) -> list[str]:
    """Extract 'Max frequency for clock ...' lines (last pass) from a nextpnr log."""
    try:
        lines = tim_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    hits = [ln.split("Info:", 1)[-1].strip() for ln in lines if "Max frequency for clock" in ln]
    return hits[-limit:]


def run_build(
    source: str,
    top: str | None,
    revision: str | None,
    output_dir: str,
    name: str,
    overrides: dict[str, Any],
    elaborate_only: bool,
) -> dict[str, Any]:
    t0 = time.monotonic()
    major, minor = parse_revision(revision)
    plat_name = platform_class_name(major, minor)
    # Make sure no LUNA helper ever probes USB to guess the platform.
    os.environ["LUNA_PLATFORM"] = f"cynthion.gateware.platform:{plat_name}"

    _stage("load")
    module = load_module(source)

    _stage("platform")
    platform = get_platform_class(major, minor)()

    _stage("top")
    top_name, elaboratable = resolve_top(module, top)

    out = Path(output_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    if elaborate_only:
        _stage("elaborate")
        plan = platform.build(elaboratable, name=name, build_dir=str(out), do_build=False,
                              do_program=False, **overrides)
        plan.extract(str(out))
        files = sorted(plan.files)
        return {
            "ok": True,
            "elaborate_only": True,
            "name": name,
            "top": top_name,
            "platform": plat_name,
            "revision": f"r{major}.{minor}",
            "output_dir": str(out),
            "files": files,
            "bitstream": None,
            "duration_s": round(time.monotonic() - t0, 3),
        }

    _stage("build")
    from amaranth._toolchain import ToolNotFound  # lazy

    try:
        platform.build(elaboratable, name=name, build_dir=str(out), do_build=True,
                       do_program=False, **overrides)
    except ToolNotFound as exc:
        # Never elaborated: avoid a spurious amaranth UnusedElaboratable warning in the log.
        try:
            elaboratable._MustUse__silence = True
        except Exception:  # noqa: BLE001
            pass
        raise RunnerError("UNSUPPORTED", f"FPGA toolchain not found: {exc}", INSTALL_HINT) from exc
    except Exception as exc:
        import subprocess

        if isinstance(exc, subprocess.CalledProcessError):
            raise RunnerError(
                "BUILD_FAILED",
                f"Toolchain step failed (exit code {exc.returncode}); see the build log.",
            ) from exc
        if isinstance(exc, FileNotFoundError):
            raise RunnerError("UNSUPPORTED", f"FPGA toolchain executable not found: {exc}", INSTALL_HINT) from exc
        raise

    bit = out / f"{name}.bit"
    if not bit.is_file():
        raise RunnerError("BUILD_FAILED", f"The toolchain finished but {bit} was not produced.")
    data = bit.read_bytes()
    _stage("done")
    return {
        "ok": True,
        "elaborate_only": False,
        "name": name,
        "top": top_name,
        "platform": plat_name,
        "revision": f"r{major}.{minor}",
        "output_dir": str(out),
        "bitstream": str(bit),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "fmax": _fmax_lines(out / f"{name}.tim"),
        "files": sorted(p.name for p in out.iterdir() if p.is_file()),
        "duration_s": round(time.monotonic() - t0, 3),
    }


def _parse_overrides(text: str | None) -> dict[str, Any]:
    if not text:
        return {}
    value = json.loads(text)
    if not isinstance(value, dict):
        raise RunnerError("INVALID_ARGUMENT", "--overrides must be a JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    # Keep the real stdout for the final JSON line only; everything else (including child
    # processes spawned by amaranth, which inherit fd 1) goes to stderr.
    try:
        result_fd = os.dup(1)
        os.dup2(2, 1)
        result_stream = os.fdopen(result_fd, "w", encoding="utf-8", newline="\n")
    except OSError:  # pragma: no cover - exotic environments without real fds
        result_stream = sys.stdout
    sys.stdout = sys.stderr

    ap = argparse.ArgumentParser(prog="cynthion_mcp.gateware_build_runner")
    ap.add_argument("--source", required=True)
    ap.add_argument("--top", default=None)
    ap.add_argument("--revision", default=None)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--name", default="top")
    ap.add_argument("--overrides", default=None, help="JSON object of Amaranth toolchain overrides")
    ap.add_argument("--elaborate-only", action="store_true")
    args = ap.parse_args(argv)

    try:
        result = run_build(
            args.source, args.top, args.revision, args.output_dir, args.name,
            _parse_overrides(args.overrides), args.elaborate_only,
        )
        code = 0
    except RunnerError as exc:
        result = {"ok": False, "error": {"code": exc.code, "message": exc.message, "hint": exc.hint}}
        code = 2
    except BaseException as exc:  # noqa: BLE001 - report everything, including SystemExit
        tb = traceback.format_exc()
        sys.stderr.write(tb)
        result = {
            "ok": False,
            "error": {
                "code": "BUILD_FAILED",
                "message": f"{type(exc).__name__}: {exc}",
                "hint": None,
                "traceback_tail": tb.splitlines()[-15:],
            },
        }
        code = 3
    sys.stderr.flush()
    result_stream.write(f"{RESULT_MARKER} {json.dumps(result)}\n")
    result_stream.flush()
    return code


if __name__ == "__main__":  # pragma: no cover - exercised through subprocess tests
    sys.exit(main())
