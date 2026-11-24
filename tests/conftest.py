"""Shared pytest fixtures for the cynthion_mcp test-suite.

No real hardware is ever touched: USB enumeration and Apollo construction are
monkeypatched for every test (autouse ``no_usb``), and long-lived singletons
(analyzer capture manager, facedancer runner, activity registry) are replaced
with fresh instances so state never leaks between tests.

Fakes provided:
  * ``fake_usb_device(...)``  - pyusb-like Device (iterable configs -> interfaces)
  * ``FakeApollo`` / ``FakeProgrammer`` / ``FakeJTAG`` - stand-ins for
    apollo_fpga.ApolloDebugger and its ECP5 JTAG programmer
  * ``FakeAnalyzerDevice`` - scripted analyzer USB driver (bulk chunks + state)
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence, Tuple

import pytest

# --------------------------------------------------------------------------
# Make ``src`` importable (pyproject's pytest pythonpath already does this;
# this is a defensive fallback when pytest is run without that config).
# --------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


# ==========================================================================
# Fake pyusb device
# ==========================================================================
class FakeInterface:
    """Mimics usb.core.Interface: only the bInterface* descriptor fields."""

    def __init__(self, number: int, cls: int, subclass: int, protocol: int,
                 alternate: int = 0):
        self.bInterfaceNumber = number
        self.bAlternateSetting = alternate
        self.bInterfaceClass = cls
        self.bInterfaceSubClass = subclass
        self.bInterfaceProtocol = protocol
        self.bNumEndpoints = 0
        self.iInterface = 0

    def __iter__(self):  # endpoints
        return iter(())

    def __repr__(self) -> str:
        return (f"FakeInterface({self.bInterfaceNumber}, 0x{self.bInterfaceClass:02x}, "
                f"0x{self.bInterfaceSubClass:02x}, 0x{self.bInterfaceProtocol:02x})")


class FakeConfiguration:
    """Mimics usb.core.Configuration: iterable of interfaces, indexable by (num, alt)."""

    def __init__(self, interfaces: Sequence[FakeInterface], value: int = 1):
        self.bConfigurationValue = value
        self.bNumInterfaces = len(interfaces)
        self._interfaces = list(interfaces)

    def __iter__(self):
        return iter(self._interfaces)

    def __getitem__(self, key):
        num, alt = key
        for intf in self._interfaces:
            if intf.bInterfaceNumber == num and intf.bAlternateSetting == alt:
                return intf
        raise IndexError(key)


class FakeUSBDevice:
    """Mimics usb.core.Device for non-invasive enumeration code paths."""

    def __init__(self, vid: int, pid: int, bcd: int = 0x0104, serial: Optional[str] = "ABC",
                 product: Optional[str] = "USB Analyzer",
                 manufacturer: Optional[str] = "Cynthion Project",
                 interfaces: Iterable[Tuple[int, int, int, int]] = ((0, 0xFF, 0x10, 0x01),),
                 bus: int = 1, address: int = 5):
        self.idVendor = vid
        self.idProduct = pid
        self.bcdDevice = bcd
        self.serial_number = serial
        self.manufacturer = manufacturer
        self.product = product
        self.bus = bus
        self.address = address
        self.port_number = 1
        self.bDeviceClass = 0
        self.bNumConfigurations = 1
        self.configurations = [FakeConfiguration([FakeInterface(*i) for i in interfaces])]
        self.disposed = False

    def __iter__(self):
        return iter(self.configurations)

    def get_active_configuration(self):
        return self.configurations[0]

    def set_configuration(self, *_a, **_kw):
        return None

    def __repr__(self) -> str:
        return f"FakeUSBDevice({self.idVendor:04x}:{self.idProduct:04x}, serial={self.serial_number!r})"


def make_fake_usb_device(vid: int, pid: int, bcd: int = 0x0104, serial: Optional[str] = "ABC",
                         product: Optional[str] = "USB Analyzer",
                         interfaces: Optional[Iterable[Tuple[int, int, int, int]]] = None,
                         **kwargs: Any) -> FakeUSBDevice:
    if interfaces is None:
        interfaces = [(0, 0xFF, 0x10, 0x01)]
    return FakeUSBDevice(vid, pid, bcd=bcd, serial=serial, product=product,
                         interfaces=interfaces, **kwargs)


@pytest.fixture
def fake_usb_device():
    """Factory: fake_usb_device(vid, pid, bcd=0x0104, serial='ABC',
    product='USB Analyzer', interfaces=[(num, cls, subclass, protocol)])."""
    return make_fake_usb_device


# ==========================================================================
# Fake Apollo debugger
# ==========================================================================
class FakeJTAG:
    """Reference-counted context manager like apollo_fpga.jtag.JTAGChain."""

    def __init__(self, calls: List[Tuple[Any, ...]]):
        self.calls = calls
        self.depth = 0
        self.idcodes = [0x21111043]

    def __enter__(self):
        self.depth += 1
        self.calls.append(("jtag_enter",))
        return self

    def __exit__(self, *exc):
        self.depth -= 1
        self.calls.append(("jtag_exit",))
        return False

    def enumerate(self, return_idcodes: bool = False):
        if return_idcodes:
            return list(self.idcodes)

        class _Dev:
            DEVICE = "LFE5U-12F"

            def __init__(self, code):
                self._code = code

            def idcode(self):
                return self._code

            def description(self):
                return "Lattice LFE5U-12F ECP5 FPGA"

        return [_Dev(c) for c in self.idcodes]


class FakeProgrammer:
    """Stand-in for apollo_fpga.ecp5.ECP5_JTAGProgrammer."""

    FLASH_SIZE = 4 * 1024 * 1024

    def __init__(self, calls: List[Tuple[Any, ...]]):
        self.calls = calls
        self.flash_content = bytearray(b"\xff" * 4096)

    def configure(self, bitstream):
        self.calls.append(("configure", len(bitstream)))

    def unconfigure(self):
        self.calls.append(("unconfigure",))

    def trigger_reconfiguration(self):
        self.calls.append(("trigger_reconfiguration",))

    def flash(self, bitstream, erase_first=True, disable_protections=False, offset=0):
        if offset % 256:
            raise ValueError("offset must be a multiple of 256")
        self.calls.append(("flash", len(bitstream), offset))
        end = offset + len(bitstream)
        if end > len(self.flash_content):
            self.flash_content.extend(b"\xff" * (end - len(self.flash_content)))
        self.flash_content[offset:end] = bitstream

    def erase_flash(self):
        self.calls.append(("erase_flash",))
        self.flash_content = bytearray(b"\xff" * len(self.flash_content))

    def read_flash(self, length, offset=0):
        if offset % 256:
            raise ValueError("offset must be a multiple of 256")
        self.calls.append(("read_flash", length, offset))
        data = bytes(self.flash_content[offset:offset + length])
        return bytearray(data + b"\xff" * (length - len(data)))

    def read_flash_id(self):
        self.calls.append(("read_flash_id",))
        return (0xEF, 0xEF4016)

    def read_flash_uid(self):
        self.calls.append(("read_flash_uid",))
        return 0x0123456789ABCDEF

    def read_id(self):
        return 0x21111043

    def part_name(self):
        return "LFE5U-12"


class FakeRegisters:
    def __init__(self, calls: List[Tuple[Any, ...]]):
        self.calls = calls
        self.values = {1: 0x54455354}

    def register_read(self, addr):
        self.calls.append(("register_read", addr))
        return self.values.get(addr, 0)

    def register_write(self, addr, value):
        self.calls.append(("register_write", addr, value))
        self.values[addr] = value


class FakeApollo:
    """Stand-in for apollo_fpga.ApolloDebugger; records every call in ``calls``."""

    LED_PATTERN_IDLE = 500
    LED_PATTERN_UPLOAD = 50

    def __init__(self, force_offline: bool = False, device: Any = None,
                 major: int = 1, minor: int = 4, serial: str = "ABC"):
        self.calls: List[Tuple[Any, ...]] = [("init", force_offline)]
        self.force_offline = force_offline
        self.major = major
        self.minor = minor
        self.serial_number = serial
        self.device = device if device is not None else make_fake_usb_device(
            0x1D50, 0x615C, bcd=(major << 8) | minor, serial=serial,
            product="Cynthion Apollo Debugger", manufacturer="Great Scott Gadgets",
            interfaces=[(0, 0xFF, 0x00, 0x00)])
        self.jtag = FakeJTAG(self.calls)
        self.registers = FakeRegisters(self.calls)
        self.spi = self.registers
        self.programmer = FakeProgrammer(self.calls)
        self.closed = False

    # -- info ------------------------------------------------------------
    def get_hardware_name(self):
        return f"Cynthion r{self.major}.{self.minor}"

    def get_hardware_revision(self):
        return (self.major, self.minor)

    detect_connected_version = get_hardware_revision

    def get_firmware_version(self):
        return "v1.1.1"

    def get_usb_api_version(self):
        return (1, 2)

    def get_usb_api_version_string(self):
        return "1.2"

    def get_adc_reading(self):
        return 0x1234

    def get_compatibility_string(self):
        return "Cynthion"

    def get_fpga_type(self):
        return "LFE5U-12F"

    # -- control ---------------------------------------------------------
    def set_led_pattern(self, number):
        self.calls.append(("set_led_pattern", number))

    def soft_reset(self):
        self.calls.append(("soft_reset",))

    def force_fpga_offline(self):
        self.calls.append(("force_fpga_offline",))

    def allow_fpga_takeover_usb(self):
        self.calls.append(("allow_fpga_takeover_usb",))

    def create_jtag_programmer(self, jtag):
        self.calls.append(("create_jtag_programmer",))
        return self.programmer

    def close(self):
        self.calls.append(("close",))
        self.closed = True

    def call_names(self) -> List[str]:
        return [c[0] for c in self.calls]


@pytest.fixture
def fake_apollo():
    """A fresh FakeApollo instance."""
    return FakeApollo()


@pytest.fixture
def use_fake_apollo(monkeypatch):
    """Install a FakeApollo as cynthion_mcp.device._apollo_factory.

    Returns the list of FakeApollo instances created (one per factory call)."""
    import cynthion_mcp.device as device_mod

    created: List[FakeApollo] = []

    def factory(*args, **kwargs):
        force_offline = kwargs.get("force_offline", args[0] if args else False)
        inst = FakeApollo(force_offline=bool(force_offline), device=kwargs.get("device"))
        created.append(inst)
        return inst

    monkeypatch.setattr(device_mod, "_apollo_factory", factory)
    return created


# ==========================================================================
# Fake analyzer device
# ==========================================================================
STOP_EVENT_BYTES = bytes([0xFF, 0x01, 0x00, 0x00])  # CAPTURE_STOP_NORMAL, ts 0


class FakeAnalyzerDevice:
    """Scripted analyzer driver.

    ``chunks`` are returned one per read() call while capture is enabled;
    afterwards read() returns b''. Once set_state() is called with the ENABLE
    bit (bit0) cleared, the next read() returns the stop event FF 01 00 00
    exactly once (after any remaining scripted chunks).
    """

    def __init__(self, chunks: Optional[Sequence[bytes]] = None, minor: int = 1,
                 speeds: Optional[Sequence[str]] = None, serial: str = "ABC",
                 major: int = 1, revision: Tuple[int, int] = (1, 4)):
        self.chunks: List[bytes] = [bytes(c) for c in (chunks or [])]
        self.states: List[int] = []
        self.test_configs: List[int] = []
        self.state = 0
        self.major = major
        self.minor = minor
        self.serial = serial
        self.serial_number = serial
        self.revision = revision
        self._speeds = list(speeds) if speeds is not None else ["auto", "low", "full", "high"]
        self._stop_pending = False
        self.closed = False
        self.reads = 0

    # protocol / info
    @property
    def protocol_version(self) -> str:
        return f"{self.major}.{self.minor}"

    def get_minor_version(self):
        return self.minor

    def get_speeds(self):
        return list(self._speeds)

    speeds = get_speeds

    def get_state(self):
        return self.state

    def set_state(self, value: int):
        value &= 0xFF
        self.states.append(value)
        was_enabled = bool(self.state & 1)
        self.state = value
        if not (value & 1) and was_enabled:
            self._stop_pending = True

    def set_test_config(self, value: int):
        self.test_configs.append(value)

    def test_device(self, connect: bool = True, speed: str = "high"):
        sp = {"high": 0, "full": 1, "low": 2}[speed]
        self.set_test_config(int(connect) | (sp << 1))

    def read(self, size: int = 0x4000, timeout_ms: int = 100) -> bytes:
        self.reads += 1
        if self.chunks:
            return self.chunks.pop(0)
        if self._stop_pending:
            self._stop_pending = False
            return STOP_EVENT_BYTES
        return b""

    def close(self):
        self.closed = True


@pytest.fixture
def fake_analyzer_device():
    """Factory: fake_analyzer_device(chunks=[...], minor=1, speeds=None)."""
    return FakeAnalyzerDevice


# ==========================================================================
# Autouse isolation fixtures
# ==========================================================================
def _raising_factory(*_args, **_kwargs):
    try:
        from apollo_fpga import DebuggerNotFound
    except Exception:  # pragma: no cover - apollo_fpga broken
        class DebuggerNotFound(IOError):  # type: ignore[no-redef]
            pass
    raise DebuggerNotFound("No Apollo debugger or stub interface found.")


@pytest.fixture(autouse=True)
def no_usb(monkeypatch, tmp_path):
    """Never touch real USB: empty enumeration, Apollo always absent."""
    import cynthion_mcp.device as device_mod

    # Keep the real implementation reachable for fixtures that fake usb.core.find.
    monkeypatch.setattr(device_mod, "_real_usb_find_all", device_mod._usb_find_all, raising=False)
    monkeypatch.setattr(device_mod, "_usb_find_all", lambda *a, **kw: [])
    monkeypatch.setattr(device_mod, "_apollo_factory", _raising_factory)
    monkeypatch.setenv("CYNTHION_MCP_OUTPUT_DIR", str(tmp_path))

    # Hard guard: even code paths that bypass device.py (analyzer.AnalyzerDevice.open,
    # board_io.open_board, apollo_fpga internals) must never reach a real board,
    # which matters when a Cynthion happens to be plugged in while tests run.
    try:
        import usb.core

        def _no_find(*_a, find_all=False, **_kw):
            return iter(()) if find_all else None

        monkeypatch.setattr(usb.core, "find", _no_find)
    except Exception:  # pragma: no cover - pyusb broken
        pass
    try:
        import cynthion

        def _no_board(*_a, **_kw):
            from pygreat.errors import DeviceNotFoundError
            raise DeviceNotFoundError("no board (tests)")

        monkeypatch.setattr(cynthion, "Cynthion", _no_board)
    except Exception:  # pragma: no cover
        pass
    yield


def _fresh_instance(old: Any) -> Any:
    """Create a new instance of ``type(old)`` with its default constructor."""
    return type(old)()


@pytest.fixture(autouse=True)
def reset_singletons(monkeypatch):
    """Fresh ACTIVITY registry, CAPTURE and RUNNER singletons for each test."""
    import cynthion_mcp.common as common
    import cynthion_mcp.analyzer as analyzer
    import cynthion_mcp.facedancer_runner as facedancer_runner

    new_registry = common.ActivityRegistry()
    monkeypatch.setattr(common, "ACTIVITY", new_registry)
    # Modules that did `from .common import ACTIVITY` hold their own reference.
    import cynthion_mcp.board_io as board_io
    import cynthion_mcp.device as device_mod
    import cynthion_mcp.gateware as gateware_mod
    for mod in (analyzer, facedancer_runner, board_io, device_mod, gateware_mod):
        if hasattr(mod, "ACTIVITY"):
            monkeypatch.setattr(mod, "ACTIVITY", new_registry)
    try:
        import cynthion_mcp.server as server_mod
        if hasattr(server_mod, "ACTIVITY"):
            monkeypatch.setattr(server_mod, "ACTIVITY", new_registry)
    except Exception:
        server_mod = None

    old_capture = analyzer.CAPTURE
    old_runner = facedancer_runner.RUNNER
    new_capture = _fresh_instance(old_capture)
    new_runner = _fresh_instance(old_runner)
    monkeypatch.setattr(analyzer, "CAPTURE", new_capture)
    monkeypatch.setattr(facedancer_runner, "RUNNER", new_runner)
    if server_mod is not None:
        if hasattr(server_mod, "CAPTURE"):
            monkeypatch.setattr(server_mod, "CAPTURE", new_capture)
        if hasattr(server_mod, "RUNNER"):
            monkeypatch.setattr(server_mod, "RUNNER", new_runner)

    # Re-register the owner probes on the fresh registry (they reference the
    # module globals, so they always see the currently patched singleton).
    register = getattr(new_registry, "register", None)
    if callable(register):
        for name, probe in (
            ("analyzer_capture", lambda: analyzer.CAPTURE.is_running()),
            ("facedancer", lambda: facedancer_runner.RUNNER.is_running()),
        ):
            try:
                register(name, probe)
            except Exception:
                pass

    yield {"activity": new_registry, "capture": new_capture, "runner": new_runner}

    # Best-effort cleanup of anything a test may have started.
    for obj, meth in ((new_capture, "stop"), (new_runner, "stop")):
        try:
            if getattr(obj, "is_running", lambda: False)():
                getattr(obj, meth)()
        except Exception:
            pass
