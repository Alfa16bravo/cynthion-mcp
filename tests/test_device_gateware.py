"""Tests for cynthion_mcp.device and cynthion_mcp.gateware.

No Cynthion hardware is required: USB enumeration is replaced by a fake
``usb.core.find`` and the Apollo debugger by ``FakeApollo`` (injected through
``device._apollo_factory``). The bundled bitstreams / firmware come from the
real installed ``cynthion`` package.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Make the src layout importable even without conftest / an editable install.
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from cynthion_mcp import common, device, gateware  # noqa: E402


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _as_mcp_error(exc: BaseException) -> common.CynthionMCPError:
    """Return the CynthionMCPError equivalent of any exception."""
    if isinstance(exc, common.CynthionMCPError):
        return exc
    return common.translate_exception(exc)


def _raises_mcp(fn, *args, **kwargs) -> common.CynthionMCPError:
    """Call fn and return the (translated) error it raises; fail if none."""
    try:
        result = fn(*args, **kwargs)
        # open_apollo may be a context manager: enter it to trigger errors.
        if hasattr(result, "__enter__"):
            with result:
                pass
    except BaseException as exc:  # noqa: BLE001 - we want every error here
        return _as_mcp_error(exc)
    pytest.fail(f"{getattr(fn, '__name__', fn)} did not raise")


def _asset_dir() -> Path:
    import cynthion
    return Path(cynthion.cynthion_assets_directory())


# --------------------------------------------------------------------------
# Fake pyusb objects
# --------------------------------------------------------------------------

class FakeInterface:
    def __init__(self, number, cls=0xFF, subclass=0x00, protocol=0x00):
        self.bInterfaceNumber = number
        self.bAlternateSetting = 0
        self.bInterfaceClass = cls
        self.bInterfaceSubClass = subclass
        self.bInterfaceProtocol = protocol
        self.bNumEndpoints = 0
        self.iInterface = 0

    def __iter__(self):
        return iter(())


class FakeConfiguration:
    def __init__(self, interfaces):
        self.bConfigurationValue = 1
        self.bNumInterfaces = len(interfaces)
        self._interfaces = list(interfaces)

    def __iter__(self):
        return iter(self._interfaces)

    def interfaces(self):
        return tuple(self._interfaces)

    def __getitem__(self, key):
        number, alt = key
        for intf in self._interfaces:
            if intf.bInterfaceNumber == number and intf.bAlternateSetting == alt:
                return intf
        raise KeyError(key)


class FakeUSBDevice:
    """Minimal stand-in for usb.core.Device."""

    def __init__(self, vid, pid, bcd=0x0104, interfaces=(), manufacturer="Great Scott Gadgets",
                 product="Cynthion Apollo Debugger", serial="0123456789ABCDEF", bus=1, address=7):
        self.idVendor = vid
        self.idProduct = pid
        self.bcdDevice = bcd
        self.bcdUSB = 0x0200
        self.bDeviceClass = 0
        self.bNumConfigurations = 1
        self.iManufacturer, self.iProduct, self.iSerialNumber = 1, 2, 3
        self.manufacturer = manufacturer
        self.product = product
        self.serial_number = serial
        self.bus = bus
        self.address = address
        self.port_numbers = (1,)
        self._strings = {1: manufacturer, 2: product, 3: serial}
        self._configs = [FakeConfiguration(interfaces)]

    def __iter__(self):
        return iter(self._configs)

    def configurations(self):
        return tuple(self._configs)

    def get_active_configuration(self):
        return self._configs[0]

    def set_configuration(self, *a, **k):
        return None

    def ctrl_transfer(self, bmRequestType, bRequest, wValue=0, wIndex=0, data_or_wLength=None, timeout=None):
        # Answer Apollo's GET_ID (0xa0) so _device_has_apollo_id() is happy.
        if bRequest == 0xA0 and self.idProduct in (0x615C, 0x0010):
            return bytearray(b"Apollo Debugger\x00")
        if isinstance(data_or_wLength, int):
            return bytearray(data_or_wLength)
        return 0

    def __repr__(self):
        return f"<FakeUSBDevice {self.idVendor:04x}:{self.idProduct:04x}>"


def fake_apollo_usb():
    return FakeUSBDevice(0x1D50, 0x615C, bcd=0x0104, interfaces=[FakeInterface(0, 0xFF, 0x00, 0x00)])


def fake_analyzer_usb():
    return FakeUSBDevice(0x1D50, 0x615B, bcd=0x0104,
                         interfaces=[FakeInterface(0, 0xFF, 0x10, 0x01), FakeInterface(1, 0xFF, 0x00, 0x00)],
                         manufacturer="Cynthion Project", product="USB Analyzer", address=8)


def fake_facedancer_usb():
    return FakeUSBDevice(0x1D50, 0x615B, bcd=0x0104,
                         interfaces=[FakeInterface(0, 0xFF, 0x20, 0x00), FakeInterface(1, 0xFF, 0x00, 0x00)],
                         manufacturer="Cynthion Project", product="Facedancer", address=9)


def fake_stub_usb():
    return FakeUSBDevice(0x1209, 0x000F, bcd=0x0104, interfaces=[FakeInterface(0, 0xFF, 0x00, 0x00)],
                         manufacturer="LUNA", product="Flash bridge", address=10)


@pytest.fixture
def fake_usb(monkeypatch):
    """Replace pyusb enumeration with an in-memory device list.

    Returns the (mutable) list; tests append fake devices to it.
    """
    import usb.core
    import usb.util

    devices: list = []

    def fake_find(find_all=False, backend=None, custom_match=None, **kwargs):
        matches = []
        for d in devices:
            if any(getattr(d, k, None) != v for k, v in kwargs.items()):
                continue
            if custom_match is not None:
                try:
                    if not custom_match(d):
                        continue
                except Exception:  # noqa: BLE001 - mimic a non-matching device
                    continue
            matches.append(d)
        if find_all:
            return iter(matches)
        return matches[0] if matches else None

    def fake_get_string(dev, index, langid=None):
        return getattr(dev, "_strings", {}).get(index)

    monkeypatch.setattr(usb.core, "find", fake_find)
    # The autouse no_usb fixture stubs device._usb_find_all; route it back through
    # the real implementation so it sees this fake usb.core.find.
    real = getattr(device, "_real_usb_find_all", None)
    if real is not None:
        monkeypatch.setattr(device, "_usb_find_all", real)
    monkeypatch.setattr(usb.util, "get_string", fake_get_string)
    monkeypatch.setattr(usb.util, "dispose_resources", lambda dev: None)
    monkeypatch.setattr(usb.util, "claim_interface", lambda dev, intf: None, raising=False)
    monkeypatch.setattr(usb.util, "release_interface", lambda dev, intf: None, raising=False)
    # Avoid loading the real libusb backend during these tests.
    try:
        from apollo_fpga import ApolloDebugger
        monkeypatch.setattr(ApolloDebugger, "backend", object(), raising=False)
    except Exception:  # noqa: BLE001
        pass
    return devices


# --------------------------------------------------------------------------
# Fake Apollo debugger
# --------------------------------------------------------------------------

class CallLog(list):
    def names(self):
        return [c[0] for c in self]


class FakeJTAG:
    def __init__(self, log):
        self.log = log

    def __enter__(self):
        self.log.append(("jtag_enter",))
        return self

    def __exit__(self, *exc):
        self.log.append(("jtag_exit",))
        return False

    def enumerate(self, return_idcodes=False):
        return [0x21111043] if return_idcodes else []


class FakeProgrammer:
    """Mirrors apollo_fpga.ecp5.ECP5_JTAGProgrammer's signatures."""

    def __init__(self, log):
        self.log = log

    def configure(self, bitstream, progress_callback=None):
        self.log.append(("configure", len(bitstream)))

    def unconfigure(self):
        self.log.append(("unconfigure",))

    def flash(self, bitstream, erase_first=True, disable_protections=False, offset=0):
        self.log.append(("flash", offset, len(bitstream)))

    def erase_flash(self):
        self.log.append(("erase_flash",))

    def read_flash(self, length, offset=0):
        # The real implementation print()s progress to stdout.
        print(length)
        self.log.append(("read_flash", offset, length))
        return bytearray((i & 0xFF for i in range(length)))

    def read_flash_id(self):
        return (0xEF, 0xEF4016)

    def read_flash_uid(self):
        return 0x0123456789ABCDEF

    def read_id(self):
        return 0x21111043

    def part_name(self):
        return "LFE5U-12"

    def trigger_reconfiguration(self):
        self.log.append(("trigger_reconfiguration",))


class FakeApollo:
    instances: list = []

    def __init__(self, log, force_offline=False, device=None, major=1, minor=4):
        self.log = log
        self.force_offline_requested = force_offline
        self.device = device if device is not None else fake_apollo_usb()
        self.major, self.minor = major, minor
        self.jtag = FakeJTAG(log)
        self.spi = None
        self.registers = None
        FakeApollo.instances.append(self)

    # --- info
    @property
    def serial_number(self):
        return self.device.serial_number

    def get_hardware_revision(self):
        return (self.major, self.minor)

    detect_connected_version = get_hardware_revision

    def get_hardware_name(self):
        return f"Cynthion r{self.major}.{self.minor}"

    def get_compatibility_string(self):
        return "Cynthion"

    def get_firmware_version(self):
        return "v1.1.1"

    def get_usb_api_version(self):
        return (1, 2)

    def get_usb_api_version_string(self):
        return "1.2"

    def get_adc_reading(self):
        return 1234

    def get_fpga_type(self):
        return "LFE5U-12F"

    # --- control
    def create_jtag_programmer(self, jtag):
        return FakeProgrammer(self.log)

    def set_led_pattern(self, number):
        self.log.append(("set_led_pattern", number))

    def soft_reset(self):
        self.log.append(("soft_reset",))

    def force_fpga_offline(self):
        self.log.append(("force_fpga_offline",))

    def allow_fpga_takeover_usb(self):
        self.log.append(("allow_fpga_takeover_usb",))

    def close(self):
        self.log.append(("close",))


@pytest.fixture
def fake_apollo(monkeypatch, fake_usb):
    """Install FakeApollo as the ApolloDebugger factory; returns the call log."""
    log = CallLog()
    FakeApollo.instances = []

    def factory(*args, **kwargs):
        force_offline = kwargs.get("force_offline", args[0] if args else False)
        dev = kwargs.get("device")
        return FakeApollo(log, force_offline=force_offline, device=dev)

    monkeypatch.setattr(device, "_apollo_factory", factory)
    # Pretend Apollo is enumerated so mode pre-checks pass.
    fake_usb.append(fake_apollo_usb())
    return log


def _subsequence_index(log, expected):
    """Assert `expected` (list of predicates) appear in order in `log`."""
    pos = 0
    for pred, label in expected:
        while pos < len(log) and not pred(log[pos]):
            pos += 1
        assert pos < len(log), f"missing step {label!r} (in order) in call log {list(log)!r}"
        pos += 1


# --------------------------------------------------------------------------
# device.py
# --------------------------------------------------------------------------

def test_list_devices_without_usb(fake_usb):
    res = device.list_devices()
    assert res["ok"] is True
    assert res["count"] == 0
    assert res["mode"] == "absent"
    assert res.get("devices", []) == []


def test_list_devices_real_bus_does_not_raise():
    """On the real bus (no Cynthion attached on CI) it must never raise."""
    res = device.list_devices()
    assert res["ok"] is True
    if res["count"] == 0:
        assert res["mode"] == "absent"


def _classify(dev):
    try:
        return device.classify(dev)
    except TypeError:
        intfs = [(i.bInterfaceClass, i.bInterfaceSubClass, i.bInterfaceProtocol)
                 for cfg in dev for i in cfg]
        return device.classify(dev.idVendor, dev.idProduct, intfs)


@pytest.mark.parametrize("factory, expected", [
    (fake_apollo_usb, "apollo"),
    (fake_analyzer_usb, "analyzer"),
    (fake_facedancer_usb, "facedancer"),
    (fake_stub_usb, "gateware_stub"),
])
def test_classify(fake_usb, factory, expected):
    assert _classify(factory()) == expected


def test_list_devices_with_fake_devices(fake_usb):
    fake_usb.append(fake_analyzer_usb())
    res = device.list_devices()
    assert res["ok"] is True
    assert res["count"] == 1
    assert res["mode"] == "analyzer"
    d = res["devices"][0]
    assert d["revision"] == "r1.4"
    assert d["mode"] == "analyzer"
    assert d["vid"] in (0x1D50, "0x1d50", "1d50")
    json.dumps(res)  # must be JSON-serialisable


def test_list_devices_apollo_mode(fake_usb):
    fake_usb.append(fake_apollo_usb())
    res = device.list_devices()
    assert res["count"] == 1
    assert res["mode"] == "apollo"
    assert res["devices"][0]["revision"] == "r1.4"


def test_get_info_without_device(monkeypatch, fake_usb):
    from apollo_fpga import DebuggerNotFound

    def factory(*a, **k):
        raise DebuggerNotFound("No Apollo debugger or stub interface found.")

    monkeypatch.setattr(device, "_apollo_factory", factory)
    err = _raises_mcp(device.get_info)
    assert isinstance(err, common.NoDeviceError)
    assert err.format().startswith("[NO_DEVICE]")


def test_open_apollo_stub_not_forced_is_wrong_mode(monkeypatch, fake_usb):
    from apollo_fpga import DebuggerNotFound

    def factory(*a, **k):
        raise DebuggerNotFound("Apollo stub interface found but not requested to be forced offline.")

    monkeypatch.setattr(device, "_apollo_factory", factory)
    err = _raises_mcp(device.open_apollo, force_offline=False)
    assert isinstance(err, common.WrongModeError)
    assert err.format().startswith("[WRONG_MODE]")


def test_set_led_pattern_records_and_closes(fake_apollo):
    res = device.set_led_pattern(500)
    assert res["ok"] is True
    assert res.get("pattern", 500) == 500
    assert ("set_led_pattern", 500) in fake_apollo
    assert "close" in fake_apollo.names()
    assert fake_apollo.names().index("close") > fake_apollo.index(("set_led_pattern", 500))


def test_set_led_pattern_invalid(fake_apollo):
    err = _raises_mcp(device.set_led_pattern, -1)
    assert isinstance(err, common.InvalidArgumentError)
    assert ("set_led_pattern", -1) not in fake_apollo


# --------------------------------------------------------------------------
# gateware.py: assets
# --------------------------------------------------------------------------

def test_list_bundled_assets_real():
    res = gateware.list_bundled_assets()
    assert res["ok"] is True
    text = json.dumps(res)
    assert "CynthionPlatformRev1D4" in text
    for target in ("analyzer", "facedancer", "selftest"):
        assert target in text
    assert "moondancer.bin" in text


def test_bitstream_path_ok():
    p = Path(gateware.bitstream_path("analyzer", 1, 4))
    assert p.is_file()
    assert p.name == "analyzer.bit"
    assert p.parent.name == "CynthionPlatformRev1D4"
    assert p.stat().st_size == (_asset_dir() / "CynthionPlatformRev1D4" / "analyzer.bit").stat().st_size


def test_bitstream_path_unknown_revision():
    err = _raises_mcp(gateware.bitstream_path, "analyzer", 9, 9)
    assert isinstance(err, common.UnsupportedError)


def test_bitstream_path_unknown_target():
    err = _raises_mcp(gateware.bitstream_path, "bogus", 1, 4)
    assert isinstance(err, common.InvalidArgumentError)


# --------------------------------------------------------------------------
# gateware.py: run / flash with FakeApollo
# --------------------------------------------------------------------------

def test_run_gateware_facedancer_sequence(fake_apollo):
    moondancer_size = (_asset_dir() / "moondancer.bin").stat().st_size
    facedancer_size = (_asset_dir() / "CynthionPlatformRev1D4" / "facedancer.bit").stat().st_size

    res = gateware.run_gateware("facedancer", wait=False)
    assert res["ok"] is True
    assert res["target"] == "facedancer"
    assert res["soc_firmware_flashed"] is True

    _subsequence_index(fake_apollo, [
        (lambda c: c[0] == "force_fpga_offline", "force_fpga_offline"),
        (lambda c: c[0] == "flash" and c[1] == 0xB0000 and c[2] == moondancer_size, "flash moondancer.bin @0xB0000"),
        (lambda c: c[0] == "configure" and c[1] == facedancer_size, "configure facedancer.bit"),
        (lambda c: c[0] == "allow_fpga_takeover_usb", "allow_fpga_takeover_usb"),
        (lambda c: c[0] == "close", "close"),
    ])
    # Every debugger that was opened must have been closed.
    assert fake_apollo.names().count("close") >= len(FakeApollo.instances) >= 1
    # Bitstream loading is volatile: the flash must never be touched at offset 0.
    assert not any(c[0] == "flash" and c[1] == 0 for c in fake_apollo)


def test_run_gateware_analyzer_no_soc_flash(fake_apollo):
    analyzer_size = (_asset_dir() / "CynthionPlatformRev1D4" / "analyzer.bit").stat().st_size

    res = gateware.run_gateware("analyzer", wait=False)
    assert res["ok"] is True
    assert res["soc_firmware_flashed"] is False
    assert not any(c[0] == "flash" for c in fake_apollo)
    _subsequence_index(fake_apollo, [
        (lambda c: c[0] == "configure" and c[1] == analyzer_size, "configure analyzer.bit"),
        (lambda c: c[0] == "allow_fpga_takeover_usb", "allow_fpga_takeover_usb"),
        (lambda c: c[0] == "close", "close"),
    ])


def test_flash_gateware_requires_confirm(fake_apollo):
    err = _raises_mcp(gateware.flash_gateware, "analyzer")
    assert isinstance(err, common.ConfirmationRequired)
    assert err.format().startswith("[CONFIRMATION_REQUIRED]")
    assert FakeApollo.instances == []
    assert not any(c[0] in ("flash", "erase_flash") for c in fake_apollo)


def test_erase_flash_requires_confirm(fake_apollo):
    err = _raises_mcp(gateware.erase_flash)
    assert isinstance(err, common.ConfirmationRequired)
    assert FakeApollo.instances == []
    assert "erase_flash" not in fake_apollo.names()


def test_flash_file_unaligned_offset(fake_apollo, tmp_path):
    img = tmp_path / "image.bin"
    img.write_bytes(b"\xAA" * 512)
    err = _raises_mcp(gateware.flash_file, str(img), offset=100, confirm=True)
    assert isinstance(err, common.InvalidArgumentError)
    assert not any(c[0] == "flash" for c in fake_apollo)


def test_read_flash_writes_file_and_keeps_stdout_clean(fake_apollo, tmp_path, capsys):
    out = tmp_path / "dump.bin"
    res = gateware.read_flash(str(out), length=1024, offset=0)
    assert res["ok"] is True
    assert out.is_file()
    data = out.read_bytes()
    assert len(data) == 1024
    assert data[:4] == bytes([0, 1, 2, 3])
    assert res["length"] == 1024
    assert ("read_flash", 0, 1024) in fake_apollo
    assert "close" in fake_apollo.names()
    captured = capsys.readouterr()
    assert captured.out == ""


def test_run_gateware_refused_while_busy(fake_apollo):
    state = {"busy": True}
    registered = False
    try:
        common.ACTIVITY.register("pytest_owner", lambda: state["busy"])
        registered = True
    except (AttributeError, TypeError):
        pass

    try:
        if not registered:
            def check_free(*a, **k):
                if state["busy"]:
                    raise common.BusyError("busy: pytest_owner")
            orig = common.ACTIVITY.check_free
            common.ACTIVITY.check_free = check_free  # type: ignore[method-assign]
        try:
            err = _raises_mcp(gateware.run_gateware, "analyzer", wait=False)
        finally:
            if not registered:
                common.ACTIVITY.check_free = orig  # type: ignore[method-assign]
        assert isinstance(err, common.BusyError)
        assert err.format().startswith("[BUSY]")
        assert not any(c[0] in ("configure", "flash") for c in fake_apollo)
    finally:
        state["busy"] = False
        for name in ("unregister", "remove"):
            fn = getattr(common.ACTIVITY, name, None)
            if callable(fn):
                try:
                    fn("pytest_owner")
                except Exception:  # noqa: BLE001
                    pass
                break
