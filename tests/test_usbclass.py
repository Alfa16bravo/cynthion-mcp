"""Tests for the pure-Python USB class decoder (no hardware).

Transactions are produced the realistic way: raw USB packets are wrapped in
usbdecode.Record objects and grouped with usbdecode.group_transactions.
"""
from __future__ import annotations

import json
import struct

import pytest

from cynthion_mcp import usbdecode
from cynthion_mcp.usbclass import (
    UsbClassDecoder,
    ch34x_baud,
    decode_scsi_cdb,
    decode_transactions,
    ftdi_baud,
    parse_config_descriptor,
    parse_hid_report_descriptor,
)

SETUP_PID, IN_PID, OUT_PID = 0x2D, 0x69, 0xE1
DATA0, DATA1 = 0xC3, 0x4B
ACK, NAK, STALL = 0xD2, 0x5A, 0x1E
TICKS_PER_US = 60


def _token(pid_byte: int, addr: int, ep: int) -> bytes:
    v = addr | (ep << 7)
    v |= usbdecode.crc5_usb(v & 0x7FF) << 11
    return bytes([pid_byte, v & 0xFF, v >> 8])


def _data(pid_byte: int, payload: bytes) -> bytes:
    return bytes([pid_byte]) + payload + usbdecode.crc16_usb(payload).to_bytes(2, "little")


class Bus:
    """Builds analyzer Records for host/device traffic, then groups them."""

    def __init__(self) -> None:
        self.records: list[usbdecode.Record] = []
        self.ticks = 0
        self.toggle: dict[tuple[int, int, str], int] = {}

    def _pkt(self, raw: bytes, gap_us: float = 2.0) -> None:
        self.ticks += int(gap_us * TICKS_PER_US)
        self.records.append(usbdecode.Record(len(self.records), "packet", self.ticks, raw))

    def wait_us(self, us: float) -> None:
        self.ticks += int(us * TICKS_PER_US)

    def txn(self, pid: int, addr: int, ep: int, data_pid: int | None, payload: bytes | None,
            hs: int | None = ACK) -> None:
        self._pkt(_token(pid, addr, ep), 10)
        if data_pid is not None:
            self._pkt(_data(data_pid, payload or b""))
        if hs is not None:
            self._pkt(bytes([hs]))

    # control ---------------------------------------------------------------
    def control(self, addr: int, setup: bytes, response: bytes = b"", out_data: bytes = b"",
                mps: int = 8, status_hs: int = ACK) -> None:
        self.txn(SETUP_PID, addr, 0, DATA0, setup)
        is_in = setup[0] & 0x80
        toggle = 1
        if is_in:
            self.txn(IN_PID, addr, 0, None, None, NAK)  # a NAK in the data stage
            chunks = [response[i:i + mps] for i in range(0, len(response), mps)] or []
            if response and len(response) % mps == 0 and len(response) < struct.unpack_from("<H", setup, 6)[0]:
                chunks.append(b"")
            for c in chunks:
                self.txn(IN_PID, addr, 0, DATA1 if toggle else DATA0, c)
                toggle ^= 1
            self.txn(OUT_PID, addr, 0, DATA1, b"", status_hs)
        else:
            for i in range(0, len(out_data), mps):
                self.txn(OUT_PID, addr, 0, DATA1 if toggle else DATA0, out_data[i:i + mps])
                toggle ^= 1
            self.txn(IN_PID, addr, 0, DATA1, b"", status_hs)

    def bulk(self, addr: int, ep: int, direction: str, payload: bytes, hs: int = ACK) -> None:
        k = (addr, ep, direction)
        t = self.toggle.get(k, 0)
        self.txn(IN_PID if direction == "IN" else OUT_PID, addr, ep, DATA1 if t else DATA0, payload, hs)
        self.toggle[k] = t ^ 1

    def nak_poll(self, addr: int, ep: int) -> None:
        self.txn(IN_PID, addr, ep, None, None, NAK)

    def transactions(self) -> list[dict]:
        return usbdecode.group_transactions(self.records)


def setup(bm: int, req: int, value: int, index: int, length: int) -> bytes:
    return struct.pack("<BBHHH", bm, req, value, index, length)


def string_desc(s: str) -> bytes:
    body = s.encode("utf-16-le")
    return bytes([2 + len(body), 3]) + body


def by_layer(items, layer):
    return [i for i in items if i["layer"] == layer]


# ---------------------------------------------------------------------------
# HID keyboard enumeration + key reports
# ---------------------------------------------------------------------------

KBD_REPORT_DESC = bytes.fromhex(
    "05010906a101"  # Usage Page GD, Usage Keyboard, Collection Application
    "050719e029e71500250175019508810295017508810195057501050819012905910295017503910195067508"
    "150025650507190029658100c0")

DEVICE_DESC = struct.pack("<BBHBBBBHHHBBBB", 18, 1, 0x0200, 0, 0, 0, 8, 0x046D, 0xC31C, 0x0110, 1, 2, 0, 1)


def kbd_config() -> bytes:
    itf = struct.pack("<BBBBBBBBB", 9, 4, 0, 0, 1, 3, 1, 1, 0)
    hid = struct.pack("<BBHBBBH", 9, 0x21, 0x0111, 0, 1, 0x22, len(KBD_REPORT_DESC))
    ep = struct.pack("<BBBBHB", 7, 5, 0x81, 3, 8, 10)
    body = itf + hid + ep
    return struct.pack("<BBHBBBBB", 9, 2, 9 + len(body), 1, 1, 0, 0xA0, 50) + body


def test_hid_keyboard_enumeration_and_typed_text():
    bus = Bus()
    bus.control(0, setup(0x80, 6, 0x0100, 0, 64), DEVICE_DESC[:8])  # first short read at addr 0
    bus.control(0, setup(0x00, 5, 7, 0, 0))  # SET_ADDRESS 7
    bus.control(7, setup(0x80, 6, 0x0100, 0, 18), DEVICE_DESC)
    cfg = kbd_config()
    bus.control(7, setup(0x80, 6, 0x0200, 0, 9), cfg[:9])
    bus.control(7, setup(0x80, 6, 0x0200, 0, len(cfg)), cfg)
    bus.control(7, setup(0x80, 6, 0x0302, 0x0409, 255), string_desc("USB Keyboard"))
    bus.control(7, setup(0x00, 9, 1, 0, 0))  # SET_CONFIGURATION 1
    bus.control(7, setup(0x21, 0x0A, 0, 0, 0))  # SET_IDLE
    bus.control(7, setup(0x81, 6, 0x2200, 0, len(KBD_REPORT_DESC)), KBD_REPORT_DESC)
    # type "Hi!" : Shift+h, release, i, release, Shift+1, release
    for rep in ("02000b0000000000", "0000000000000000", "00000c0000000000", "0000000000000000",
                "02001e0000000000", "0000000000000000"):
        bus.nak_poll(7, 1)
        bus.bulk(7, 1, "IN", bytes.fromhex(rep))
    # LED output report: CapsLock via SET_REPORT
    bus.control(7, setup(0x21, 0x09, 0x0200, 0, 1), out_data=b"\x02")
    bus.bulk(7, 1, "IN", bytes.fromhex("0000040000000000"))  # 'a' with caps -> 'A'

    res = decode_transactions(bus.transactions())
    items = res["items"]
    json.dumps(res)  # must be JSON-serialisable

    ctl = by_layer(items, "control")
    summaries = [i["summary"] for i in ctl]
    assert any("SET_ADDRESS 7" in s for s in summaries)
    assert any("VID 0x046d PID 0xc31c" in s for s in summaries)
    assert any('"USB Keyboard"' in s for s in summaries)
    assert any(s.startswith("SET_CONFIGURATION 1") for s in summaries)
    assert all(i["details"]["status"] == "ACK" for i in ctl)

    dev = res["devices"]["7"]
    assert dev["vid"] == "0x046d" and dev["pid"] == "0xc31c"
    assert dev["previous_addresses"] == [0]
    assert dev["product"] == "USB Keyboard"
    assert dev["active_configuration"] == 1
    assert dev["endpoints"]["0x81"]["type"] == "interrupt"
    assert dev["interfaces"][0]["label"] == "HID (boot keyboard)"
    assert dev["hid"]["0"]["report_descriptor"]["kind"] == "keyboard"

    hid = by_layer(items, "hid")
    names = [i["details"]["request"] for i in hid if "request" in i["details"]]
    assert "SET_IDLE" in names and "SET_REPORT" in names
    reports = [i for i in hid if "keys" in i["details"]]
    assert len(reports) == 7
    assert reports[0]["details"]["modifiers"] == ["LeftShift"]
    assert reports[0]["details"]["keys"] == ["H"]
    assert reports[0]["details"]["text"] == "H"
    assert "".join(r["details"]["text"] for r in reports) == "Hi!A"
    assert dev["keyboard_text"]["0x81"] == "Hi!A"
    led = [i for i in hid if i["details"].get("leds")]
    assert led and led[0]["details"]["leds"] == ["CapsLock"]


def test_boot_mouse_with_hint():
    bus = Bus()
    bus.bulk(3, 1, "IN", bytes([0x01, 0x05, 0xFE, 0x01]))
    items = decode_transactions(bus.transactions(), hints={"3": {"0x81": "mouse"}})["items"]
    assert len(items) == 1
    d = items[0]["details"]
    assert d["buttons"] == ["Left"] and d["dx"] == 5 and d["dy"] == -2 and d["wheel"] == 1
    assert items[0]["summary"].startswith("Mouse: buttons [Left] dx +5 dy -2")


def test_hid_report_descriptor_parser_mouse_with_report_id():
    desc = bytes.fromhex(
        "05010902a1010901a100"
        "8501"  # report ID 1
        "05091901290315002501950375018102"  # 3 buttons
        "950175058103"  # 5 bits padding
        "05010930093116 01f8 26ff07 750c 9502 8106".replace(" ", "")  # X/Y 12 bits
        + "0938 1581 257f 7508 9501 8106 c0c0".replace(" ", ""))  # wheel
    bus = Bus()
    bus.control(3, setup(0x81, 6, 0x2200, 0, len(desc)), desc)
    # report ID 1, Left button, X = +3, Y = -1 (12-bit each), wheel -1
    xy = (3 & 0xFFF) | ((-1 & 0xFFF) << 12)
    bus.bulk(3, 1, "IN", bytes([1, 0x01]) + xy.to_bytes(3, "little") + bytes([0xFF]))
    # No configuration descriptor: the endpoint hint + the single known layout are used.
    items = decode_transactions(bus.transactions(), hints={3: {"1": "hid"}})["items"]
    mouse = [i for i in items if i["summary"].startswith("Mouse")]
    assert len(mouse) == 1
    d = mouse[0]["details"]
    assert (d["buttons"], d["dx"], d["dy"], d["wheel"], d["report_id"]) == (["Left"], 3, -1, -1, 1)
    lay = parse_hid_report_descriptor(desc)
    assert lay["kind"] == "mouse"
    assert lay["report_ids"] == [1]
    # 1 + (8 bits buttons) + 24 bits x/y + 8 bits wheel = 5 bytes payload
    assert lay["input_reports"][1]["bytes"] == 5


# ---------------------------------------------------------------------------
# CDC-ACM
# ---------------------------------------------------------------------------

def cdc_config() -> bytes:
    itf0 = struct.pack("<BBBBBBBBB", 9, 4, 0, 0, 1, 2, 2, 1, 0)
    hdr = bytes([5, 0x24, 0x00, 0x10, 0x01])
    acm = bytes([4, 0x24, 0x02, 0x02])
    union = bytes([5, 0x24, 0x06, 0, 1])
    ep_int = struct.pack("<BBBBHB", 7, 5, 0x83, 3, 8, 16)
    itf1 = struct.pack("<BBBBBBBBB", 9, 4, 1, 0, 2, 0x0A, 0, 0, 0)
    ep_out = struct.pack("<BBBBHB", 7, 5, 0x02, 2, 64, 0)
    ep_in = struct.pack("<BBBBHB", 7, 5, 0x81, 2, 64, 0)
    body = itf0 + hdr + acm + union + ep_int + itf1 + ep_out + ep_in
    return struct.pack("<BBHBBBBB", 9, 2, 9 + len(body), 2, 1, 0, 0x80, 50) + body


def test_cdc_acm_line_coding_and_data():
    bus = Bus()
    cfg = cdc_config()
    bus.control(4, setup(0x80, 6, 0x0200, 0, len(cfg)), cfg, mps=64)
    bus.control(4, setup(0x00, 9, 1, 0, 0))
    lc = struct.pack("<IBBB", 115200, 0, 0, 8)
    bus.control(4, setup(0x21, 0x20, 0, 0, 7), out_data=lc)
    bus.control(4, setup(0xA1, 0x21, 0, 0, 7), lc)
    bus.control(4, setup(0x21, 0x22, 0x0003, 0, 0))
    for chunk in (b"AT", b"I\r"):
        bus.bulk(4, 2, "OUT", chunk)
        bus.wait_us(1000)
    bus.bulk(4, 2, "OUT", b"AT", hs=NAK)  # NAKed attempt is skipped ...
    bus.wait_us(200_000)  # ... gap larger than the merge window
    bus.nak_poll(4, 1)
    bus.bulk(4, 1, "IN", b"OK\r\n")
    bus.bulk(4, 3, "IN", bytes.fromhex("a120000000000200") + bytes([0x03, 0x00]))

    res = decode_transactions(bus.transactions())
    items = res["items"]
    cdc = by_layer(items, "cdc")
    s = [i["summary"] for i in cdc]
    assert "SET_LINE_CODING: 115200 8N1" in s
    assert "GET_LINE_CODING -> 115200 8N1" in s
    assert "SET_CONTROL_LINE_STATE: DTR=on RTS=on" in s
    note = [i for i in cdc if i["details"].get("notification") == "SERIAL_STATE"]
    assert note and note[0]["details"]["serial_state"]["DCD"] is True
    ser = by_layer(items, "serial")
    assert [i["details"]["text"] for i in ser] == ["ATI\\r", "OK\\r\\n"]
    assert ser[0]["details"]["packets"] == 2 and ser[0]["details"]["stream"] == "TX"
    assert ser[0]["details"]["driver"] == "cdc_acm"
    dev = res["devices"]["4"]
    assert dev["serial"]["baud"] == 115200 and dev["serial"]["dtr"] is True
    assert dev["interfaces"][0]["label"] == "CDC-ACM control"


def test_serial_merge_window_splits_items():
    bus = Bus()
    bus.bulk(9, 2, "OUT", b"a")
    bus.wait_us(80_000)
    bus.bulk(9, 2, "OUT", b"b")
    items = decode_transactions(bus.transactions(), hints={9: "cdc"})["items"]
    assert [i["details"]["text"] for i in items] == ["a", "b"]


# ---------------------------------------------------------------------------
# Mass storage BOT
# ---------------------------------------------------------------------------

def cbw(tag: int, length: int, flags: int, cdb: bytes) -> bytes:
    return struct.pack("<4sIIBBB16s", b"USBC", tag, length, flags, 0, len(cdb), cdb)


def csw(tag: int, residue: int = 0, status: int = 0) -> bytes:
    return struct.pack("<4sIIB", b"USBS", tag, residue, status)


def test_msc_read_capacity_and_read10():
    bus = Bus()
    # READ CAPACITY(10)
    bus.bulk(2, 2, "OUT", cbw(1, 8, 0x80, bytes([0x25] + [0] * 9)))
    bus.bulk(2, 1, "IN", struct.pack(">II", 0x3FFF, 512))
    bus.bulk(2, 1, "IN", csw(1))
    # READ(10) LBA 0x800, 2 blocks
    bus.bulk(2, 2, "OUT", cbw(2, 1024, 0x80, bytes([0x28, 0, 0, 0, 0x08, 0, 0, 0, 2, 0])))
    for _ in range(16):
        bus.bulk(2, 1, "IN", bytes(64))
    bus.bulk(2, 1, "IN", csw(2))
    # failing TEST UNIT READY
    bus.bulk(2, 2, "OUT", cbw(3, 0, 0, bytes(6)))
    bus.bulk(2, 1, "IN", csw(3, status=1))

    res = decode_transactions(bus.transactions(), hints={2: "msc"})
    msc = by_layer(res["items"], "msc")
    s = [i["summary"] for i in msc]
    assert s[0].startswith("CBW tag 0x00000001 LUN 0: READ CAPACITY(10)")
    assert "last LBA 16383, block 512 B" in s[1]
    assert s[2] == "CSW tag 0x00000001: Passed (READ CAPACITY(10))"
    assert "READ(10) LBA 2048 x 2 block(s) (1024 B)" in s[3]
    assert msc[3]["details"]["scsi"]["lba"] == 2048
    assert s[4] == "READ(10) data IN 1024 B"
    assert msc[4]["details"]["length"] == 1024
    assert s[5].startswith("CSW tag 0x00000002: Passed")
    assert "TEST UNIT READY" in s[6] and "no data" in s[6]
    assert s[7].startswith("CSW tag 0x00000003: Failed")
    assert res["devices"]["2"]["msc"]["block_size"] == 512


def test_msc_detected_by_signature_without_hint():
    bus = Bus()
    bus.bulk(5, 2, "OUT", cbw(9, 36, 0x80, bytes([0x12, 0, 0, 0, 36, 0])))
    inq = bytes([0, 0x80, 4, 2, 31, 0, 0, 0]) + b"Generic " + b"Flash Disk      " + b"8.07"
    bus.bulk(5, 1, "IN", inq)
    bus.bulk(5, 1, "IN", csw(9))
    msc = by_layer(decode_transactions(bus.transactions())["items"], "msc")
    assert len(msc) == 3
    assert '"Generic Flash Disk 8.07"' in msc[1]["summary"]


def test_scsi_cdb_write10():
    d = decode_scsi_cdb(bytes([0x2A, 0, 0, 0, 0, 0x10, 0, 0, 8, 0]), 512)
    assert d["name"] == "WRITE(10)" and d["lba"] == 16 and d["blocks"] == 8 and d["bytes"] == 4096


# ---------------------------------------------------------------------------
# Vendor serial chips
# ---------------------------------------------------------------------------

def _ch340_capture(bus: Bus, addr: int = 8) -> None:
    """Real sequence captured from the user's CH340 (device already enumerated)."""
    bus.control(addr, bytes.fromhex("40a19cc38bcc0000"))  # SERIAL_INIT
    bus.control(addr, bytes.fromhex("c0952c2c00000200"), bytes.fromhex("c300"))  # READ_REG 0x2c
    bus.control(addr, bytes.fromhex("409a2c0f07000000"))  # WRITE_REG
    bus.control(addr, bytes.fromhex("c095060700000200"), bytes.fromhex("ff00"))  # READ_REG 0x0706
    bus.control(addr, bytes.fromhex("409a272700000000"))  # WRITE_REG 0x27
    bus.control(addr, bytes.fromhex("40a4ff0000000000"))  # MODEM_CTRL
    bus.bulk(addr, 2, "OUT", bytes.fromhex("0d0a"))


@pytest.mark.parametrize("hints", [None, {8: {"vid": 0x1A86, "pid": 0x7523}}, {"8": "ch340"}])
def test_ch340_real_sequence(hints):
    bus = Bus()
    _ch340_capture(bus)
    res = decode_transactions(bus.transactions(), hints=hints)
    items = res["items"]
    ser = by_layer(items, "serial")
    assert len(ser) == 7
    s = [i["summary"] for i in ser]
    assert s[0].startswith("CH34x SERIAL_INIT 115200 8N1")
    assert ser[0]["details"]["baud"] == 115200
    assert ser[0]["details"]["best_effort"] is True
    assert s[1] == "CH34x READ_REG 0x2c -> c300"
    assert "WRITE_REG 0x2c=0x07, 0x0f BPS_PAD=0x00" in s[2]
    assert ser[3]["details"]["modem_status"] == {"CTS": False, "DSR": False, "RI": False, "DCD": False}
    assert ser[5]["details"]["dtr"] is False and ser[5]["details"]["rts"] is False
    assert ser[6]["details"]["text"] == "\\r\\n"
    assert ser[6]["details"]["driver"] == "ch34x"
    dev = res["devices"]["8"]
    assert dev["driver"] == "ch34x"
    assert dev["driver_source"] == ("heuristic" if hints is None else ("vid_pid" if "vid" in str(hints) else "hint"))
    assert dev["serial"]["baud"] == 115200


def test_ch34x_baud_formula_matches_linux_divisors():
    # Linux ch341_get_divisor: 9600 -> 0xb202 (+0x80 flag), 115200 -> 0xcc03
    assert round(ch34x_baud(0x82, 0xB2)) == 9615
    assert round(ch34x_baud(0x03, 0xCC)) == 115385


def test_ch34x_write_baud_registers():
    bus = Bus()
    bus.control(8, setup(0x40, 0x9A, 0x1312, 0xB282, 0))
    bus.control(8, setup(0x40, 0x9A, 0x2518, 0x00C3, 0))
    ser = by_layer(decode_transactions(bus.transactions(), hints={8: "ch340"})["items"], "serial")
    assert ser[0]["details"]["baud"] == 9600
    assert ser[1]["details"]["data_bits"] == 8 and ser[1]["details"]["parity"] == "none"


def test_ftdi_status_bytes_stripped_and_requests():
    bus = Bus()
    bus.control(6, setup(0x40, 0x03, 0x4138, 0x0000, 0))  # 9600 baud on FT232R
    bus.control(6, setup(0x40, 0x04, 0x0008, 0x0000, 0))  # 8N1
    bus.control(6, setup(0x40, 0x01, 0x0303, 0x0000, 0))  # DTR+RTS on
    bus.control(6, setup(0x40, 0x09, 16, 0, 0))
    for _ in range(3):  # status-only polls -> skipped
        bus.bulk(6, 1, "IN", bytes([0x01, 0x60]))
    bus.bulk(6, 1, "IN", bytes([0x31, 0x60]) + b"hel")
    bus.bulk(6, 1, "IN", bytes([0x31, 0x60]) + b"lo\r\n")
    bus.bulk(6, 2, "OUT", b"cmd\r")
    res = decode_transactions(bus.transactions(), hints={6: {"vid": "0x0403", "pid": "0x6001"}})
    ser = by_layer(res["items"], "serial")
    s = [i["summary"] for i in ser]
    assert s[0] == "FTDI SET_BAUDRATE 9600 (divisor 0x04138)"
    assert s[1] == "FTDI SET_DATA 8N1"
    assert s[2] == "FTDI MODEM_CTRL DTR=on RTS=on"
    assert s[3] == "FTDI SET_LATENCY_TIMER 16 ms"
    rx = [i for i in ser if i["details"].get("stream") == "RX"]
    assert len(rx) == 1 and rx[0]["details"]["text"] == "hello\\r\\n"
    assert rx[0]["details"]["packets"] == 2
    tx = [i for i in ser if i["details"].get("stream") == "TX"]
    assert tx[0]["details"]["text"] == "cmd\\r"
    assert res["devices"]["6"]["serial"]["modem_status"]["CTS"] is True


def test_ftdi_baud_special_values():
    assert ftdi_baud(0, 0, False)[0] == 3_000_000
    assert ftdi_baud(1, 0, False)[0] == 2_000_000
    assert round(ftdi_baud(0x001A, 0, False)[0]) == 115385  # 3 MHz / 26


def test_cp210x_requests():
    bus = Bus()
    bus.control(11, setup(0x41, 0x00, 1, 0, 0))
    bus.control(11, setup(0x41, 0x1E, 0, 0, 4), out_data=struct.pack("<I", 57600))
    bus.control(11, setup(0x41, 0x03, 0x0800, 0, 0))
    bus.control(11, setup(0x41, 0x07, 0x0301, 0, 0))
    bus.bulk(11, 1, "IN", b"boot>")
    res = decode_transactions(bus.transactions(), hints={11: {"vid": 0x10C4, "pid": 0xEA60}})
    s = [i["summary"] for i in by_layer(res["items"], "serial")]
    assert s == ["CP210x IFC_ENABLE enable", "CP210x SET_BAUDRATE: 57600", "CP210x SET_LINE_CTL 8N1",
                 "CP210x SET_MHS DTR=on RTS=off", 'CP210x RX (device->host) 5 B: "boot>"']


# ---------------------------------------------------------------------------
# Misc behaviour
# ---------------------------------------------------------------------------

def test_stall_and_incomplete_control_and_raw_fallback():
    bus = Bus()
    bus.control(5, setup(0x80, 6, 0x0600, 0, 10), status_hs=ACK)  # no data at all
    bus.txn(SETUP_PID, 5, 0, DATA0, setup(0x80, 6, 0x0F00, 0, 5))
    bus.txn(IN_PID, 5, 0, None, None, STALL)
    bus.txn(SETUP_PID, 5, 0, DATA0, setup(0x00, 9, 1, 0, 0))  # never gets a status stage
    bus.bulk(5, 3, "IN", b"\x01\x02")
    items = decode_transactions(bus.transactions())["items"]
    st = [i["details"]["status"] for i in items if i["layer"] == "control"]
    assert st == ["ACK", "STALL", "incomplete"]
    assert items[1]["summary"].endswith("[STALL]")
    raw = by_layer(items, "raw")
    assert raw and raw[0]["summary"] == "EP3 IN 2 B: 0102"


def test_retransmission_is_deduplicated():
    bus = Bus()
    bus.txn(OUT_PID, 1, 2, DATA0, b"x", None)  # device ACK lost
    bus.txn(OUT_PID, 1, 2, DATA0, b"x", ACK)  # host retries same toggle
    bus.txn(OUT_PID, 1, 2, DATA1, b"x", ACK)
    items = decode_transactions(bus.transactions(), hints={1: "serial"})["items"]
    assert items[0]["details"]["text"] == "xx"


def test_incremental_feed_matches_one_shot():
    bus = Bus()
    _ch340_capture(bus)
    txns = bus.transactions()
    dec = UsbClassDecoder()
    out = []
    for i in range(0, len(txns), 3):
        out += dec.feed(txns[i:i + 3])
    out += dec.flush()
    assert [i["summary"] for i in out] == [i["summary"] for i in decode_transactions(txns)["items"]]
    dec.reset()
    assert dec.devices() == {}


def test_invalid_hints_raise():
    with pytest.raises(ValueError):
        UsbClassDecoder(hints={8: "floppy"})
    with pytest.raises(ValueError):
        UsbClassDecoder(hints={"x": "cdc"})


def test_config_parser_partial_header():
    c = parse_config_descriptor(kbd_config()[:9])
    assert c["complete"] is False and c["total_length"] == 34


# ---------------------------------------------------------------------------
# Regression tests: split transactions, bus reset, SET_ADDRESS, FTDI baud, pending items
# ---------------------------------------------------------------------------

SPLIT_PID = 0x78


def test_csplit_setup_without_data_does_not_break_control_transfer():
    """HS hub split: SSPLIT SETUP+DATA0 (ACK), then CSPLIT SETUP with no DATA packet (ACK)."""
    bus = Bus()
    s = setup(0x80, 6, 0x0100, 0, 18)
    bus._pkt(bytes([SPLIT_PID, 0x01, 0x00, 0x00]))  # SSPLIT (content irrelevant to the decoder)
    bus.txn(SETUP_PID, 3, 0, DATA0, s)
    bus._pkt(bytes([SPLIT_PID, 0x81, 0x00, 0x00]))  # CSPLIT
    bus.txn(SETUP_PID, 3, 0, None, None, ACK)       # complete-split SETUP: no data packet
    bus.txn(IN_PID, 3, 0, DATA1, DEVICE_DESC[:8])
    bus.txn(IN_PID, 3, 0, DATA0, DEVICE_DESC[8:16])
    bus.txn(IN_PID, 3, 0, DATA1, DEVICE_DESC[16:])
    bus.txn(OUT_PID, 3, 0, DATA1, b"")
    items = decode_transactions(bus.transactions())["items"]
    summaries = [i["summary"] for i in items]
    assert not any("malformed SETUP" in x or "outside a control transfer" in x for x in summaries), summaries
    ctl = [i for i in items if i["layer"] == "control"]
    assert len(ctl) == 1 and ctl[0]["details"]["status"] == "ACK"
    assert ctl[0]["details"]["data_len"] == 18


def test_bus_reset_reports_aborted_control_transfer():
    """Windows legacy enumeration: GET_DESCRIPTOR(DEVICE) cut short by a port reset after 8 bytes."""
    txns = [
        {"seq": 0, "t_us": 0.0, "type": "SETUP", "addr": 0, "ep": 0, "data_pid": "DATA0",
         "data_hex": setup(0x80, 6, 0x0100, 0, 64).hex(), "data_len": 8, "handshake": "ACK", "crc_ok": True},
        {"seq": 3, "t_us": 10.0, "type": "IN", "addr": 0, "ep": 0, "data_pid": "DATA1",
         "data_hex": DEVICE_DESC[:8].hex(), "data_len": 8, "handshake": "ACK", "crc_ok": True},
        {"seq": 6, "t_us": 20.0, "type": "EVENT", "event": "BUS_RESET"},
    ]
    res = decode_transactions(txns)
    ctl = [i for i in res["items"] if i["details"].get("request")]
    assert len(ctl) == 1 and ctl[0]["details"]["status"] == "aborted by reset"
    assert "descriptor" in ctl[0]["details"]
    assert res["devices"]["0"]["device_descriptor"]["max_packet0"] == 8
    assert any(i["details"].get("event") == "BUS_RESET" for i in res["items"])


def test_set_address_needs_acked_status_and_retry_keeps_model():
    bus = Bus()
    bus.control(0, setup(0x80, 6, 0x0100, 0, 18), DEVICE_DESC)
    # First SET_ADDRESS: no status stage at all (host retries).
    bus.txn(SETUP_PID, 0, 0, DATA0, setup(0x00, 5, 5, 0, 0))
    bus.control(0, setup(0x00, 5, 5, 0, 0))  # retry, status ACKed
    res = decode_transactions(bus.transactions())
    sa = [i for i in res["items"] if "SET_ADDRESS" in i["summary"]]
    assert [i["details"]["status"] for i in sa] == ["incomplete", "ACK"]
    assert "5" in res["devices"]
    assert res["devices"]["5"]["vid"] == "0x046d"  # the learned model moved once, not replaced


def test_move_device_does_not_replace_learned_model():
    dec = UsbClassDecoder()
    learned = dec._dev(5)
    learned.device = {"complete": True}
    dec._dev(0)  # fresh, empty model at address 0
    dec._move_device(0, 5)
    assert dec._devices[5] is learned and 0 in learned.previous_addresses


def test_ftdi_baud_multiport_channel_and_h_specials():
    # FT2232 channel B at 9600, chip unknown: wIndex = 0x0002 (interface B, no divisor high bits).
    baud, info = ftdi_baud(0x4138, 0x0002)
    assert round(baud) == 9600 and info["port"] == 2
    # wIndex 1 is ambiguous: alternative reading reported.
    _baud, info = ftdi_baud(0x4138, 0x0001)
    assert "alternative" in info
    # H-series special encodings: 0 -> 12 Mbaud, 1 -> 8 Mbaud (bit 17 set, in wIndex high byte).
    assert ftdi_baud(0x0000, 0x0201, True)[0] == 12_000_000
    assert ftdi_baud(0x0001, 0x0201, True)[0] == 8_000_000


def test_pending_start_seq_points_at_open_control_transfer():
    txns = [
        {"seq": 140, "t_us": 0.0, "type": "SETUP", "addr": 4, "ep": 0, "data_pid": "DATA0",
         "data_hex": setup(0x80, 6, 0x0100, 0, 18).hex(), "data_len": 8, "handshake": "ACK", "crc_ok": True},
        {"seq": 145, "t_us": 10.0, "type": "IN", "addr": 4, "ep": 0, "data_pid": "DATA1",
         "data_hex": DEVICE_DESC.hex(), "data_len": 18, "handshake": "ACK", "crc_ok": True},
    ]
    res = decode_transactions(txns)
    assert res["pending_start_seq"] == 140
    txns.append({"seq": 155, "t_us": 20.0, "type": "OUT", "addr": 4, "ep": 0, "data_pid": "DATA1",
                 "data_hex": "", "data_len": 0, "handshake": "ACK", "crc_ok": True})
    assert decode_transactions(txns)["pending_start_seq"] is None
