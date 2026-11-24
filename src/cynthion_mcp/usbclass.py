"""USB class-level decoder for Cynthion analyzer transactions.

Pure Python, stdlib only, no hardware access.  It consumes the transaction
dicts produced by :func:`cynthion_mcp.usbdecode.group_transactions` and turns
them into higher-level, human-readable items.

Public API
----------
``UsbClassDecoder(hints=None, merge_window_us=50_000.0)``
    Stateful decoder (keeps a per-address device model across calls).

    * ``feed(transactions) -> list[dict]``: decode a batch of transactions and
      return the items completed by this batch, sorted by ``seq``.  Control
      transfers still waiting for their status stage stay pending until a later
      ``feed`` or ``flush``.  Serial data buffers are flushed at the end of each
      call (they are only merged inside one batch).
    * ``flush() -> list[dict]``: finish everything still pending (control
      transfers without status stage are reported with status ``"incomplete"``,
      mass-storage data phases without CSW are reported as is).
    * ``devices() -> dict``: the learned device model, keyed by ``str(address)``.
    * ``reset()``: forget everything (hints are kept).

``decode_transactions(transactions, hints=None) -> {"items": [...], "devices": {...}, "pending_start_seq": int|None}``
    One-shot helper: ``feed`` + ``flush`` on a fresh decoder.  ``pending_start_seq`` is the
    smallest start seq of the items that were still open before the flush
    (see ``UsbClassDecoder.pending_start_seq``).

Item format
-----------
``{"seq", "t_us", "addr", "ep", "layer", "summary", "details"}`` where

* ``seq`` / ``t_us``: first transaction of the item (SETUP for control transfers);
* ``ep``: endpoint *number* (direction is in ``details["direction"]`` when relevant);
* ``layer``: ``"control"`` (standard requests, bus reset), ``"hid"``, ``"cdc"``
  (CDC-ACM class requests and notifications), ``"msc"`` (Bulk-Only Transport +
  SCSI), ``"serial"`` (serial payload of CDC-ACM data interfaces and vendor
  USB-serial chips, plus CH34x/FTDI/CP210x vendor requests) or ``"raw"``;
* ``summary``: one-line English description;
* ``details``: layer-specific dict (always JSON-serialisable).

Control-transfer items carry ``details["request"]``, ``details["setup"]``,
``details["data_hex"]``, ``details["data_len"]`` and ``details["status"]``
(``"ACK"``, ``"STALL"``, ``"unacknowledged"``, ``"incomplete"`` or
``"aborted by reset"`` when a bus reset interrupts the transfer).

Hints
-----
Mid-session captures usually miss the enumeration, so the decoder accepts
hints keyed by device address (int or str such as ``"8"``)::

    {8: {"vid": 0x1a86, "pid": 0x7523}}         # vendor chip from VID/PID
    {8: "ch340"}                                  # driver name
    {8: {"driver": "ftdi"}}
    {5: {2: "cdc", "0x81": "keyboard"}}            # per endpoint
    {5: {"endpoints": {"1": "msc"}}}

Driver / endpoint kinds: ``cdc`` (CDC-ACM), ``serial`` (generic serial text),
``ch34x`` (aliases ch340, ch341), ``ftdi``, ``cp210x``, ``hid``, ``keyboard``,
``mouse``, ``msc``, ``raw``.  An endpoint key below 0x80 applies to both
directions; ``0x81``-style keys only to that IN endpoint.

Without descriptors nor hints the decoder falls back to heuristics: CH34x
vendor request codes (0xA1/0x9A/0x95/0xA4/0x5F), CP210x interface vendor
requests, Bulk-Only CBW/CSW signatures and 8-byte boot-keyboard reports.  Those
guesses are flagged with ``driver_source == "heuristic"`` / ``best_effort``.
"""

from __future__ import annotations

import struct
from typing import Any, Iterable

from .usbdecode import decode_setup

__all__ = [
    "UsbClassDecoder",
    "decode_transactions",
    "parse_device_descriptor",
    "parse_config_descriptor",
    "parse_string_descriptor",
    "parse_hid_report_descriptor",
    "decode_scsi_cdb",
    "ch34x_baud",
    "ftdi_baud",
    "LAYERS",
]

LAYERS = ("control", "hid", "cdc", "msc", "serial", "raw")

MAX_HEX_BYTES = 1024  # cap of hex dumps in item details
MSC_KEEP_BYTES = 4096  # data kept per SCSI data phase for interpretation

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------


def _to_int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v.strip(), 0)
        except ValueError:
            return None
    return None


def _hex(b: bytes, limit: int = MAX_HEX_BYTES) -> str:
    return bytes(b[:limit]).hex()


def escape_text(b: bytes) -> str:
    """Render bytes as readable text: printable ASCII kept, \\r \\n \\t escaped, others \\xNN."""
    out: list[str] = []
    for c in b:
        if c == 0x0D:
            out.append("\\r")
        elif c == 0x0A:
            out.append("\\n")
        elif c == 0x09:
            out.append("\\t")
        elif c == 0x5C:
            out.append("\\\\")
        elif 0x20 <= c < 0x7F:
            out.append(chr(c))
        else:
            out.append(f"\\x{c:02x}")
    return "".join(out)


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    ok = sum(1 for c in b if 0x20 <= c < 0x7F or c in (0x09, 0x0A, 0x0D))
    return round(ok / len(b), 3)


def _clip(s: str, n: int = 100) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


def _bcd(v: int) -> str:
    return f"{v >> 8:x}.{v & 0xFF:02x}"


def _s8(v: int) -> int:
    return v - 256 if v & 0x80 else v


_STD_BAUDS = (300, 600, 1200, 2400, 4800, 9600, 14400, 19200, 28800, 38400, 57600,
              76800, 115200, 128000, 153600, 230400, 250000, 256000, 460800, 500000,
              921600, 1000000, 1500000, 2000000, 3000000)


def _nominal_baud(baud: float | None) -> int | None:
    if not baud:
        return None
    best = min(_STD_BAUDS, key=lambda s: abs(s - baud))
    return best if abs(best - baud) / best <= 0.025 else None


_PARITY_LETTER = {"none": "N", "odd": "O", "even": "E", "mark": "M", "space": "S"}


def _line_str(baud: Any, data_bits: Any, parity: Any, stop: Any) -> str:
    p = _PARITY_LETTER.get(str(parity), "?")
    b = f"{baud} " if baud is not None else ""
    return f"{b}{data_bits if data_bits is not None else '?'}{p}{stop if stop is not None else '?'}"


# ---------------------------------------------------------------------------
# Descriptor parsing
# ---------------------------------------------------------------------------

CLASS_NAMES = {
    0x00: "Per-interface", 0x01: "Audio", 0x02: "CDC Communications", 0x03: "HID",
    0x05: "Physical", 0x06: "Image", 0x07: "Printer", 0x08: "Mass Storage", 0x09: "Hub",
    0x0A: "CDC Data", 0x0B: "Smart Card", 0x0D: "Content Security", 0x0E: "Video",
    0x0F: "Personal Healthcare", 0x10: "Audio/Video", 0x11: "Billboard", 0x12: "USB-C Bridge",
    0xDC: "Diagnostic", 0xE0: "Wireless Controller", 0xEF: "Miscellaneous",
    0xFE: "Application Specific", 0xFF: "Vendor Specific",
}

DESCRIPTOR_NAMES = {
    1: "DEVICE", 2: "CONFIGURATION", 3: "STRING", 4: "INTERFACE", 5: "ENDPOINT",
    6: "DEVICE_QUALIFIER", 7: "OTHER_SPEED_CONFIGURATION", 8: "INTERFACE_POWER",
    0x0B: "INTERFACE_ASSOCIATION", 0x0F: "BOS", 0x21: "HID", 0x22: "HID_REPORT", 0x23: "HID_PHYSICAL",
}

_EP_TYPES = ("control", "isochronous", "bulk", "interrupt")


def _class_name(c: int | None) -> str:
    if c is None:
        return "unknown"
    return CLASS_NAMES.get(c, f"0x{c:02x}")


def _interface_label(itf: dict[str, Any]) -> str:
    c, s, p = itf.get("class"), itf.get("subclass"), itf.get("protocol")
    if c == 3:
        kind = {1: "keyboard", 2: "mouse"}.get(p) if s == 1 else None
        return f"HID ({'boot ' + kind if kind else 'generic'})"
    if c == 2 and s == 2:
        return "CDC-ACM control"
    if c == 8:
        bits = []
        if s == 6:
            bits.append("SCSI")
        if p == 0x50:
            bits.append("Bulk-Only")
        return "Mass Storage" + (f" ({', '.join(bits)})" if bits else "")
    return _class_name(c)


def parse_device_descriptor(data: bytes) -> dict[str, Any]:
    """Parse a (possibly partial, >= 8 bytes) DEVICE descriptor."""
    data = bytes(data)
    d: dict[str, Any] = {"length": len(data), "complete": len(data) >= 18}
    if len(data) < 8:
        d["error"] = f"too short ({len(data)} bytes)"
        return d
    _bl, _bt, bcd_usb, cls, sub, proto, mps0 = struct.unpack_from("<BBHBBBB", data)
    d.update(bcdUSB=_bcd(bcd_usb), device_class=cls, class_name=_class_name(cls),
             subclass=sub, protocol=proto, max_packet0=mps0)
    if len(data) >= 18:
        vid, pid, bcd_dev, imf, iprod, iser, ncfg = struct.unpack_from("<HHHBBBB", data, 8)
        d.update(idVendor=vid, idProduct=pid, vid=f"0x{vid:04x}", pid=f"0x{pid:04x}",
                 bcdDevice=_bcd(bcd_dev), iManufacturer=imf, iProduct=iprod,
                 iSerialNumber=iser, num_configurations=ncfg)
    return d


def _parse_cdc_functional(body: bytes) -> dict[str, Any]:
    sub = body[2] if len(body) > 2 else -1
    names = {0x00: "Header", 0x01: "Call Management", 0x02: "ACM", 0x06: "Union",
             0x0F: "Ethernet Networking", 0x1A: "NCM"}
    f: dict[str, Any] = {"subtype": f"0x{sub:02x}", "name": names.get(sub, f"subtype 0x{sub:02x}")}
    if sub == 0x00 and len(body) >= 5:
        f["bcdCDC"] = _bcd(body[3] | (body[4] << 8))
    elif sub == 0x01 and len(body) >= 5:
        f["capabilities"] = f"0x{body[3]:02x}"
        f["data_interface"] = body[4]
    elif sub == 0x02 and len(body) >= 4:
        caps = body[3]
        f["capabilities"] = f"0x{caps:02x}"
        f["supports"] = [n for bit, n in ((1, "comm_feature"), (2, "line_coding+control_line_state"),
                                          (4, "send_break"), (8, "network_connection")) if caps & bit]
    elif sub == 0x06 and len(body) >= 5:
        f["control_interface"] = body[3]
        f["data_interfaces"] = list(body[4:])
    return f


def parse_config_descriptor(data: bytes) -> dict[str, Any]:
    """Parse a CONFIGURATION descriptor and its interfaces/endpoints/class descriptors.

    ``complete`` is False when fewer than wTotalLength bytes were captured
    (typical first 9-byte read); interfaces are still parsed as far as possible.
    """
    data = bytes(data)
    if len(data) < 9 or data[1] != 2:
        return {"length": len(data), "complete": False, "error": "not a configuration descriptor",
                "interfaces": []}
    _bl, _bt, total, nif, value, icfg, attrs, maxp = struct.unpack_from("<BBHBBBBB", data)
    cfg: dict[str, Any] = {
        "value": value, "total_length": total, "length": len(data),
        "complete": len(data) >= total, "num_interfaces": nif, "iConfiguration": icfg,
        "attributes": f"0x{attrs:02x}", "self_powered": bool(attrs & 0x40),
        "remote_wakeup": bool(attrs & 0x20), "max_power_ma": maxp * 2,
        "interfaces": [], "associations": [],
    }
    end = min(len(data), total) if total >= 9 else len(data)
    pos = max(data[0], 9)
    cur: dict[str, Any] | None = None
    while pos + 2 <= end:
        bl, bt = data[pos], data[pos + 1]
        if bl < 2 or pos + bl > end:
            break
        body = data[pos:pos + bl]
        if bt == 4 and bl >= 9:
            num, alt, nep, c, s, p, istr = struct.unpack_from("<BBBBBBB", body, 2)
            cur = {"number": num, "alt": alt, "num_endpoints": nep, "class": c,
                   "class_name": _class_name(c), "subclass": s, "protocol": p,
                   "iInterface": istr, "endpoints": []}
            cur["label"] = _interface_label(cur)
            cfg["interfaces"].append(cur)
        elif bt == 5 and bl >= 7:
            addr, att, mps, interval = struct.unpack_from("<BBHB", body, 2)
            ep = {"address": f"0x{addr:02x}", "number": addr & 0x0F,
                  "direction": "IN" if addr & 0x80 else "OUT", "type": _EP_TYPES[att & 3],
                  "max_packet": mps & 0x7FF, "interval": interval}
            if (mps >> 11) & 3:
                ep["extra_transactions"] = (mps >> 11) & 3
            if cur is not None:
                cur["endpoints"].append(ep)
        elif bt == 0x0B and bl >= 8:
            first, count, c, s, p, istr = struct.unpack_from("<BBBBBB", body, 2)
            cfg["associations"].append({"first_interface": first, "interface_count": count,
                                        "class": c, "class_name": _class_name(c),
                                        "subclass": s, "protocol": p})
        elif bt == 0x21 and cur is not None and cur["class"] == 3 and bl >= 6:
            bcd_hid, country, ndesc = struct.unpack_from("<HBB", body, 2)
            hid: dict[str, Any] = {"bcdHID": _bcd(bcd_hid), "country_code": country}
            for k in range(ndesc):
                o = 6 + 3 * k
                if o + 3 > bl:
                    break
                dtype, dlen = body[o], body[o + 1] | (body[o + 2] << 8)
                if dtype == 0x22:
                    hid["report_descriptor_length"] = dlen
            cur["hid"] = hid
        elif bt == 0x24 and cur is not None:
            cur.setdefault("cdc_functional", []).append(_parse_cdc_functional(body))
        elif cur is not None:
            cur.setdefault("other_descriptors", []).append({"type": f"0x{bt:02x}", "length": bl})
        pos += bl
    return cfg


def parse_string_descriptor(data: bytes, index: int) -> dict[str, Any]:
    """Parse a STRING descriptor (index 0 -> language IDs, else UTF-16LE text)."""
    data = bytes(data)
    if len(data) < 2:
        return {"index": index, "error": "too short"}
    bl = min(data[0], len(data))
    body = data[2:bl]
    if index == 0:
        langs = [f"0x{body[i] | (body[i + 1] << 8):04x}" for i in range(0, len(body) - 1, 2)]
        return {"index": 0, "languages": langs}
    if len(body) & 1:
        body = body[:-1]
    return {"index": index, "text": body.decode("utf-16-le", errors="replace"),
            "truncated": data[0] > len(data)}


def _device_summary(d: dict[str, Any]) -> str:
    if "error" in d:
        return f"device descriptor ({d['error']})"
    if not d.get("complete"):
        return f"partial device descriptor: USB {d['bcdUSB']}, EP0 max packet {d['max_packet0']}"
    return (f"VID {d['vid']} PID {d['pid']}, USB {d['bcdUSB']}, class {d['class_name']}, "
            f"EP0 {d['max_packet0']} B, {d['num_configurations']} configuration(s)")


def _config_summary(c: dict[str, Any]) -> str:
    if "error" in c:
        return c["error"]
    head = f"config {c['value']}, {c['num_interfaces']} interface(s), {c['max_power_ma']} mA"
    if not c["complete"]:
        return f"{head} (header only, {c['length']}/{c['total_length']} bytes)"
    parts = []
    for itf in c["interfaces"]:
        eps = ", ".join(f"{e['address']} {e['type']}" for e in itf["endpoints"])
        alt = f" alt {itf['alt']}" if itf["alt"] else ""
        parts.append(f"if{itf['number']}{alt} {itf['label']}" + (f" [{eps}]" if eps else ""))
    return head + ": " + "; ".join(parts)


# ---------------------------------------------------------------------------
# HID
# ---------------------------------------------------------------------------

_MOD_NAMES = ("LeftCtrl", "LeftShift", "LeftAlt", "LeftGUI",
              "RightCtrl", "RightShift", "RightAlt", "RightGUI")

_KEY_NAMES: dict[int, str] = {}
_KEY_CHARS: dict[int, tuple[str, str]] = {}
for _i in range(26):
    _KEY_NAMES[0x04 + _i] = chr(65 + _i)
    _KEY_CHARS[0x04 + _i] = (chr(97 + _i), chr(65 + _i))
for _i, (_a, _b) in enumerate(zip("1234567890", "!@#$%^&*()")):
    _KEY_NAMES[0x1E + _i] = _a
    _KEY_CHARS[0x1E + _i] = (_a, _b)
for _code, _a, _b in ((0x2D, "-", "_"), (0x2E, "=", "+"), (0x2F, "[", "{"), (0x30, "]", "}"),
                      (0x31, "\\", "|"), (0x32, "#", "~"), (0x33, ";", ":"), (0x34, "'", '"'),
                      (0x35, "`", "~"), (0x36, ",", "<"), (0x37, ".", ">"), (0x38, "/", "?")):
    _KEY_NAMES[_code] = _a
    _KEY_CHARS[_code] = (_a, _b)
_KEY_NAMES.update({0x28: "Enter", 0x29: "Escape", 0x2A: "Backspace", 0x2B: "Tab", 0x2C: "Space",
                   0x39: "CapsLock", 0x46: "PrintScreen", 0x47: "ScrollLock", 0x48: "Pause",
                   0x49: "Insert", 0x4A: "Home", 0x4B: "PageUp", 0x4C: "Delete", 0x4D: "End",
                   0x4E: "PageDown", 0x4F: "Right", 0x50: "Left", 0x51: "Down", 0x52: "Up",
                   0x53: "NumLock", 0x54: "KP/", 0x55: "KP*", 0x56: "KP-", 0x57: "KP+",
                   0x58: "KPEnter", 0x63: "KP.", 0x64: "NonUS\\", 0x65: "Application",
                   0x66: "Power", 0x01: "ErrorRollOver"})
for _i in range(12):
    _KEY_NAMES[0x3A + _i] = f"F{_i + 1}"
for _i in range(9):
    _KEY_NAMES[0x59 + _i] = f"KP{_i + 1}"
    _KEY_CHARS[0x59 + _i] = (str(_i + 1), str(_i + 1))
_KEY_NAMES[0x62] = "KP0"
_KEY_CHARS.update({0x28: ("\n", "\n"), 0x2B: ("\t", "\t"), 0x2C: (" ", " "), 0x62: ("0", "0"),
                   0x54: ("/", "/"), 0x55: ("*", "*"), 0x56: ("-", "-"), 0x57: ("+", "+"),
                   0x58: ("\n", "\n"), 0x63: (".", "."), 0x64: ("\\", "|")})
for _i in range(0xE0, 0xE8):
    _KEY_NAMES[_i] = _MOD_NAMES[_i - 0xE0]


def key_name(code: int) -> str:
    return _KEY_NAMES.get(code, f"0x{code:02x}")


_HID_REQUESTS = {0x01: "GET_REPORT", 0x02: "GET_IDLE", 0x03: "GET_PROTOCOL",
                 0x09: "SET_REPORT", 0x0A: "SET_IDLE", 0x0B: "SET_PROTOCOL"}
_HID_REPORT_TYPES = {1: "Input", 2: "Output", 3: "Feature"}
_GD_USAGES = {0x01: "Pointer", 0x02: "Mouse", 0x04: "Joystick", 0x05: "Gamepad", 0x06: "Keyboard",
              0x07: "Keypad", 0x08: "Multi-axis Controller", 0x30: "X", 0x31: "Y", 0x32: "Z",
              0x33: "Rx", 0x34: "Ry", 0x35: "Rz", 0x36: "Slider", 0x37: "Dial", 0x38: "Wheel",
              0x39: "Hat switch", 0x80: "System Control"}
_CONSUMER_USAGES = {0x01: "Consumer Control", 0xB5: "Next Track", 0xB6: "Previous Track",
                    0xB7: "Stop", 0xCD: "Play/Pause", 0xE2: "Mute", 0xE9: "Volume Up",
                    0xEA: "Volume Down", 0x183: "Media Select", 0x18A: "Mail", 0x192: "Calculator",
                    0x194: "My Computer", 0x221: "WWW Search", 0x223: "WWW Home", 0x224: "WWW Back",
                    0x225: "WWW Forward", 0x238: "AC Pan"}
_PAGE_NAMES = {0x01: "Generic Desktop", 0x07: "Keyboard", 0x08: "LED", 0x09: "Button",
               0x0C: "Consumer", 0x0D: "Digitizer", 0xFF00: "Vendor"}


def _usage_name(page: int, usage: int) -> str:
    if page == 0x01:
        return _GD_USAGES.get(usage, f"GD 0x{usage:02x}")
    if page == 0x07:
        return key_name(usage)
    if page == 0x09:
        return f"Button {usage}"
    if page == 0x0C:
        return _CONSUMER_USAGES.get(usage, f"Consumer 0x{usage:03x}")
    return f"0x{page:04x}:0x{usage:04x}"


def parse_hid_report_descriptor(data: bytes) -> dict[str, Any]:
    """Simple HID report-descriptor parser.

    Returns top-level collections, report IDs and, per report ID, the bit
    layout of input/output/feature reports (enough to decode keyboards, mice
    and simple consumer controls).
    """
    data = bytes(data)
    g = {"page": 0, "lmin": 0, "lmax": 0, "size": 0, "count": 0, "rid": 0}
    stack: list[dict[str, int]] = []
    usages: list[tuple[int | None, int]] = []
    umin: tuple[int | None, int] | None = None
    umax: tuple[int | None, int] | None = None
    depth = 0
    collections: list[dict[str, Any]] = []
    reports: dict[str, dict[int, dict[str, Any]]] = {"input": {}, "output": {}, "feature": {}}
    rids: set[int] = set()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b == 0xFE:  # long item
            if i + 1 >= n:
                break
            i += 3 + data[i + 1]
            continue
        size = (0, 1, 2, 4)[b & 3]
        typ = (b >> 2) & 3
        tag = b >> 4
        raw = data[i + 1:i + 1 + size]
        i += 1 + size
        if len(raw) < size:
            break
        uval = int.from_bytes(raw, "little")
        sval = uval - (1 << (8 * size)) if size and uval & (1 << (8 * size - 1)) else uval
        if typ == 1:  # global
            if tag == 0:
                g["page"] = uval
            elif tag == 1:
                g["lmin"] = sval
            elif tag == 2:
                g["lmax"] = sval if sval >= g["lmin"] else uval
            elif tag == 7:
                g["size"] = uval
            elif tag == 8:
                g["rid"] = uval
                rids.add(uval)
            elif tag == 9:
                g["count"] = uval
            elif tag == 10:
                stack.append(dict(g))
            elif tag == 11 and stack:
                g = stack.pop()
        elif typ == 2:  # local
            u = (uval >> 16, uval & 0xFFFF) if size == 4 else (None, uval)
            if tag == 0:
                usages.append(u)
            elif tag == 1:
                umin = u
            elif tag == 2:
                umax = u
        elif typ == 0:  # main
            if tag in (8, 9, 11):
                kind = {8: "input", 9: "output", 11: "feature"}[tag]
                rep = reports[kind].setdefault(g["rid"], {"bits": 0, "fields": []})
                field = {
                    "bit_offset": rep["bits"], "size": g["size"], "count": g["count"],
                    "usage_page": g["page"], "constant": bool(uval & 1), "variable": bool(uval & 2),
                    "relative": bool(uval & 4), "logical_min": g["lmin"], "logical_max": g["lmax"],
                    "usages": [((p if p is not None else g["page"]), u) for p, u in usages],
                }
                if umin is not None and umax is not None:
                    field["usage_min"] = ((umin[0] if umin[0] is not None else g["page"]), umin[1])
                    field["usage_max"] = umax[1]
                rep["bits"] += g["size"] * g["count"]
                if not field["constant"]:
                    rep["fields"].append(field)
            elif tag == 10:
                if depth == 0:
                    first = usages[0] if usages else (None, 0)
                    page = first[0] if first[0] is not None else g["page"]
                    collections.append({"usage_page": page, "usage": first[1],
                                        "name": _usage_name(page, first[1])})
                depth += 1
            elif tag == 12:
                depth = max(0, depth - 1)
            usages, umin, umax = [], None, None
    kinds = {(c["usage_page"], c["usage"]) for c in collections}
    if (1, 6) in kinds:
        kind = "keyboard"
    elif (1, 2) in kinds:
        kind = "mouse"
    elif (0x0C, 1) in kinds:
        kind = "consumer"
    else:
        kind = "generic"
    out: dict[str, Any] = {"length": n, "kind": kind, "collections": collections,
                           "report_ids": sorted(r for r in rids if r), "uses_report_ids": bool(rids - {0})}
    for k, reps in reports.items():
        out[f"{k}_reports"] = {rid: {"bytes": (r["bits"] + 7) // 8, "fields": r["fields"]}
                               for rid, r in reps.items()}
    return out


def _hid_extract(body: bytes, field: dict[str, Any]) -> list[int]:
    val = int.from_bytes(body, "little")
    size = field["size"]
    if size <= 0 or size > 32:
        return []
    mask = (1 << size) - 1
    signed = field["logical_min"] < 0
    vals = []
    for k in range(field["count"]):
        off = field["bit_offset"] + k * size
        if off + size > len(body) * 8:
            break
        v = (val >> off) & mask
        if signed and v & (1 << (size - 1)):
            v -= 1 << size
        vals.append(v)
    return vals


def _hid_apply_layout(layout: dict[str, Any], data: bytes) -> dict[str, Any] | None:
    reps = layout.get("input_reports") or {}
    if layout.get("uses_report_ids"):
        if not data:
            return None
        rid, body = data[0], data[1:]
    else:
        rid, body = 0, data
    rep = reps.get(rid)
    if rep is None:
        return None
    res: dict[str, Any] = {"report_id": rid if layout.get("uses_report_ids") else None}
    mods = 0
    keys: list[int] = []
    has_kbd = False
    buttons: list[int] = []
    has_buttons = False
    axes: dict[str, int] = {}
    consumer: list[str] = []
    values: list[dict[str, Any]] = []
    for f in rep["fields"]:
        vals = _hid_extract(body, f)
        if f["variable"]:
            for k, v in enumerate(vals):
                if k < len(f["usages"]):
                    page, usage = f["usages"][k]
                elif "usage_min" in f:
                    page, usage = f["usage_min"][0], f["usage_min"][1] + k
                elif f["usages"]:
                    page, usage = f["usages"][-1]
                else:
                    page, usage = f["usage_page"], 0
                if page == 7:
                    has_kbd = True
                    if 0xE0 <= usage <= 0xE7:
                        if v:
                            mods |= 1 << (usage - 0xE0)
                    elif v:
                        keys.append(usage)
                elif page == 9:
                    has_buttons = True
                    if v:
                        buttons.append(usage)
                elif page == 1 and usage in (0x30, 0x31, 0x32, 0x38):
                    axes[{0x30: "x", 0x31: "y", 0x32: "z", 0x38: "wheel"}[usage]] = v
                elif page == 0x0C and usage == 0x238:
                    axes["pan"] = v
                elif page == 0x0C:
                    if v:
                        consumer.append(_usage_name(page, usage))
                elif len(values) < 32:
                    values.append({"usage": _usage_name(page, usage), "value": v})
        else:  # array
            for v in vals:
                idx = v - f["logical_min"]
                if "usage_min" in f:
                    page, usage = f["usage_min"][0], f["usage_min"][1] + idx
                elif 0 <= idx < len(f["usages"]):
                    page, usage = f["usages"][idx]
                else:
                    continue
                if page == 7:
                    has_kbd = True
                    if usage > 3:
                        if 0xE0 <= usage <= 0xE7:
                            mods |= 1 << (usage - 0xE0)
                        else:
                            keys.append(usage)
                elif page == 0x0C:
                    if usage:
                        consumer.append(_usage_name(page, usage))
                elif usage and len(values) < 32:
                    values.append({"usage": _usage_name(page, usage), "value": 1})
    if has_kbd:
        res["modifiers"] = mods
        res["keys"] = keys
    if has_buttons or "x" in axes:
        res["buttons"] = buttons
        res.update(axes)
    elif axes:
        res.update(axes)
    if consumer:
        res["consumer"] = consumer
    if values:
        res["values"] = values
    return res


# ---------------------------------------------------------------------------
# Mass storage / SCSI
# ---------------------------------------------------------------------------

SCSI_OPCODES = {
    0x00: "TEST UNIT READY", 0x03: "REQUEST SENSE", 0x04: "FORMAT UNIT", 0x08: "READ(6)",
    0x0A: "WRITE(6)", 0x12: "INQUIRY", 0x15: "MODE SELECT(6)", 0x1A: "MODE SENSE(6)",
    0x1B: "START STOP UNIT", 0x1D: "SEND DIAGNOSTIC", 0x1E: "PREVENT ALLOW MEDIUM REMOVAL",
    0x23: "READ FORMAT CAPACITIES", 0x25: "READ CAPACITY(10)", 0x28: "READ(10)",
    0x2A: "WRITE(10)", 0x2F: "VERIFY(10)", 0x35: "SYNCHRONIZE CACHE(10)", 0x55: "MODE SELECT(10)",
    0x5A: "MODE SENSE(10)", 0x88: "READ(16)", 0x8A: "WRITE(16)", 0x9E: "SERVICE ACTION IN(16)",
    0xA0: "REPORT LUNS", 0xA8: "READ(12)", 0xAA: "WRITE(12)",
}
SENSE_KEYS = ("NO SENSE", "RECOVERED ERROR", "NOT READY", "MEDIUM ERROR", "HARDWARE ERROR",
              "ILLEGAL REQUEST", "UNIT ATTENTION", "DATA PROTECT", "BLANK CHECK", "VENDOR SPECIFIC",
              "COPY ABORTED", "ABORTED COMMAND", "RESERVED", "VOLUME OVERFLOW", "MISCOMPARE",
              "COMPLETED")
_CSW_STATUS = {0: "Passed", 1: "Failed", 2: "Phase Error"}


def decode_scsi_cdb(cdb: bytes, block_size: int | None = None) -> dict[str, Any]:
    """Decode a SCSI command descriptor block (as carried in a CBW)."""
    cdb = bytes(cdb)
    if not cdb:
        return {"name": "EMPTY CDB", "summary": "empty CDB"}
    op = cdb[0]
    name = SCSI_OPCODES.get(op, f"OPCODE 0x{op:02x}")
    d: dict[str, Any] = {"opcode": f"0x{op:02x}", "name": name}
    c = cdb + bytes(16)  # pad for safe unpacking
    lba = blocks = None
    if op in (0x28, 0x2A, 0x2F, 0x35):
        lba, blocks = struct.unpack_from(">I", c, 2)[0], struct.unpack_from(">H", c, 7)[0]
    elif op in (0x08, 0x0A):
        lba = ((c[1] & 0x1F) << 16) | (c[2] << 8) | c[3]
        blocks = c[4] or 256
    elif op in (0xA8, 0xAA):
        lba, blocks = struct.unpack_from(">II", c, 2)
    elif op in (0x88, 0x8A):
        lba, blocks = struct.unpack_from(">Q", c, 2)[0], struct.unpack_from(">I", c, 10)[0]
    elif op == 0x12:
        d["evpd"] = bool(c[1] & 1)
        d["page_code"] = c[2]
        d["allocation_length"] = struct.unpack_from(">H", c, 3)[0]
    elif op == 0x03:
        d["allocation_length"] = c[4]
    elif op == 0x1A:
        d["page_code"] = f"0x{c[2] & 0x3F:02x}"
        d["allocation_length"] = c[4]
    elif op == 0x5A:
        d["page_code"] = f"0x{c[2] & 0x3F:02x}"
        d["allocation_length"] = struct.unpack_from(">H", c, 7)[0]
    elif op == 0x1B:
        d["start"] = bool(c[4] & 1)
        d["load_eject"] = bool(c[4] & 2)
    elif op == 0x1E:
        d["prevent"] = c[4] & 3
    elif op == 0x9E:
        if c[1] & 0x1F == 0x10:
            name = d["name"] = "READ CAPACITY(16)"
    summary = name
    if lba is not None:
        d["lba"] = lba
        d["blocks"] = blocks
        summary += f" LBA {lba} x {blocks} block(s)"
        if block_size:
            d["bytes"] = blocks * block_size
            summary += f" ({blocks * block_size} B)"
    elif op == 0x1B:
        summary += " (" + ("eject" if d["load_eject"] and not d["start"] else
                           "load" if d["load_eject"] else "start" if d["start"] else "stop") + ")"
    elif op == 0x1E:
        summary += " (prevent)" if d["prevent"] else " (allow)"
    elif "page_code" in d and op in (0x1A, 0x5A):
        summary += f" page {d['page_code']}"
    d["summary"] = summary
    return d


def _scsi_interpret(op: int, data: bytes) -> tuple[dict[str, Any], str]:
    """Interpret a SCSI data-in phase. Returns (decoded, short text)."""
    if op == 0x12 and len(data) >= 36:
        dec = {"peripheral_type": data[0] & 0x1F, "removable": bool(data[1] & 0x80),
               "vendor": data[8:16].decode("ascii", "replace").strip(),
               "product": data[16:32].decode("ascii", "replace").strip(),
               "revision": data[32:36].decode("ascii", "replace").strip()}
        return dec, f'"{dec["vendor"]} {dec["product"]} {dec["revision"]}"'
    if op == 0x25 and len(data) >= 8:
        last, bs = struct.unpack_from(">II", data)
        cap = (last + 1) * bs
        dec = {"last_lba": last, "block_size": bs, "capacity_bytes": cap}
        return dec, f"last LBA {last}, block {bs} B, {cap / 1e6:.1f} MB"
    if op == 0x9E and len(data) >= 12:
        last, bs = struct.unpack_from(">QI", data)
        cap = (last + 1) * bs
        dec = {"last_lba": last, "block_size": bs, "capacity_bytes": cap}
        return dec, f"last LBA {last}, block {bs} B, {cap / 1e6:.1f} MB"
    if op == 0x03 and len(data) >= 14:
        sk = data[2] & 0x0F
        dec = {"sense_key": SENSE_KEYS[sk], "asc": f"0x{data[12]:02x}", "ascq": f"0x{data[13]:02x}"}
        return dec, f"{dec['sense_key']} ASC {dec['asc']} ASCQ {dec['ascq']}"
    if op == 0x1A and len(data) >= 4:
        dec = {"mode_data_length": data[0], "write_protected": bool(data[2] & 0x80)}
        return dec, "write-protected" if dec["write_protected"] else "writable"
    if op == 0x5A and len(data) >= 8:
        dec = {"mode_data_length": struct.unpack_from(">H", data)[0], "write_protected": bool(data[3] & 0x80)}
        return dec, "write-protected" if dec["write_protected"] else "writable"
    return {}, ""


# ---------------------------------------------------------------------------
# Vendor USB-serial chips
# ---------------------------------------------------------------------------

_SERIAL_DRIVERS = ("ch34x", "ftdi", "cp210x")
_DRIVER_LABELS = {"cdc_acm": "CDC-ACM", "ch34x": "CH34x", "ftdi": "FTDI", "cp210x": "CP210x",
                  "serial": "Serial"}

#: (vid, pid or None for any) -> driver
_VID_PID_DRIVERS: dict[tuple[int, int | None], str] = {
    (0x1A86, 0x7523): "ch34x", (0x1A86, 0x5523): "ch34x", (0x1A86, 0x7522): "ch34x",
    (0x1A86, 0xE523): "ch34x", (0x4348, 0x5523): "ch34x",
    (0x0403, None): "ftdi",
    (0x10C4, 0xEA60): "cp210x", (0x10C4, 0xEA61): "cp210x", (0x10C4, 0xEA63): "cp210x",
    (0x10C4, 0xEA70): "cp210x", (0x10C4, 0xEA71): "cp210x", (0x10C4, 0xEA7A): "cp210x",
    (0x10C4, 0xEA7B): "cp210x",
}

_CH34X_REGS = {0x05: "BREAK", 0x06: "MODEM_STATUS", 0x07: "MODEM_STATUS_2", 0x0F: "BPS_PAD",
               0x12: "PRESCALER", 0x13: "DIVISOR", 0x14: "BPS_MOD", 0x18: "LCR", 0x25: "LCR2"}
_CH34X_REQUESTS = {0x5F: "READ_VERSION", 0x95: "READ_REG", 0x9A: "WRITE_REG",
                   0xA1: "SERIAL_INIT", 0xA4: "MODEM_CTRL"}


def ch34x_baud(prescaler: int, divisor: int) -> float | None:
    """Baud rate from CH34x registers 0x12 (prescaler) and 0x13 (divisor).

    Inverse of Linux ``ch341_get_divisor``: prescaler bits[1:0] = ps,
    bit 2 = fact, bit 7 = "no buffering" flag (ignored);
    baud = 48 MHz / ((1 << (12 - 3*ps - fact)) * (256 - divisor)).
    """
    ps = prescaler & 3
    fact = (prescaler >> 2) & 1
    div = 256 - (divisor & 0xFF)
    if div <= 0:
        return None
    return 48_000_000 / ((1 << (12 - 3 * ps - fact)) * div)


def _ch34x_lcr(lcr: int) -> dict[str, Any]:
    if not lcr & 0x08:
        parity = "none"
    elif lcr & 0x20:
        parity = "space" if lcr & 0x10 else "mark"
    else:
        parity = "even" if lcr & 0x10 else "odd"
    return {"data_bits": 5 + (lcr & 3), "parity": parity, "stop_bits": 2 if lcr & 0x04 else 1,
            "rx_enabled": bool(lcr & 0x80), "tx_enabled": bool(lcr & 0x40)}


def _ch34x_modem_status(raw: int) -> dict[str, bool]:
    st = ~raw & 0x0F
    return {"CTS": bool(st & 1), "DSR": bool(st & 2), "RI": bool(st & 4), "DCD": bool(st & 8)}


_FTDI_REQUESTS = {0x00: "RESET", 0x01: "MODEM_CTRL", 0x02: "SET_FLOW_CTRL", 0x03: "SET_BAUDRATE",
                  0x04: "SET_DATA", 0x05: "GET_MODEM_STATUS", 0x06: "SET_EVENT_CHAR",
                  0x07: "SET_ERROR_CHAR", 0x09: "SET_LATENCY_TIMER", 0x0A: "GET_LATENCY_TIMER",
                  0x0B: "SET_BITMODE", 0x0C: "READ_PINS", 0x90: "READ_EEPROM",
                  0x91: "WRITE_EEPROM", 0x92: "ERASE_EEPROM"}
_FTDI_FRAC = (0.0, 0.5, 0.25, 0.125, 0.375, 0.625, 0.75, 0.875)
# Chips whose driver puts divisor bits 16-17 in the HIGH byte of wIndex (low byte = interface number):
# FT2232C/D/H (0x6010), FT4232H (0x6011), FT232H (0x6014), FT-X (0x6015), FT4232HA (0x6048).
# Linux ftdi_sio change_speed() does this for FT2232C/FT2232H/FT4232H/FT232H/FTX.
_FTDI_MULTIPORT_PIDS = {0x6010, 0x6011, 0x6014, 0x6015, 0x6048}


def ftdi_baud(wvalue: int, windex: int, multiport: bool | None = None) -> tuple[float | None, dict[str, Any]]:
    """Decode an FTDI SET_BAUDRATE divisor (FT232BM/R and H-series encoding).

    Divisor bits: [13:0] integer part, [15:14] + bit 16 fractional code
    (eighths: 0, 1/2, 1/4, 1/8, 3/8, 5/8, 3/4, 7/8), bit 17 selects the 12 MHz
    H-series clock (otherwise 3 MHz).  Multi-port / H / X chips carry bits 16-17
    in the high byte of wIndex (low byte = interface: A=1, B=2, ...), FT232BM/R
    in wIndex itself.  ``multiport=None`` (chip unknown) guesses: a non-zero
    high byte, or a wIndex of 2..4 (impossible for FT232BM/R, which never set
    bit 17), means multiport; wIndex 1 is ambiguous (``info["alternative"]``).
    """
    guessed = multiport is None
    if multiport is None:
        multiport = windex > 0xFF or windex in (2, 3, 4)
    hi = (windex >> 8) if multiport else windex
    div = wvalue | ((hi & 0xFF) << 16)
    base = 12_000_000 if div & 0x20000 else 3_000_000
    code = ((div >> 14) & 3) | (((div >> 16) & 1) << 2)
    integer = div & 0x3FFF
    info: dict[str, Any] = {"divisor": f"0x{div:05x}", "integer": integer, "fraction": _FTDI_FRAC[code],
                            "clock_hz": base}
    if multiport:
        info["port"] = windex & 0xFF
    if guessed and windex == 1:
        alt, _ = ftdi_baud(wvalue, windex, True)
        info["alternative"] = {"assumes": "multi-port chip, interface A",
                               "baud": round(alt, 1) if alt else None}
    low = div & 0x1FFFF
    # Special encodings of the highest rates (Linux ftdi_232bm/2232h_baud_base_to_divisor).
    if base == 3_000_000 and low == 0:
        return 3_000_000.0, info
    if base == 3_000_000 and low == 1:
        return 2_000_000.0, info
    if base == 12_000_000 and low == 0:
        return 12_000_000.0, info
    if base == 12_000_000 and low == 1:
        return 8_000_000.0, info
    total = integer + _FTDI_FRAC[code]
    if total <= 0:
        return None, info
    return base / total, info


_CP210X_REQUESTS = {0x00: "IFC_ENABLE", 0x01: "SET_BAUDDIV", 0x02: "GET_BAUDDIV", 0x03: "SET_LINE_CTL",
                    0x04: "GET_LINE_CTL", 0x05: "SET_BREAK", 0x06: "IMM_CHAR", 0x07: "SET_MHS",
                    0x08: "GET_MDMSTS", 0x09: "SET_XON", 0x0A: "SET_XOFF", 0x0B: "SET_EVENTMASK",
                    0x0C: "GET_EVENTMASK", 0x0D: "SET_CHAR", 0x0E: "GET_CHARS", 0x0F: "GET_PROPS",
                    0x10: "GET_COMM_STATUS", 0x11: "RESET", 0x12: "PURGE", 0x13: "SET_FLOW",
                    0x14: "GET_FLOW", 0x15: "EMBED_EVENTS", 0x16: "GET_EVENTSTATE", 0x19: "SET_CHARS",
                    0x1D: "GET_BAUDRATE", 0x1E: "SET_BAUDRATE", 0xFF: "VENDOR_SPECIFIC"}
_PARITY5 = ("none", "odd", "even", "mark", "space")
_CDC_STOP = {0: "1", 1: "1.5", 2: "2"}


def _cp210x_line_ctl(v: int) -> dict[str, Any]:
    return {"data_bits": v >> 8, "parity": _PARITY5[(v >> 4) & 0xF] if ((v >> 4) & 0xF) < 5 else "?",
            "stop_bits": {0: "1", 1: "1.5", 2: "2"}.get(v & 0xF, "?")}


_CDC_REQUESTS = {0x00: "SEND_ENCAPSULATED_COMMAND", 0x01: "GET_ENCAPSULATED_RESPONSE",
                 0x02: "SET_COMM_FEATURE", 0x03: "GET_COMM_FEATURE", 0x04: "CLEAR_COMM_FEATURE",
                 0x20: "SET_LINE_CODING", 0x21: "GET_LINE_CODING", 0x22: "SET_CONTROL_LINE_STATE",
                 0x23: "SEND_BREAK"}
_CDC_NOTIFICATIONS = {0x00: "NETWORK_CONNECTION", 0x01: "RESPONSE_AVAILABLE", 0x20: "SERIAL_STATE",
                      0x2A: "CONNECTION_SPEED_CHANGE"}


def _cdc_line_coding(data: bytes) -> dict[str, Any] | None:
    if len(data) < 7:
        return None
    baud, fmt, par, bits = struct.unpack_from("<IBBB", data)
    return {"baud": baud, "stop_bits": _CDC_STOP.get(fmt, f"?{fmt}"),
            "parity": _PARITY5[par] if par < 5 else f"?{par}", "data_bits": bits}


# ---------------------------------------------------------------------------
# Hints
# ---------------------------------------------------------------------------

_KIND_ALIASES = {
    "cdc": "cdc", "cdc_acm": "cdc", "acm": "cdc", "serial": "serial",
    "hid": "hid", "keyboard": "keyboard", "kbd": "keyboard", "mouse": "mouse",
    "msc": "msc", "mass_storage": "msc", "storage": "msc", "bot": "msc",
    "ch34x": "ch34x", "ch340": "ch34x", "ch341": "ch34x", "wch": "ch34x",
    "ftdi": "ftdi", "ft232": "ftdi", "cp210x": "cp210x", "cp2102": "cp210x", "silabs": "cp210x",
    "raw": "raw",
}


def _norm_kind(v: Any) -> str:
    k = _KIND_ALIASES.get(str(v).strip().lower())
    if k is None:
        raise ValueError(f"unknown class hint {v!r}; expected one of {sorted(set(_KIND_ALIASES.values()))}")
    return k


def _parse_hints(hints: Any) -> dict[int, dict[str, Any]]:
    out: dict[int, dict[str, Any]] = {}
    if not hints:
        return out
    if not isinstance(hints, dict):
        raise ValueError("hints must be a dict keyed by device address")
    for k, v in hints.items():
        addr = _to_int(k)
        if addr is None or not 0 <= addr <= 127:
            raise ValueError(f"invalid device address in hints: {k!r}")
        h: dict[str, Any] = {"vid": None, "pid": None, "driver": None, "eps": {}, "eps_any": {}}

        def add_ep(ek: Any, ev: Any, h: dict[str, Any] = h) -> None:
            n = _to_int(ek)
            if n is None or not 0 <= n <= 0x8F or (n & 0x70):
                raise ValueError(f"invalid endpoint in hints: {ek!r}")
            kind = _norm_kind(ev)
            if n & 0x80:
                h["eps"][n] = kind
            else:
                h["eps_any"][n] = kind

        if isinstance(v, str):
            h["driver"] = _norm_kind(v)
        elif isinstance(v, dict):
            for kk, vv in v.items():
                key = kk.strip().lower() if isinstance(kk, str) else kk
                if key in ("vid", "pid"):
                    iv = _to_int(vv)
                    if iv is None:
                        raise ValueError(f"invalid {key} in hints: {vv!r}")
                    h[key] = iv
                elif key in ("driver", "class", "kind"):
                    h["driver"] = _norm_kind(vv)
                elif key in ("endpoints", "eps"):
                    if not isinstance(vv, dict):
                        raise ValueError("hints 'endpoints' must be a dict")
                    for ek, ev in vv.items():
                        add_ep(ek, ev)
                else:
                    add_ep(kk, vv)
        else:
            raise ValueError(f"invalid hint for address {k!r}: {v!r}")
        out[addr] = h
    return out


# ---------------------------------------------------------------------------
# Device model
# ---------------------------------------------------------------------------

class _Device:
    def __init__(self, addr: int) -> None:
        self.addr = addr
        self.previous_addresses: list[int] = []
        self.device: dict[str, Any] | None = None
        self.vid: int | None = None
        self.pid: int | None = None
        self.driver: str | None = None
        self.driver_source: str | None = None
        self.strings: dict[int, str] = {}
        self.languages: list[str] = []
        self.configs: dict[int, dict[str, Any]] = {}
        self.last_config: int | None = None
        self.active_config: int | None = None
        self.alt: dict[int, int] = {}
        self.interfaces: dict[int, dict[str, Any]] = {}
        self.endpoints: dict[int, dict[str, Any]] = {}
        self.hid: dict[int, dict[str, Any]] = {}
        self.keyboards: dict[int, dict[str, Any]] = {}
        self.caps_lock = False
        self.leds_seen = False
        self.serial: dict[str, Any] = {}
        self.msc: dict[str, Any] = {}
        self.msc_pending: dict[str, Any] | None = None
        self.toggles: dict[int, tuple[str, bytes]] = {}

    def has_state(self) -> bool:
        """True when something was learned from the traffic (descriptors, strings, configuration)."""
        return bool(self.device or self.configs or self.strings or self.languages
                    or self.active_config is not None or self.hid or self.serial or self.msc)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "address": self.addr,
            "vid": f"0x{self.vid:04x}" if self.vid is not None else None,
            "pid": f"0x{self.pid:04x}" if self.pid is not None else None,
            "driver": self.driver, "driver_source": self.driver_source,
        }
        if self.previous_addresses:
            d["previous_addresses"] = list(self.previous_addresses)
        if self.device:
            d["device_descriptor"] = self.device
            for key, field in (("manufacturer", "iManufacturer"), ("product", "iProduct"),
                               ("serial_number", "iSerialNumber")):
                idx = self.device.get(field)
                if idx and idx in self.strings:
                    d[key] = self.strings[idx]
        if self.strings:
            d["strings"] = {str(k): v for k, v in sorted(self.strings.items())}
        if self.languages:
            d["languages"] = self.languages
        if self.configs:
            d["configurations"] = {str(k): v for k, v in self.configs.items()}
        d["active_configuration"] = self.active_config
        if self.interfaces:
            d["interfaces"] = [
                {"number": n, "alt": itf["alt"], "class": itf["class"], "class_name": itf["class_name"],
                 "subclass": itf["subclass"], "protocol": itf["protocol"], "label": itf["label"],
                 "endpoints": [e["address"] for e in itf["endpoints"]]}
                for n, itf in sorted(self.interfaces.items())]
        if self.endpoints:
            d["endpoints"] = {f"0x{k:02x}": v for k, v in sorted(self.endpoints.items())}
        if self.hid:
            hid = {}
            for n, h in self.hid.items():
                e = {k: v for k, v in h.items() if k != "layout"}
                lay = h.get("layout")
                if lay:
                    e["report_descriptor"] = {"length": lay["length"], "kind": lay["kind"],
                                              "collections": lay["collections"],
                                              "report_ids": lay["report_ids"]}
                hid[str(n)] = e
            d["hid"] = hid
        if self.keyboards:
            d["keyboard_text"] = {f"0x{k:02x}": v["text"] for k, v in self.keyboards.items()}
        if self.serial:
            d["serial"] = self.serial
        if self.msc:
            d["msc"] = self.msc
        return d


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------

class UsbClassDecoder:
    """Stateful class-level decoder; see the module docstring for the API."""

    def __init__(self, hints: dict[Any, Any] | None = None, merge_window_us: float = 50_000.0,
                 max_merge_bytes: int = 4096) -> None:
        self._hints = _parse_hints(hints)
        self.merge_window_us = float(merge_window_us)
        self.max_merge_bytes = int(max_merge_bytes)
        self.reset()

    # -- public ------------------------------------------------------------

    def reset(self) -> None:
        self._devices: dict[int, _Device] = {}
        self._ctl: dict[tuple[int, int], dict[str, Any]] = {}
        self._serial_open: dict[tuple[int, int, str], dict[str, Any]] = {}
        self._serial_last_open: list[tuple[Any, float]] = []
        self._last_t_us: float | None = None
        self._out: list[dict[str, Any]] = []
        for addr in self._hints:
            self._dev(addr)

    def feed(self, transactions: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        self._out = []
        for txn in transactions:
            try:
                self._process(txn)
            except Exception as exc:  # never let one odd transaction kill the decode
                self._out.append(self._mk(txn.get("seq"), txn.get("t_us"), txn.get("addr"), txn.get("ep"),
                                          "raw", f"decoder error: {type(exc).__name__}: {exc}",
                                          {"error": str(exc), "type": txn.get("type")}))
            if txn.get("t_us") is not None:
                self._last_t_us = txn["t_us"]
        # Remember which serial accumulators were still open (they are emitted now, but could still grow).
        self._serial_last_open = [(acc["seq"], acc["t_last"]) for acc in self._serial_open.values()]
        self._flush_serial()
        return self._take()

    def pending_start_seq(self, max_age_us: float | None = 10_000_000.0) -> int | None:
        """Smallest start seq of the items that were still OPEN after the last feed() (control transfers
        without status stage, MSC data without CSW, serial runs still inside the merge window). Such items
        are reported in partial form by flush(); a live pager must resume at this seq to see them complete.
        Items that started more than ``max_age_us`` before the last transaction are considered stale (hosts
        time control transfers out after 5 s) so a dead transfer cannot pin the pager forever."""
        now = self._last_t_us
        cands: list[tuple[Any, Any]] = [(ct.get("seq"), ct.get("t_us")) for ct in self._ctl.values()]
        for dev in self._devices.values():
            if dev.msc_pending is not None:
                cands.append((dev.msc_pending.get("seq"), dev.msc_pending.get("t_us")))
        seqs: list[int] = []
        for seq, t_us in cands:
            if seq is None:
                continue
            if max_age_us is not None and now is not None and t_us is not None and now - t_us > max_age_us:
                continue
            seqs.append(seq)
        for seq, t_last in self._serial_last_open:
            if seq is not None and (now is None or now - t_last <= self.merge_window_us):
                seqs.append(seq)
        return min(seqs) if seqs else None

    def flush(self) -> list[dict[str, Any]]:
        self._out = []
        for key in list(self._ctl):
            self._finish_control(key, "incomplete")
        for dev in self._devices.values():
            if dev.msc_pending is not None:
                self._msc_emit_data(dev, note="no CSW seen")
                dev.msc_pending = None
        self._flush_serial()
        return self._take()

    def devices(self) -> dict[str, Any]:
        return {str(a): d.to_dict() for a, d in sorted(self._devices.items())}

    # -- internals: plumbing -------------------------------------------------

    def _take(self) -> list[dict[str, Any]]:
        out = self._out
        self._out = []
        out.sort(key=lambda it: (it["seq"] if it["seq"] is not None else -1))
        return out

    @staticmethod
    def _mk(seq: Any, t_us: Any, addr: Any, ep: Any, layer: str, summary: str,
            details: dict[str, Any]) -> dict[str, Any]:
        return {"seq": seq, "t_us": t_us, "addr": addr, "ep": ep, "layer": layer,
                "summary": summary, "details": details}

    def _dev(self, addr: int) -> _Device:
        dev = self._devices.get(addr)
        if dev is None:
            dev = self._devices[addr] = _Device(addr)
            self._apply_hints(dev, addr)
        return dev

    def _apply_hints(self, dev: _Device, addr: int) -> None:
        h = self._hints.get(addr)
        if not h:
            return
        if dev.vid is None and h["vid"] is not None:
            dev.vid = h["vid"]
        if dev.pid is None and h["pid"] is not None:
            dev.pid = h["pid"]
        if h["driver"] and (dev.driver is None or dev.driver_source == "heuristic"):
            dev.driver, dev.driver_source = h["driver"], "hint"

    def _driver(self, dev: _Device) -> str | None:
        if dev.driver is None and dev.vid is not None:
            drv = _VID_PID_DRIVERS.get((dev.vid, dev.pid)) or _VID_PID_DRIVERS.get((dev.vid, None))
            if drv:
                dev.driver, dev.driver_source = drv, "vid_pid"
        return dev.driver

    def _ep_hint(self, addr: int, ep: int, direction: str) -> str | None:
        h = self._hints.get(addr)
        if not h:
            return None
        key = ep | (0x80 if direction == "IN" else 0)
        if key in h["eps"]:
            return h["eps"][key]
        return h["eps_any"].get(ep)

    # -- transaction dispatch ------------------------------------------------

    def _process(self, txn: dict[str, Any]) -> None:
        t = txn.get("type")
        if t == "EVENT":
            if txn.get("event") == "BUS_RESET":
                # Report transfers aborted by the reset (e.g. the GET_DESCRIPTOR(DEVICE) a host cuts short
                # with a port reset) instead of silently dropping them.
                for key in list(self._ctl):
                    self._finish_control(key, "aborted by reset")
                for dev in self._devices.values():
                    dev.toggles.clear()
                self._ctl.clear()
                self._out.append(self._mk(txn.get("seq"), txn.get("t_us"), None, None, "control",
                                          "Bus reset", {"event": "BUS_RESET"}))
            return
        if t not in ("SETUP", "IN", "OUT"):
            return
        addr, ep = txn.get("addr"), txn.get("ep")
        if addr is None or ep is None:
            return
        hs = txn.get("handshake")
        key = (addr, ep)
        if t == "SETUP":
            # Only a valid SETUP carrying its data packet supersedes an open control transfer. A SETUP token
            # without DATA0 is the complete-split of a high-speed hub transaction (USB 2.0 11.17/11.18): the
            # payload was in the start-split, so ignore it. Same for NYET/NAK/STALL or corrupted SETUPs.
            if txn.get("data_pid") is None or hs not in ("ACK", None) or txn.get("crc_ok") is False:
                return
            if key in self._ctl:
                self._finish_control(key, "incomplete")
            setup = txn.get("setup")
            raw = bytes.fromhex(txn.get("data_hex") or "")
            if setup is None:
                setup = decode_setup(raw)
            if setup is None:
                self._out.append(self._mk(txn["seq"], txn["t_us"], addr, ep, "raw",
                                          f"malformed SETUP ({len(raw)} bytes)", {"data_hex": raw.hex()}))
                return
            self._ctl[key] = {"setup": setup, "setup_hex": raw.hex(), "seq": txn["seq"], "t_us": txn["t_us"],
                              "addr": addr, "ep": ep, "data": bytearray(), "last": None,
                              "seq_end": txn["seq"], "t_end": txn["t_us"]}
            return
        ct = self._ctl.get(key)
        if ct is not None:
            self._control_stage(key, ct, txn)
            return
        if hs == "NAK":
            return
        if ep == 0:
            if txn.get("data_len"):
                self._out.append(self._mk(txn["seq"], txn["t_us"], addr, ep, "raw",
                                          f"EP0 {t} {txn['data_len']} B outside a control transfer",
                                          {"direction": t, "data_hex": txn.get("data_hex")}))
            return
        self._endpoint_data(txn)

    def _control_stage(self, key: tuple[int, int], ct: dict[str, Any], txn: dict[str, Any]) -> None:
        t, hs = txn["type"], txn.get("handshake")
        if hs == "NAK":
            return
        s = ct["setup"]
        status_dir = "IN" if (s["direction"] == "OUT" or s["wLength"] == 0) else "OUT"
        ct["seq_end"], ct["t_end"] = txn["seq"], txn["t_us"]
        if hs == "STALL":
            self._finish_control(key, "STALL")
            return
        if t == status_dir:
            if hs == "ACK":
                self._finish_control(key, "ACK")
            elif txn.get("data_pid") is not None:
                self._finish_control(key, "unacknowledged")
            return
        if txn.get("data_pid") is None or txn.get("crc_ok") is False:
            return
        data = bytes.fromhex(txn.get("data_hex") or "")
        sig = (txn["data_pid"], data)
        if sig == ct["last"]:
            return  # retransmission (same toggle, same payload)
        ct["last"] = sig
        ct["data"] += data

    # -- control transfers ---------------------------------------------------

    def _finish_control(self, key: tuple[int, int], status: str) -> None:
        ct = self._ctl.pop(key, None)
        if ct is None:
            return
        addr = ct["addr"]
        dev = self._dev(addr)
        s = ct["setup"]
        data = bytes(ct["data"])
        rtype = s["type"]
        layer, summary, extra = "control", "", {}
        if rtype == "standard":
            summary, extra = self._std_request(dev, s, data, status)
        elif rtype == "class":
            layer, summary, extra = self._class_request(dev, s, data)
        elif rtype == "vendor":
            layer, summary, extra = self._vendor_request(dev, s, data)
        else:
            summary = f"reserved request type bRequest 0x{s['bRequest']:02x}"
        if status != "ACK":
            summary += f" [{status}]"
        details = {
            "request": extra.pop("request", None) or s.get("request_name") or f"0x{s['bRequest']:02x}",
            "setup": s, "setup_hex": ct["setup_hex"], "data_len": len(data), "data_hex": _hex(data),
            "status": status, "seq_end": ct["seq_end"], "t_end_us": ct["t_end"],
        }
        if len(data) > MAX_HEX_BYTES:
            details["data_truncated"] = True
        details.update(extra)
        self._out.append(self._mk(ct["seq"], ct["t_us"], addr, ct["ep"], layer, summary, details))

    def _std_request(self, dev: _Device, s: dict[str, Any], data: bytes,
                     status: str) -> tuple[str, dict[str, Any]]:
        breq, wv, wi = s["bRequest"], s["wValue"], s["wIndex"]
        name = s.get("request_name") or f"STANDARD 0x{breq:02x}"
        extra: dict[str, Any] = {}
        ok = status != "STALL"
        if breq == 6:
            dtype, idx = wv >> 8, wv & 0xFF
            dname = DESCRIPTOR_NAMES.get(dtype, f"0x{dtype:02x}")
            summary = f"GET_DESCRIPTOR {dname}"
            if dtype in (2, 3):
                summary += f" #{idx}"
            if dtype in (0x21, 0x22):
                summary += f" (interface {wi})"
            summary += f" len {s['wLength']}"
            if not data:
                return summary + " -> no data", extra
            if dtype == 1:
                d = parse_device_descriptor(data)
                extra["descriptor"] = d
                self._apply_device_descriptor(dev, d)
                return summary + " -> " + _device_summary(d), extra
            if dtype in (2, 7):
                c = parse_config_descriptor(data)
                extra["descriptor"] = c
                if dtype == 2 and c.get("complete"):
                    dev.configs[c["value"]] = c
                    dev.last_config = c["value"]
                    self._rebuild_endpoints(dev)
                return summary + " -> " + _config_summary(c), extra
            if dtype == 3:
                sd = parse_string_descriptor(data, idx)
                extra["descriptor"] = sd
                if idx == 0:
                    dev.languages = sd.get("languages", [])
                    return summary + " -> languages " + ", ".join(dev.languages), extra
                dev.strings[idx] = sd.get("text", "")
                return summary + f' -> "{_clip(sd.get("text", ""), 80)}"', extra
            if dtype == 0x22:
                lay = parse_hid_report_descriptor(data)
                dev.hid.setdefault(wi & 0xFF, {})["layout"] = lay
                extra["descriptor"] = {k: v for k, v in lay.items() if not k.endswith("_reports")}
                cols = ", ".join(c["name"] for c in lay["collections"]) or "no collection"
                rid = f", report IDs {lay['report_ids']}" if lay["report_ids"] else ""
                return summary + f" -> {len(data)} B: {cols}{rid}", extra
            if dtype == 6 and len(data) >= 10:
                extra["descriptor"] = {"bcdUSB": _bcd(data[2] | (data[3] << 8)), "device_class": data[4],
                                       "max_packet0": data[7], "num_configurations": data[8]}
            return summary + f" -> {len(data)} B", extra
        if breq == 5:
            new = wv & 0x7F
            extra["new_address"] = new
            # USB 2.0 9.4.6: the device adopts the address only after a successful status stage.
            if status == "ACK":
                self._move_device(dev.addr, new)
            return f"SET_ADDRESS {new} (device {dev.addr} -> {new})", extra
        if breq == 9:
            cfg = wv & 0xFF
            if ok:
                dev.active_config = cfg or None
                dev.alt.clear()
                dev.toggles.clear()
                self._rebuild_endpoints(dev)
            return f"SET_CONFIGURATION {cfg}", extra
        if breq == 11:
            if ok:
                dev.alt[wi & 0xFF] = wv
                dev.toggles.clear()
                self._rebuild_endpoints(dev)
            return f"SET_INTERFACE interface {wi} alt {wv}", extra
        if breq == 8:
            return f"GET_CONFIGURATION -> {data[0] if data else '?'}", extra
        if breq == 10:
            return f"GET_INTERFACE {wi} -> alt {data[0] if data else '?'}", extra
        if breq == 0:
            val = int.from_bytes(data[:2], "little") if data else None
            return f"GET_STATUS {s['recipient']} {wi} -> {('0x%04x' % val) if val is not None else '?'}", extra
        if breq in (1, 3):
            feat = {0: "ENDPOINT_HALT", 1: "DEVICE_REMOTE_WAKEUP", 2: "TEST_MODE"}.get(wv, f"0x{wv:x}")
            if breq == 1 and wv == 0 and s["recipient"] == "endpoint":
                dev.toggles.pop(wi & 0x8F, None)
            tgt = f" endpoint 0x{wi & 0xFF:02x}" if s["recipient"] == "endpoint" else f" {s['recipient']}"
            return f"{name} {feat}{tgt}", extra
        return f"{name} wValue 0x{wv:04x} wIndex 0x{wi:04x} len {len(data)}", extra

    def _apply_device_descriptor(self, dev: _Device, d: dict[str, Any]) -> None:
        if "error" in d:
            return
        if dev.device is None or d.get("complete") or not dev.device.get("complete"):
            dev.device = d
        if d.get("complete"):
            dev.vid, dev.pid = d["idVendor"], d["idProduct"]
            if dev.driver_source in (None, "heuristic", "vid_pid"):
                dev.driver = dev.driver_source = None
                self._driver(dev)

    def _rebuild_endpoints(self, dev: _Device) -> None:
        cfg_no = dev.active_config if dev.active_config in dev.configs else dev.last_config
        cfg = dev.configs.get(cfg_no) if cfg_no is not None else None
        if cfg is None:
            return
        dev.interfaces, dev.endpoints = {}, {}
        for itf in cfg["interfaces"]:
            n = itf["number"]
            if itf["alt"] != dev.alt.get(n, 0):
                continue
            dev.interfaces[n] = itf
            for e in itf["endpoints"]:
                k = e["number"] | (0x80 if e["direction"] == "IN" else 0)
                dev.endpoints[k] = {"interface": n, "type": e["type"], "max_packet": e["max_packet"],
                                    "interval": e["interval"], "class": itf["class_name"]}

    def _move_device(self, old: int, new: int) -> None:
        if old == new:
            return
        dev = self._devices.pop(old, None) or _Device(old)
        existing = self._devices.get(new)
        if existing is not None and existing is not dev and not dev.has_state() and existing.has_state():
            # e.g. a retried SET_ADDRESS decoded on a fresh model: keep the learned model at the target.
            existing.previous_addresses.append(old)
            if old in self._hints:
                self._dev(old)
            return
        dev.previous_addresses.append(old)
        dev.addr = new
        self._devices[new] = dev
        self._apply_hints(dev, new)
        if old in self._hints:  # keep a (fresh) hinted model at the old address
            self._dev(old)

    # -- class requests --------------------------------------------------------

    def _request_interface_class(self, dev: _Device, s: dict[str, Any]) -> tuple[int | None, int | None]:
        rec, wi = s["recipient"], s["wIndex"]
        if rec == "interface":
            itf = dev.interfaces.get(wi & 0xFF)
            return (itf["class"] if itf else None), wi & 0xFF
        if rec == "endpoint":
            info = dev.endpoints.get(wi & 0x8F)
            if info is not None:
                itf = dev.interfaces.get(info["interface"])
                return (itf["class"] if itf else None), info["interface"]
            return None, None
        if dev.device and dev.device.get("device_class") not in (None, 0, 0xEF, 0xFF):
            return dev.device["device_class"], None
        return None, None

    def _class_request(self, dev: _Device, s: dict[str, Any], data: bytes) -> tuple[str, str, dict[str, Any]]:
        cls, iface = self._request_interface_class(dev, s)
        breq = s["bRequest"]
        if cls is None:
            drv = self._driver(dev)
            cls = {"hid": 3, "keyboard": 3, "mouse": 3, "cdc": 2, "msc": 8}.get(drv or "")
        if cls is None:
            if 0x20 <= breq <= 0x23:
                cls = 2
            elif breq in (0xFE, 0xFF):
                cls = 8
            elif breq in _HID_REQUESTS:
                cls = 3
        if cls == 3:
            summary, extra = self._hid_request(dev, s, data, iface)
            return "hid", summary, extra
        if cls in (2, 0x0A):
            summary, extra = self._cdc_request(dev, s, data)
            return "cdc", summary, extra
        if cls == 8:
            if breq == 0xFE:
                lun = data[0] if data else None
                if lun is not None:
                    dev.msc["max_lun"] = lun
                return "msc", f"GET_MAX_LUN -> {lun if lun is not None else '?'}", {"request": "GET_MAX_LUN",
                                                                                    "max_lun": lun}
            if breq == 0xFF:
                dev.msc_pending = None
                return "msc", "BULK_ONLY_MASS_STORAGE_RESET", {"request": "BULK_ONLY_MASS_STORAGE_RESET"}
        return "control", (f"CLASS request 0x{breq:02x} ({_class_name(cls)}) wValue 0x{s['wValue']:04x} "
                           f"wIndex 0x{s['wIndex']:04x} len {len(data)}"), {}

    def _hid_request(self, dev: _Device, s: dict[str, Any], data: bytes,
                     iface: int | None) -> tuple[str, dict[str, Any]]:
        breq, wv = s["bRequest"], s["wValue"]
        name = _HID_REQUESTS.get(breq, f"HID 0x{breq:02x}")
        iface = iface if iface is not None else s["wIndex"] & 0xFF
        extra: dict[str, Any] = {"request": name, "interface": iface}
        hstate = dev.hid.setdefault(iface, {})
        if breq in (0x01, 0x09):
            rtype = _HID_REPORT_TYPES.get(wv >> 8, f"type {wv >> 8}")
            extra.update(report_type=rtype, report_id=wv & 0xFF)
            summary = f"{name} {rtype} report ID {wv & 0xFF} ({len(data)} B)"
            payload = data[1:] if (wv & 0xFF) and data and data[0] == (wv & 0xFF) else data
            if breq == 0x09 and rtype == "Output" and len(payload) == 1:
                leds = [n for b, n in ((1, "NumLock"), (2, "CapsLock"), (4, "ScrollLock"),
                                       (8, "Compose"), (16, "Kana")) if payload[0] & b]
                extra["leds"] = leds
                dev.leds_seen = True
                dev.caps_lock = "CapsLock" in leds
                hstate["leds"] = leds
                summary += f": LEDs {', '.join(leds) if leds else 'all off'}"
            elif data:
                summary += f": {_clip(data.hex(), 48)}"
            return summary, extra
        if breq == 0x0A:
            dur = (wv >> 8) * 4
            extra.update(duration_ms=dur, report_id=wv & 0xFF)
            hstate["idle_ms"] = dur
            return (f"SET_IDLE {'infinite (report only on change)' if dur == 0 else f'{dur} ms'} "
                    f"report ID {wv & 0xFF}"), extra
        if breq == 0x02:
            return f"GET_IDLE report ID {wv & 0xFF} -> {data[0] * 4 if data else '?'} ms", extra
        if breq == 0x0B:
            mode = "boot" if wv == 0 else "report"
            hstate["protocol_mode"] = mode
            extra["protocol"] = mode
            return f"SET_PROTOCOL {mode} (interface {iface})", extra
        if breq == 0x03:
            mode = ("boot" if data[0] == 0 else "report") if data else "?"
            return f"GET_PROTOCOL -> {mode}", extra
        return f"{name} wValue 0x{wv:04x} len {len(data)}", extra

    def _cdc_request(self, dev: _Device, s: dict[str, Any], data: bytes) -> tuple[str, dict[str, Any]]:
        breq, wv = s["bRequest"], s["wValue"]
        name = _CDC_REQUESTS.get(breq, f"CDC 0x{breq:02x}")
        extra: dict[str, Any] = {"request": name, "interface": s["wIndex"]}
        st = dev.serial
        if breq in (0x20, 0x21):
            lc = _cdc_line_coding(data)
            if lc is None:
                return f"{name} ({len(data)} B)", extra
            extra["line_coding"] = lc
            if breq == 0x20 or "baud" not in st:
                st.update(driver="cdc_acm", baud=lc["baud"], data_bits=lc["data_bits"],
                          parity=lc["parity"], stop_bits=lc["stop_bits"])
            arrow = ":" if breq == 0x20 else " ->"
            return f"{name}{arrow} {_line_str(lc['baud'], lc['data_bits'], lc['parity'], lc['stop_bits'])}", extra
        if breq == 0x22:
            dtr, rts = bool(wv & 1), bool(wv & 2)
            extra.update(dtr=dtr, rts=rts)
            st.update(driver=st.get("driver", "cdc_acm"), dtr=dtr, rts=rts)
            return f"{name}: DTR={'on' if dtr else 'off'} RTS={'on' if rts else 'off'}", extra
        if breq == 0x23:
            extra["duration_ms"] = wv
            return f"SEND_BREAK {'until cleared' if wv == 0xFFFF else f'{wv} ms'}", extra
        if breq in (0x00, 0x01):
            return f"{name} ({len(data)} B){': ' + _clip(escape_text(data), 60) if data else ''}", extra
        return f"{name} wValue 0x{wv:04x} len {len(data)}", extra

    # -- vendor requests ---------------------------------------------------------

    @staticmethod
    def _guess_vendor_driver(s: dict[str, Any]) -> str | None:
        breq = s["bRequest"]
        if s["recipient"] == "device" and breq in _CH34X_REQUESTS:
            return "ch34x"
        if s["recipient"] == "interface" and breq in (0x00, 0x01, 0x03, 0x04, 0x07, 0x08, 0x0F, 0x10,
                                                      0x12, 0x13, 0x19, 0x1D, 0x1E):
            return "cp210x"
        return None

    def _vendor_request(self, dev: _Device, s: dict[str, Any], data: bytes) -> tuple[str, str, dict[str, Any]]:
        drv = self._driver(dev)
        if drv is None:
            guess = self._guess_vendor_driver(s)
            if guess:
                dev.driver, dev.driver_source = guess, "heuristic"
                drv = guess
        if drv == "ch34x":
            summary, extra = self._ch34x_request(dev, s, data)
        elif drv == "ftdi":
            summary, extra = self._ftdi_request(dev, s, data)
        elif drv == "cp210x":
            summary, extra = self._cp210x_request(dev, s, data)
        else:
            return "control", (f"VENDOR request 0x{s['bRequest']:02x} {s['direction']} wValue 0x{s['wValue']:04x} "
                               f"wIndex 0x{s['wIndex']:04x} len {len(data)}"
                               + (f": {_clip(data.hex(), 48)}" if data else "")), {}
        extra["driver"] = drv
        if dev.driver_source == "heuristic":
            extra["best_effort"] = True
        return "serial", f"{_DRIVER_LABELS[drv]} {summary}", extra

    def _ch34x_request(self, dev: _Device, s: dict[str, Any], data: bytes) -> tuple[str, dict[str, Any]]:
        breq, wv, wi = s["bRequest"], s["wValue"], s["wIndex"]
        name = _CH34X_REQUESTS.get(breq, f"0x{breq:02x}")
        extra: dict[str, Any] = {"request": name}
        st = dev.serial
        st["driver"] = "ch34x"
        regs = st.setdefault("registers", {})

        def reg_label(r: int) -> str:
            return f"0x{r:02x}" + (f" {_CH34X_REGS[r]}" if r in _CH34X_REGS else "")

        if breq == 0x5F:
            ver = data[0] if data else None
            if ver is not None:
                st["version"] = f"0x{ver:02x}"
            extra["version"] = st.get("version")
            return f"READ_VERSION -> {st.get('version', '?')}", extra
        if breq == 0xA1:
            if wv == 0 and wi == 0:
                return "SERIAL_INIT (reset, no parameters)", extra
            parts = ["SERIAL_INIT"]
            lcr = wv >> 8
            if lcr:
                lc = _ch34x_lcr(lcr)
                extra["lcr"] = f"0x{lcr:02x}"
                extra.update(lc)
                st.update(data_bits=lc["data_bits"], parity=lc["parity"], stop_bits=lc["stop_bits"])
            if wi:
                baud = ch34x_baud(wi & 0xFF, wi >> 8)
                extra.update(prescaler=f"0x{wi & 0xFF:02x}", divisor=f"0x{wi >> 8:02x}",
                             baud_exact=round(baud, 1) if baud else None,
                             baud=_nominal_baud(baud) or (round(baud) if baud else None), best_effort=True)
                st["baud"] = extra["baud"]
            parts.append(_line_str(extra.get("baud"), extra.get("data_bits"), extra.get("parity"),
                                   extra.get("stop_bits")))
            return " ".join(parts) + f" (wValue 0x{wv:04x} wIndex 0x{wi:04x}, best-effort)", extra
        if breq == 0x9A:
            pairs = [(wv & 0xFF, wi & 0xFF), (wv >> 8, wi >> 8)]
            if pairs[0][0] == pairs[1][0]:
                pairs = pairs[1:]
            writes = []
            for r, v in pairs:
                regs[f"0x{r:02x}"] = f"0x{v:02x}"
                writes.append(f"{reg_label(r)}=0x{v:02x}")
            extra["writes"] = {f"0x{r:02x}": f"0x{v:02x}" for r, v in pairs}
            written = {r for r, _ in pairs}
            text = "WRITE_REG " + ", ".join(writes)
            if {0x12, 0x13} & written and "0x12" in regs and "0x13" in regs:
                baud = ch34x_baud(int(regs["0x12"], 16), int(regs["0x13"], 16))
                nominal = _nominal_baud(baud)
                extra.update(baud_exact=round(baud, 1) if baud else None,
                             baud=nominal or (round(baud) if baud else None))
                st["baud"] = extra["baud"]
                text += f" -> baud {extra['baud']}"
            if 0x18 in written:
                lc = _ch34x_lcr(int(regs["0x18"], 16))
                extra.update(lc)
                st.update(data_bits=lc["data_bits"], parity=lc["parity"], stop_bits=lc["stop_bits"])
                text += " -> " + _line_str(None, lc["data_bits"], lc["parity"], lc["stop_bits"])
            if 0x05 in written:
                extra["break"] = not (int(regs["0x05"], 16) & 0x01)
            return text, extra
        if breq == 0x95:
            ra, rb = wv & 0xFF, wv >> 8
            vals = list(data[:2])
            reads = {}
            for r, v in zip((ra, rb), vals):
                reads[f"0x{r:02x}"] = f"0x{v:02x}"
                regs[f"0x{r:02x}"] = f"0x{v:02x}"
            extra["reads"] = reads
            label = reg_label(ra) if ra == rb else f"{reg_label(ra)}, {reg_label(rb)}"
            text = f"READ_REG {label} -> {data.hex() if data else '?'}"
            if ra == 0x06 and vals:
                ms = _ch34x_modem_status(vals[0])
                extra["modem_status"] = ms
                st["modem_status"] = ms
                text += " (" + " ".join(f"{k}={'on' if v else 'off'}" for k, v in ms.items()) + ")"
            return text, extra
        if breq == 0xA4:
            ctl = ~wv & 0xFF
            dtr, rts = bool(ctl & 0x20), bool(ctl & 0x40)
            extra.update(dtr=dtr, rts=rts)
            st.update(dtr=dtr, rts=rts)
            return f"MODEM_CTRL DTR={'on' if dtr else 'off'} RTS={'on' if rts else 'off'} (wValue 0x{wv:04x}, inverted)", extra
        return f"request 0x{breq:02x} wValue 0x{wv:04x} wIndex 0x{wi:04x} len {len(data)}", extra

    def _ftdi_request(self, dev: _Device, s: dict[str, Any], data: bytes) -> tuple[str, dict[str, Any]]:
        breq, wv, wi = s["bRequest"], s["wValue"], s["wIndex"]
        name = _FTDI_REQUESTS.get(breq, f"0x{breq:02x}")
        extra: dict[str, Any] = {"request": name}
        st = dev.serial
        st["driver"] = "ftdi"
        if breq == 0x00:
            what = {0: "reset SIO", 1: "purge RX", 2: "purge TX"}.get(wv, f"0x{wv:04x}")
            return f"RESET ({what})", extra
        if breq == 0x01:
            parts = []
            if wv & 0x0100:
                extra["dtr"] = st["dtr"] = bool(wv & 1)
                parts.append(f"DTR={'on' if wv & 1 else 'off'}")
            if wv & 0x0200:
                extra["rts"] = st["rts"] = bool(wv & 2)
                parts.append(f"RTS={'on' if wv & 2 else 'off'}")
            return "MODEM_CTRL " + (" ".join(parts) or f"(no mask, wValue 0x{wv:04x})"), extra
        if breq == 0x02:
            hi = wi >> 8
            flow = [n for b, n in ((1, "RTS/CTS"), (2, "DTR/DSR"), (4, "XON/XOFF")) if hi & b] or ["none"]
            extra["flow_control"] = flow
            st["flow_control"] = flow
            return f"SET_FLOW_CTRL {', '.join(flow)}", extra
        if breq == 0x03:
            multi = (dev.pid in _FTDI_MULTIPORT_PIDS) if dev.pid is not None else None
            baud, info = ftdi_baud(wv, wi, multi)
            nominal = _nominal_baud(baud)
            extra.update(info)
            extra.update(baud_exact=round(baud, 1) if baud else None,
                         baud=nominal or (round(baud) if baud else None))
            if dev.pid is None:
                extra["best_effort"] = True
            st["baud"] = extra["baud"]
            return f"SET_BAUDRATE {extra['baud']} (divisor {info['divisor']})", extra
        if breq == 0x04:
            bits = wv & 0xFF
            par = (wv >> 8) & 7
            stop = {0: "1", 1: "1.5", 2: "2"}.get((wv >> 11) & 3, "?")
            parity = _PARITY5[par] if par < 5 else "?"
            extra.update(data_bits=bits, parity=parity, stop_bits=stop, break_on=bool(wv & 0x4000))
            st.update(data_bits=bits, parity=parity, stop_bits=stop)
            return f"SET_DATA {_line_str(None, bits, parity, stop)}" + (" BREAK" if wv & 0x4000 else ""), extra
        if breq == 0x05:
            if data:
                ms = self._ftdi_status(data[0], data[1] if len(data) > 1 else None)
                extra["modem_status"] = ms
                return f"GET_MODEM_STATUS -> {data.hex()}", extra
            return "GET_MODEM_STATUS", extra
        if breq == 0x09:
            extra["latency_ms"] = wv & 0xFF
            st["latency_ms"] = wv & 0xFF
            return f"SET_LATENCY_TIMER {wv & 0xFF} ms", extra
        if breq == 0x0A:
            return f"GET_LATENCY_TIMER -> {data[0] if data else '?'} ms", extra
        if breq in (0x06, 0x07):
            return f"{name} 0x{wv & 0xFF:02x} ({'enabled' if wv & 0x100 else 'disabled'})", extra
        if breq == 0x0B:
            mode = {0: "reset", 1: "async bitbang", 2: "MPSSE", 4: "sync bitbang", 8: "MCU host",
                    0x10: "fast serial", 0x20: "CBUS bitbang", 0x40: "sync FIFO"}.get(wv >> 8, f"0x{wv >> 8:02x}")
            return f"SET_BITMODE {mode} mask 0x{wv & 0xFF:02x}", extra
        if breq == 0x0C:
            return f"READ_PINS -> {data.hex() if data else '?'}", extra
        if breq == 0x90:
            return f"READ_EEPROM word 0x{wi:02x} -> {data.hex() if data else '?'}", extra
        return f"{name} wValue 0x{wv:04x} wIndex 0x{wi:04x} len {len(data)}", extra

    @staticmethod
    def _ftdi_status(b0: int, b1: int | None) -> dict[str, Any]:
        ms: dict[str, Any] = {"CTS": bool(b0 & 0x10), "DSR": bool(b0 & 0x20), "RI": bool(b0 & 0x40),
                              "DCD": bool(b0 & 0x80)}
        if b1 is not None:
            errs = [n for b, n in ((0x02, "overrun"), (0x04, "parity"), (0x08, "framing"),
                                   (0x10, "break"), (0x80, "fifo")) if b1 & b]
            ms["line_errors"] = errs
        return ms

    def _cp210x_request(self, dev: _Device, s: dict[str, Any], data: bytes) -> tuple[str, dict[str, Any]]:
        breq, wv = s["bRequest"], s["wValue"]
        name = _CP210X_REQUESTS.get(breq, f"0x{breq:02x}")
        extra: dict[str, Any] = {"request": name, "interface": s["wIndex"]}
        st = dev.serial
        st["driver"] = "cp210x"
        if breq == 0x00:
            extra["enabled"] = bool(wv & 1)
            return f"IFC_ENABLE {'enable' if wv & 1 else 'disable'}", extra
        if breq in (0x1E, 0x1D):
            baud = struct.unpack_from("<I", data)[0] if len(data) >= 4 else None
            extra["baud"] = baud
            if baud and (breq == 0x1E or "baud" not in st):
                st["baud"] = baud
            return f"{name}{':' if breq == 0x1E else ' ->'} {baud if baud is not None else '?'}", extra
        if breq == 0x01:
            baud = round(3686400 / wv) if wv else None
            extra["baud"] = baud
            st["baud"] = baud
            return f"SET_BAUDDIV {wv} -> baud {baud}", extra
        if breq in (0x03, 0x04):
            v = wv if breq == 0x03 else (int.from_bytes(data[:2], "little") if len(data) >= 2 else None)
            if v is None:
                return f"{name} -> ?", extra
            lc = _cp210x_line_ctl(v)
            extra.update(lc)
            st.update(lc)
            return f"{name} {_line_str(None, lc['data_bits'], lc['parity'], lc['stop_bits'])}", extra
        if breq == 0x07:
            parts = []
            if wv & 0x0100:
                extra["dtr"] = st["dtr"] = bool(wv & 1)
                parts.append(f"DTR={'on' if wv & 1 else 'off'}")
            if wv & 0x0200:
                extra["rts"] = st["rts"] = bool(wv & 2)
                parts.append(f"RTS={'on' if wv & 2 else 'off'}")
            return "SET_MHS " + (" ".join(parts) or f"(no mask, wValue 0x{wv:04x})"), extra
        if breq == 0x08:
            if data:
                b = data[0]
                ms = {"DTR": bool(b & 1), "RTS": bool(b & 2), "CTS": bool(b & 0x10), "DSR": bool(b & 0x20),
                      "RI": bool(b & 0x40), "DCD": bool(b & 0x80)}
                extra["modem_status"] = ms
                st["modem_status"] = ms
            return f"GET_MDMSTS -> {data.hex() if data else '?'}", extra
        if breq == 0x05:
            return f"SET_BREAK {'on' if wv else 'off'}", extra
        if breq == 0x12:
            return f"PURGE mask 0x{wv:04x}", extra
        return f"{name} wValue 0x{wv:04x} len {len(data)}" + (f": {_clip(data.hex(), 48)}" if data else ""), extra

    # -- non-control endpoints ------------------------------------------------------

    def _classify(self, dev: _Device, ep: int, direction: str, data: bytes) -> dict[str, Any]:
        hint = self._ep_hint(dev.addr, ep, direction)
        if hint:
            return self._kind_ctx(hint, dev, ep, direction, data, source="hint")
        key = ep | (0x80 if direction == "IN" else 0)
        info = dev.endpoints.get(key)
        if info is not None:
            n = info["interface"]
            itf = dev.interfaces.get(n) or {}
            cls = itf.get("class")
            ctx: dict[str, Any] = {"iface": n, "ep_type": info["type"], "source": "descriptor"}
            if cls == 3:
                p = itf.get("protocol")
                ctx.update(kind="hid", hid_type={1: "keyboard", 2: "mouse"}.get(p) if itf.get("subclass") == 1 else None)
                return ctx
            if cls == 0x0A:
                ctx.update(kind="serial", driver="cdc_acm")
                return ctx
            if cls == 0x02:
                ctx.update(kind="cdc_notify")
                return ctx
            if cls == 0x08:
                ctx.update(kind="msc")
                return ctx
            drv = self._driver(dev)
            if drv in _SERIAL_DRIVERS:
                if drv == "ch34x" and info["type"] == "interrupt":
                    ctx.update(kind="ch34x_status", driver=drv)
                else:
                    ctx.update(kind="serial", driver=drv)
                return ctx
            if drv:
                return self._kind_ctx(drv, dev, ep, direction, data, source=dev.driver_source)
            ctx.update(kind="raw")
            return ctx
        drv = self._driver(dev)
        if drv:
            return self._kind_ctx(drv, dev, ep, direction, data, source=dev.driver_source)
        if (direction == "OUT" and len(data) == 31 and data[:4] == b"USBC") or \
                (direction == "IN" and len(data) == 13 and data[:4] == b"USBS") or \
                dev.msc_pending is not None:
            return {"kind": "msc", "iface": None, "source": "heuristic"}
        return {"kind": "raw", "iface": None, "source": None}

    @staticmethod
    def _kind_ctx(kind: str, dev: _Device, ep: int, direction: str, data: bytes,
                  source: str | None) -> dict[str, Any]:
        ctx: dict[str, Any] = {"iface": None, "source": source}
        if kind in ("cdc", "serial"):
            if kind == "cdc" and direction == "IN" and len(data) >= 8 and data[0] == 0xA1 \
                    and data[1] in _CDC_NOTIFICATIONS:
                ctx["kind"] = "cdc_notify"
            else:
                ctx.update(kind="serial", driver="cdc_acm" if kind == "cdc" else "serial")
        elif kind in _SERIAL_DRIVERS:
            if kind == "ch34x" and direction == "IN" and ep == 1:
                ctx.update(kind="ch34x_status", driver=kind)  # CH34x EP1 IN is the interrupt status pipe
            else:
                ctx.update(kind="serial", driver=kind)
        elif kind in ("hid", "keyboard", "mouse"):
            ctx.update(kind="hid", hid_type=None if kind == "hid" else kind)
        elif kind == "msc":
            ctx["kind"] = "msc"
        else:
            ctx["kind"] = "raw"
        return ctx

    def _endpoint_data(self, txn: dict[str, Any]) -> None:
        addr, ep, direction, hs = txn["addr"], txn["ep"], txn["type"], txn.get("handshake")
        dev = self._dev(addr)
        if hs == "STALL":
            ctx = self._classify(dev, ep, direction, b"")
            layer = {"hid": "hid", "msc": "msc", "serial": "serial", "cdc_notify": "cdc",
                     "ch34x_status": "serial"}.get(ctx["kind"], "raw")
            self._out.append(self._mk(txn["seq"], txn["t_us"], addr, ep, layer,
                                      f"EP{ep} {direction} STALL", {"direction": direction, "handshake": "STALL"}))
            return
        if txn.get("data_pid") is None or txn.get("crc_ok") is False:
            return
        data = bytes.fromhex(txn.get("data_hex") or "")
        if not data:
            return
        key = ep | (0x80 if direction == "IN" else 0)
        if txn["data_pid"] in ("DATA0", "DATA1"):
            sig = (txn["data_pid"], data)
            if dev.toggles.get(key) == sig:
                return  # retransmission
            dev.toggles[key] = sig
        ctx = self._classify(dev, ep, direction, data)
        kind = ctx["kind"]
        if kind == "serial":
            self._serial_data(dev, txn, ep, direction, data, ctx)
        elif kind == "hid":
            self._hid_report(dev, txn, ep, direction, data, ctx)
        elif kind == "msc":
            self._msc_data(dev, txn, ep, direction, data)
        elif kind == "cdc_notify":
            self._cdc_notification(dev, txn, ep, data)
        elif kind == "ch34x_status":
            det: dict[str, Any] = {"direction": direction, "data_hex": data.hex(), "driver": "ch34x"}
            text = f"CH34x interrupt status {data.hex()}"
            if len(data) >= 4:
                ms = _ch34x_modem_status(data[2])
                det["modem_status"] = ms
                dev.serial["modem_status"] = ms
                text += " (" + " ".join(f"{k}={'on' if v else 'off'}" for k, v in ms.items()) + ")"
            self._out.append(self._mk(txn["seq"], txn["t_us"], addr, ep, "serial", text, det))
        else:
            det = {"direction": direction, "length": len(data), "data_hex": _hex(data),
                   "data_pid": txn["data_pid"]}
            if ctx.get("ep_type"):
                det["transfer_type"] = ctx["ep_type"]
            self._out.append(self._mk(txn["seq"], txn["t_us"], addr, ep, "raw",
                                      f"EP{ep} {direction} {len(data)} B: {_clip(data.hex(), 64)}", det))

    # -- serial ------------------------------------------------------------------

    def _serial_data(self, dev: _Device, txn: dict[str, Any], ep: int, direction: str, data: bytes,
                     ctx: dict[str, Any]) -> None:
        drv = ctx.get("driver") or "serial"
        if drv == "ftdi" and direction == "IN":
            if len(data) >= 2:
                ms = self._ftdi_status(data[0], data[1])
                dev.serial["modem_status"] = {k: v for k, v in ms.items() if k != "line_errors"}
                if ms["line_errors"]:
                    dev.serial["line_errors"] = ms["line_errors"]
            # Each FTDI bulk-IN USB packet (one transaction) starts with 2 status bytes.
            data = data[2:]
            if not data:
                return  # status-only poll
        k = (dev.addr, ep, direction)
        t = txn.get("t_us") or 0.0
        acc = self._serial_open.get(k)
        if acc is not None and acc["driver"] == drv and t - acc["t_last"] <= self.merge_window_us \
                and len(acc["data"]) + len(data) <= self.max_merge_bytes:
            acc["data"] += data
            acc["t_last"] = t
            acc["seq_end"] = txn["seq"]
            acc["packets"] += 1
            return
        if acc is not None:
            self._emit_serial(acc)
        self._serial_open[k] = {"seq": txn["seq"], "t_us": txn.get("t_us"), "t_last": t, "addr": dev.addr,
                                "ep": ep, "direction": direction, "driver": drv, "data": bytearray(data),
                                "packets": 1, "seq_end": txn["seq"], "source": ctx.get("source")}

    def _emit_serial(self, acc: dict[str, Any]) -> None:
        data = bytes(acc["data"])
        stream = "TX" if acc["direction"] == "OUT" else "RX"
        arrow = "host->device" if acc["direction"] == "OUT" else "device->host"
        text = escape_text(data)
        label = _DRIVER_LABELS.get(acc["driver"], acc["driver"])
        details = {"driver": acc["driver"], "direction": acc["direction"], "stream": stream,
                   "length": len(data), "packets": acc["packets"], "text": text, "data_hex": _hex(data),
                   "printable_ratio": _printable_ratio(data), "seq_end": acc["seq_end"],
                   "t_end_us": acc["t_last"]}
        if len(data) > MAX_HEX_BYTES:
            details["data_truncated"] = True
        if acc.get("source") == "heuristic":
            details["best_effort"] = True
        self._out.append(self._mk(acc["seq"], acc["t_us"], acc["addr"], acc["ep"], "serial",
                                  f'{label} {stream} ({arrow}) {len(data)} B: "{_clip(text, 100)}"', details))

    def _flush_serial(self) -> None:
        for acc in self._serial_open.values():
            self._emit_serial(acc)
        self._serial_open.clear()

    def _cdc_notification(self, dev: _Device, txn: dict[str, Any], ep: int, data: bytes) -> None:
        det: dict[str, Any] = {"direction": "IN", "data_hex": data.hex()}
        if len(data) < 8:
            self._out.append(self._mk(txn["seq"], txn["t_us"], dev.addr, ep, "cdc",
                                      f"CDC notification (short, {len(data)} B)", det))
            return
        bm, note, wv, wi, wl = struct.unpack_from("<BBHHH", data)
        name = _CDC_NOTIFICATIONS.get(note, f"0x{note:02x}")
        det.update(notification=name, interface=wi, wValue=wv)
        text = f"CDC notification {name}"
        if note == 0x20 and len(data) >= 10:
            v = data[8] | (data[9] << 8)
            st = {"DCD": bool(v & 1), "DSR": bool(v & 2), "break": bool(v & 4), "RI": bool(v & 8),
                  "framing_error": bool(v & 0x10), "parity_error": bool(v & 0x20), "overrun": bool(v & 0x40)}
            det["serial_state"] = st
            dev.serial["serial_state"] = st
            text += ": " + " ".join(f"{k}={'on' if v else 'off'}" for k, v in st.items() if k in ("DCD", "DSR", "RI")) \
                + "".join(f" {k}" for k, v in st.items() if v and k not in ("DCD", "DSR", "RI"))
        elif note == 0x00:
            text += ": " + ("connected" if wv else "disconnected")
        self._out.append(self._mk(txn["seq"], txn["t_us"], dev.addr, ep, "cdc", text, det))

    # -- HID ---------------------------------------------------------------------

    def _hid_report(self, dev: _Device, txn: dict[str, Any], ep: int, direction: str, data: bytes,
                    ctx: dict[str, Any]) -> None:
        iface = ctx.get("iface")
        if iface is None and len(dev.hid) == 1:
            iface = next(iter(dev.hid))  # single HID interface known: use its state/layout
        hstate = dev.hid.get(iface, {}) if iface is not None else {}
        layout = hstate.get("layout")
        mode = hstate.get("protocol_mode")
        hid_type = ctx.get("hid_type") or (layout or {}).get("kind")
        det: dict[str, Any] = {"direction": direction, "data_hex": data.hex(), "interface": iface}
        key = ep | (0x80 if direction == "IN" else 0)
        if direction == "OUT":
            text = f"HID output report {len(data)} B: {_clip(data.hex(), 48)}"
            if hid_type == "keyboard" and len(data) == 1:
                leds = [n for b, n in ((1, "NumLock"), (2, "CapsLock"), (4, "ScrollLock")) if data[0] & b]
                det["leds"] = leds
                dev.leds_seen = True
                dev.caps_lock = "CapsLock" in leds
                text = f"HID keyboard LEDs: {', '.join(leds) if leds else 'all off'}"
            self._out.append(self._mk(txn["seq"], txn["t_us"], dev.addr, ep, "hid", text, det))
            return
        if layout and mode != "boot":
            dec = _hid_apply_layout(layout, data)
            if dec is not None:
                det["report_id"] = dec.get("report_id")
                if "keys" in dec:
                    self._keyboard(dev, txn, ep, key, dec["modifiers"], dec["keys"], det, best_effort=False)
                    return
                if "buttons" in dec:
                    self._mouse(dev, txn, ep, dec["buttons"], dec.get("x", 0), dec.get("y", 0),
                                dec.get("wheel"), dec.get("pan"), det)
                    return
                parts = []
                if dec.get("consumer"):
                    parts.append("Consumer: " + ", ".join(dec["consumer"]))
                    det["consumer"] = dec["consumer"]
                if dec.get("values"):
                    det["values"] = dec["values"]
                    parts.append(", ".join(f"{v['usage']}={v['value']}" for v in dec["values"][:8]))
                rid = f" ID {dec['report_id']}" if dec.get("report_id") is not None else ""
                text = f"HID report{rid}: " + ("; ".join(parts) if parts else
                                               ("all released" if not any(data[1 if rid else 0:]) else data.hex()))
                self._out.append(self._mk(txn["seq"], txn["t_us"], dev.addr, ep, "hid", _clip(text, 160), det))
                return
        guessed = hid_type is None and len(data) == 8 and data[1] == 0
        if hid_type == "keyboard" or guessed:
            if len(data) >= 3:
                keys = [c for c in data[2:8] if c]
                self._keyboard(dev, txn, ep, key, data[0], keys, det,
                               best_effort=guessed or ctx.get("source") == "heuristic")
                return
        if hid_type == "mouse" and len(data) >= 3:
            det["best_effort"] = len(data) > 4 and mode != "boot"
            self._mouse(dev, txn, ep, [b + 1 for b in range(5) if data[0] & (1 << b)], _s8(data[1]),
                        _s8(data[2]), _s8(data[3]) if len(data) >= 4 else None, None, det)
            return
        self._out.append(self._mk(txn["seq"], txn["t_us"], dev.addr, ep, "hid",
                                  f"HID input report {len(data)} B: {_clip(data.hex(), 48)}", det))

    def _keyboard(self, dev: _Device, txn: dict[str, Any], ep: int, key: int, mods: int, keys: list[int],
                  det: dict[str, Any], best_effort: bool) -> None:
        state = dev.keyboards.setdefault(key, {"prev": [], "text": ""})
        mod_names = [_MOD_NAMES[b] for b in range(8) if mods & (1 << b)]
        rollover = any(k == 1 for k in keys)
        keys = [k for k in keys if k > 3]
        new = [k for k in keys if k not in state["prev"]]
        shift = bool(mods & 0x22)
        combo = bool(mods & 0xDD)  # Ctrl / Alt / GUI held
        typed = ""
        if not rollover:
            for k in new:
                if k == 0x39 and not dev.leds_seen:
                    dev.caps_lock = not dev.caps_lock
                elif k == 0x2A:
                    if state["text"]:
                        state["text"] = state["text"][:-1]
                    typed += "\b"
                elif not combo and k in _KEY_CHARS:
                    lo, hi = _KEY_CHARS[k]
                    up = shift ^ (dev.caps_lock and lo.isalpha())
                    ch = hi if up else lo
                    typed += ch
                    state["text"] = (state["text"] + ch)[-4096:]
            state["prev"] = keys
        det.update(modifiers=mod_names, keys=[key_name(k) for k in keys], pressed=[key_name(k) for k in new],
                   text=typed, typed_so_far=_clip(state["text"][-200:], 200))
        if best_effort:
            det["best_effort"] = True
        if rollover:
            text = "Keyboard: ErrorRollOver (too many keys)"
        elif not keys and not mods:
            text = "Keyboard: all keys released"
        else:
            combo_txt = "+".join(mod_names + [key_name(k) for k in keys])
            text = f"Keyboard: {combo_txt}"
            if typed:
                text += f' -> "{escape_text(typed.encode("latin-1", "replace"))}"'
        self._out.append(self._mk(txn["seq"], txn["t_us"], dev.addr, ep, "hid", text, det))

    def _mouse(self, dev: _Device, txn: dict[str, Any], ep: int, buttons: list[int], dx: int, dy: int,
               wheel: int | None, pan: int | None, det: dict[str, Any]) -> None:
        names = {1: "Left", 2: "Right", 3: "Middle", 4: "Back", 5: "Forward"}
        bnames = [names.get(b, f"Button{b}") for b in buttons]
        det.update(buttons=bnames, dx=dx, dy=dy, wheel=wheel)
        if pan is not None:
            det["pan"] = pan
        text = f"Mouse: buttons [{', '.join(bnames)}] dx {dx:+d} dy {dy:+d}"
        if wheel:
            text += f" wheel {wheel:+d}"
        if pan:
            text += f" pan {pan:+d}"
        self._out.append(self._mk(txn["seq"], txn["t_us"], dev.addr, ep, "hid", text, det))

    # -- mass storage ---------------------------------------------------------------

    def _msc_data(self, dev: _Device, txn: dict[str, Any], ep: int, direction: str, data: bytes) -> None:
        if direction == "OUT" and len(data) == 31 and data[:4] == b"USBC":
            if dev.msc_pending is not None:
                self._msc_emit_data(dev, note="no CSW seen")
            _sig, tag, dlen, flags, lun, cblen, cb = struct.unpack("<4sIIBBB16s", data)
            cdb = cb[:max(1, min(cblen & 0x1F, 16))]
            ddir = "IN" if flags & 0x80 else "OUT"
            scsi = decode_scsi_cdb(cdb, dev.msc.get("block_size"))
            cbw = {"tag": f"0x{tag:08x}", "data_length": dlen, "direction": ddir if dlen else "none",
                   "lun": lun & 0x0F, "cdb_hex": cdb.hex()}
            dev.msc_pending = {"cbw": cbw, "scsi": scsi, "op": cdb[0], "data": bytearray(), "total": 0,
                               "seq": None, "t_us": None, "ep": None, "dir": ddir}
            exp = f", expects {dlen} B {ddir}" if dlen else ", no data"
            self._out.append(self._mk(txn["seq"], txn["t_us"], dev.addr, ep, "msc",
                                      f"CBW tag {cbw['tag']} LUN {cbw['lun']}: {scsi['summary']}{exp}",
                                      {"phase": "command", "cbw": cbw, "scsi": scsi}))
            return
        pend = dev.msc_pending
        if direction == "IN" and len(data) == 13 and data[:4] == b"USBS":
            _sig, tag, residue, status = struct.unpack("<4sIIB", data)
            csw = {"tag": f"0x{tag:08x}", "residue": residue, "status": _CSW_STATUS.get(status, f"0x{status:02x}")}
            cmd = None
            if pend is not None:
                self._msc_emit_data(dev)
                cmd = pend["scsi"]["name"]
                csw["command"] = cmd
                csw["tag_match"] = pend["cbw"]["tag"] == csw["tag"]
            dev.msc_pending = None
            text = f"CSW tag {csw['tag']}: {csw['status']}" + (f" ({cmd})" if cmd else "")
            if residue:
                text += f", residue {residue}"
            self._out.append(self._mk(txn["seq"], txn["t_us"], dev.addr, ep, "msc", text,
                                      {"phase": "status", "csw": csw}))
            return
        if pend is not None:
            if pend["seq"] is None:
                pend.update(seq=txn["seq"], t_us=txn["t_us"], ep=ep, dir=direction)
            pend["total"] += len(data)
            room = MSC_KEEP_BYTES - len(pend["data"])
            if room > 0:
                pend["data"] += data[:room]
            return
        self._out.append(self._mk(txn["seq"], txn["t_us"], dev.addr, ep, "msc",
                                  f"MSC data {direction} {len(data)} B without CBW",
                                  {"phase": "data", "direction": direction, "length": len(data),
                                   "data_hex": _hex(data, 64)}))

    def _msc_emit_data(self, dev: _Device, note: str | None = None) -> None:
        pend = dev.msc_pending
        if pend is None or not pend["total"]:
            return
        data = bytes(pend["data"])
        name = pend["scsi"]["name"]
        det: dict[str, Any] = {"phase": "data", "command": name, "tag": pend["cbw"]["tag"],
                               "direction": pend["dir"], "length": pend["total"],
                               "expected_length": pend["cbw"]["data_length"], "preview_hex": data[:64].hex()}
        text = f"{name} data {pend['dir']} {pend['total']} B"
        if pend["dir"] == "IN":
            dec, short = _scsi_interpret(pend["op"], data)
            if dec:
                det["decoded"] = dec
                text += f": {short}"
                if "block_size" in dec:
                    dev.msc.update(block_size=dec["block_size"], last_lba=dec["last_lba"],
                                   capacity_bytes=dec["capacity_bytes"])
                if "vendor" in dec:
                    dev.msc.update(vendor=dec["vendor"], product=dec["product"], revision=dec["revision"])
        if note:
            det["note"] = note
            text += f" ({note})"
        self._out.append(self._mk(pend["seq"], pend["t_us"], dev.addr, pend["ep"], "msc", text, det))


def decode_transactions(transactions: Iterable[dict[str, Any]],
                        hints: dict[Any, Any] | None = None) -> dict[str, Any]:
    """One-shot decode: returns {"items": [...], "devices": {...}}."""
    dec = UsbClassDecoder(hints=hints)
    items = dec.feed(transactions)
    pending = dec.pending_start_seq()
    items += dec.flush()
    items.sort(key=lambda it: (it["seq"] if it["seq"] is not None else -1))
    return {"items": items, "devices": dec.devices(), "pending_start_seq": pending}
