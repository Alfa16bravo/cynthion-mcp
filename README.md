# cynthion-mcp

An [MCP](https://modelcontextprotocol.io) (Model Context Protocol) server that lets an AI assistant such as Claude drive a **Great Scott Gadgets Cynthion**: capture and decode USB traffic, emulate USB devices with Facedancer, switch, flash and build FPGA gateware, and drive the board I/O.

> **Unofficial project.** `cynthion-mcp` is a community project. It is **not affiliated with, endorsed by or supported by Great Scott Gadgets**. "Cynthion", "Great Scott Gadgets", "Facedancer", "Moondancer", "LUNA", "Packetry" and other names are trademarks of their respective owners and are used here only to describe compatibility.

The server is built on FastMCP (the official `mcp` Python SDK) and speaks JSON-RPC over **stdio**. It stays usable without hardware: the decoding, information and build tools work offline, and hardware tools fail cleanly with `[NO_DEVICE]`.

## Features

- **Discovery**: list Cynthion boards, detect the current mode (Apollo, analyzer, facedancer...) without side effects, read hardware revision, firmware, FPGA and SPI flash details.
- **Gateware switching**: load the bundled `analyzer`, `facedancer` or `selftest` gateware into FPGA SRAM (volatile), or flash it (persistent, confirmation required).
- **USB analyzer**: background capture (auto / high / full / low speed), packet decoding (PID, address, endpoint, CRC5/CRC16), transactions, class-level decoding (standard requests and descriptors, HID, CDC-ACM, mass storage, CH34x / FTDI / CP210x serial), statistics and **pcap export** for Wireshark or Packetry.
- **Facedancer device emulation** (Moondancer backend): keyboard, FTDI serial adapter, mass-storage stick, USB proxy, or your own Python device script.
- **Board I/O**: the six FPGA LEDs, PMOD A GPIOs, USER button, Apollo LED pattern, JTAG registers, firmware debug log.
- **SPI flash and firmware**: JEDEC/UID info, read, write, erase, Apollo DFU firmware update.
- **Hardware self-test** (PHYs, HyperRAM, debug module).
- **Custom gateware builds**: build an Amaranth design into a `.bit` bitstream with the open-source ECP5 toolchain, then load it.

## Supported hardware

- **Cynthion r0.6 and later.** Developed and tested on **Cynthion r1.4**.
- Uses the gateware and firmware bundled with the installed `cynthion` Python package, selected automatically for the detected board revision.
- Host OS: Windows 10/11, Linux, macOS (Python >= 3.10). Hardware validation so far was done on Windows.

### Board ports and buttons

```text
        CONTROL (USB-C)                  AUX (USB-C)
     +------[====]--------------------------[====]------+
     |                                                  |
     |   [PROGRAM]        LEDs 0..5     [USER] [RESET]  |
     |                                                  |
     |              ECP5 FPGA  +  Apollo MCU            |
     |                                                  |
     +------[====]--------------------------[=====]-----+
        TARGET-C (USB-C)                 TARGET-A (USB-A)

                  (schematic only, not to scale)
```

| Port | Role |
|---|---|
| **CONTROL** | Connects to **your PC** (the machine running `cynthion-mcp`). Shared between the Apollo debug MCU (`1d50:615c`) and the running gateware (`1d50:615b`). Every tool talks through this port. |
| **TARGET-C** | Analyzer: connects to the **host** being observed. Facedancer: the **emulated device appears here**; connect it to the target host. |
| **TARGET-A** | Analyzer: the **device under test** plugs in here and is passed through to TARGET-C while it is captured. |
| **AUX** | Auxiliary port. Used by the analyzer's built-in test device (`analyzer_test_device`, `1209:000a`) and by some gateware. |

| Button | Role |
|---|---|
| **PROGRAM** | Hands the CONTROL port back to Apollo (stops the gateware). Held while plugging in, it keeps the board in Apollo / bootloader mode for recovery. |
| **USER** | General-purpose button, readable with `gpio_read(pin="USER")` in facedancer mode. |
| **RESET** | Reboots the FPGA from SPI flash (same effect as `reconfigure_fpga`). |

### Device modes

`server_status` and `list_devices` report the current mode:

| Mode | USB ID | Meaning |
|---|---|---|
| `apollo` | `1d50:615c` | Only Apollo is enumerated: FPGA unconfigured or running USB-less gateware (selftest). |
| `analyzer` | `1d50:615b`, subclass `0x10` | USB analyzer gateware: use the `analyzer_*` tools. |
| `facedancer` | `1d50:615b`, subclass `0x20` | Moondancer gateware + SoC firmware: use the `facedancer_*` and board I/O tools. |
| `gateware_stub` | LUNA IDs, Apollo stub interface only | Custom gateware. |
| `absent` | - | No Cynthion visible: use the `diagnose_connection` prompt. |

Only one user of the USB port at a time: a running capture or emulation blocks every tool that reconfigures or reflashes the FPGA (`[BUSY]`) until `analyzer_stop` / `facedancer_stop`.

## Installation

```bash
# from a clone
git clone https://github.com/Alfa16bravo/cynthion-mcp.git
cd cynthion-mcp
pip install -e .

# or directly from git
pip install "git+https://github.com/Alfa16bravo/cynthion-mcp.git"
```

Optional extras:

```bash
pip install -e ".[build]"   # YoWASP toolchain for build_gateware
pip install -e ".[dev]"     # pytest + ruff
```

An MCP client starts the server with `python -m cynthion_mcp` (or the `cynthion-mcp` console script). It speaks JSON-RPC on stdin/stdout and is not meant to be used by hand.

### Drivers

**Windows**
- The **WinUSB** driver is normally bound automatically: Apollo and the Cynthion gateware expose Microsoft OS descriptors, so no manual install is needed.
- If you get `[DRIVER]` (access denied / libusb not found), use **Zadig** to install WinUSB on:
  - `1d50:615c` Cynthion Apollo Debugger;
  - `1d50:615b` Cynthion gateware (USB Analyzer / Facedancer), all interfaces.
- The libusb-1.0 DLL ships with the `libusb1` Python package; nothing else to install.
- In Facedancer `proxy` mode, the proxied real device must also use WinUSB (often via Zadig).

**Linux**
- Install the udev rules with `cynthion setup` (from the `cynthion` package), then unplug and replug the board.
- Make sure libusb-1.0 is installed (`sudo apt install libusb-1.0-0` on Debian/Ubuntu).

**macOS**
- No driver needed. Install libusb if pyusb cannot find a backend (`brew install libusb`).

### Optional toolchain for `build_gateware`

`build_gateware` needs `yosys`, `nextpnr-ecp5` and `ecppack`. Either:

```bash
pip install yowasp-yosys yowasp-nextpnr-ecp5    # pure pip, works on Windows (same as: pip install -e ".[build]")
```

or install the [OSS CAD Suite](https://github.com/YosysHQ/oss-cad-suite-build) and put its `bin` folder on `PATH`. `gateware_toolchain_status` reports what was found.

## Registering with an MCP client

### Claude Code

```bash
claude mcp add cynthion -- python -m cynthion_mcp
```

Use the full path of your Python interpreter instead of `python` if several are installed. Check with `claude mcp list`; the tools appear as `mcp__cynthion__<tool>`. A server declared at project scope (`-s project` or `.mcp.json`) must be approved once in Claude Code (`/mcp`).

### Generic MCP client (JSON config)

Copy `.mcp.json.example` to `.mcp.json`, or add this block to your client's configuration (for Claude Desktop: `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "cynthion": {
      "type": "stdio",
      "command": "python",
      "args": ["-m", "cynthion_mcp"],
      "env": {
        "PYTHONUNBUFFERED": "1",
        "CYNTHION_MCP_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `CYNTHION_MCP_LOG_LEVEL` | Log level (`DEBUG`, `INFO`, `WARNING`...) | `INFO` |
| `CYNTHION_MCP_OUTPUT_DIR` | Default folder for generated files (pcap, flash dumps, builds; builds go to its `gateware_builds` subfolder) | `~/cynthion_mcp` (the `cynthion_mcp` folder in your home directory) |
| `LUNA_USB_IDS` | Extra `VVVV:PPPP` gateware ID recognised by apollo_fpga (read at import time) | - |
| `PYTHONUNBUFFERED` | Recommended `1` for an unbuffered stdio stream | - |

## Tools (50)

### A. General / discovery

| Tool | Description |
|---|---|
| `server_status` | Overall server state: package versions, platform, detected Cynthion mode and devices, analyzer capture status and Facedancer emulation status. |
| `list_devices` | Non-invasively enumerate Cynthion-related USB devices (Apollo 1d50:615c, gateware 1d50:615b...) with their mode, strings, revision and interfaces. |
| `device_info` | Detailed Apollo/Cynthion info: hardware name and revision, serial, firmware and USB API versions, ADC. |
| `list_bundled_assets` | List the gateware bitstreams (per board revision) and firmware images bundled with the installed cynthion package. |
| `get_logs` | Return recent server and library log lines (cynthion_mcp, apollo_fpga, facedancer, cynthion). |

### B. Apollo / FPGA control

| Tool | Description |
|---|---|
| `set_led_pattern` | Set the Apollo debug-MCU LED pattern. |
| `reconfigure_fpga` | Reboot the FPGA from SPI flash (soft reset + allow gateware USB takeover). |
| `force_fpga_offline` | Hold the FPGA offline so Apollo owns JTAG and the CONTROL USB port. |
| `jtag_scan` | Enumerate the JTAG chain through Apollo and return IDCODEs (0x21111043 = LFE5U-12F). |
| `jtag_register_read` | Read a gateware debug register over the JTAG/SPI register bridge (only for gateware that exposes one, e.g. selftest). |
| `jtag_register_write` | Write a gateware debug register over the JTAG register bridge (e.g. selftest register 2 = LEDs). |

### C. Gateware / SPI flash

| Tool | Description |
|---|---|
| `run_gateware` | Load a bundled gateware (analyzer, facedancer or selftest) matching the board revision into FPGA SRAM. |
| `configure_bitstream` | Load an arbitrary bitstream file into FPGA SRAM over JTAG (volatile). |
| `flash_gateware` | PERSISTENT: write a bundled gateware to SPI flash so it boots at power-on (facedancer also writes the SoC firmware). **(confirm=true)** |
| `flash_file` | PERSISTENT: write a file to the SPI flash at the given offset. **(confirm=true)** |
| `read_flash` | Dump SPI flash content to a file. |
| `erase_flash` | PERSISTENT and DESTRUCTIVE: erase the whole SPI flash (gateware and SoC firmware). **(confirm=true)** |
| `flash_info` | Read the SPI flash JEDEC manufacturer/part and 64-bit unique ID over JTAG. |
| `update_apollo_firmware` | PERSISTENT: update the Apollo debug MCU firmware over DFU. **(confirm=true)** |
| `run_selftest` | Load the selftest gateware and run the hardware self-tests (debug module, PHYs, HyperRAM). |

### D. USB analyzer

| Tool | Description |
|---|---|
| `analyzer_info` | Query the analyzer gateware: protocol version, supported speeds, decoded state register, serial. |
| `analyzer_start` | Start a background USB capture between TARGET-C (host) and TARGET-A (device). |
| `analyzer_stop` | Stop the running capture, drain the remaining data and keep the buffer for reading/export. |
| `analyzer_status` | Capture status: running flag, speed, packet/event/byte counters, buffer usage, errors. |
| `analyzer_read` | Read decoded capture records (packets with PID/address/endpoint/data/CRC check, and bus events) from the buffer. |
| `analyzer_transactions` | Group captured packets into transactions (token + data + handshake), decoding SETUP requests. |
| `analyzer_summary` | Statistics of the buffered capture: packets per PID, devices/endpoints seen with byte counts, events, detected speed, duration and CRC errors. |
| `analyzer_export_pcap` | Write the buffered capture to a pcap file (LINKTYPE_USB_2_0 = 288, opens in Wireshark/Packetry). |
| `analyzer_clear` | Discard the buffered capture. |
| `analyzer_capture` | Bounded one-shot capture: start, wait `seconds` (with progress), stop, and return status + summary (optionally exporting a pcap). |
| `analyzer_test_device` | Control the analyzer's built-in USB test device on the AUX port (1209:000a, r0.6+). |
| `analyzer_decode_classes` | Decode the captured traffic at USB class level: standard control requests and descriptors (device model per address), HID reports (keys, mouse), CDC-ACM line coding / serial state, mass-storage CBW/SCSI/CSW, and serial data of CDC-ACM / CH34x / FTDI / CP210x adapters. |
| `decode_usb_packet` | Decode one raw USB 2.0 packet: PID, address/endpoint/frame, payload, CRC5/CRC16 check, and SETUP request decoding for 8-byte DATA0 payloads. |

### E. Facedancer (device emulation)

| Tool | Description |
|---|---|
| `facedancer_list_device_kinds` | Describe the device kinds facedancer_start can emulate (keyboard, ftdi, mass_storage, proxy, script), their parameters and supported commands. |
| `facedancer_start` | Start emulating a USB device with Facedancer in a background worker process. |
| `facedancer_command` | Send a command to the running emulated device (e.g. key_down, type_string, serial_write, status) and return its result. |
| `facedancer_type_text` | Type text on the target host with the emulated keyboard (kind=keyboard must be running). |
| `facedancer_serial_write` | Send data from the emulated FTDI serial adapter to the target host (kind=ftdi must be running). |
| `facedancer_status` | Status of the Facedancer worker: running, kind, connected, pid, uptime, exit code, last error. |
| `facedancer_logs` | Log output of the Facedancer worker process (facedancer library logs, stdout/stderr). |
| `facedancer_events` | Events emitted by the emulated device (control requests from the host, received data, proxy traffic...). |
| `facedancer_stop` | Stop the emulation (disconnects the emulated device) and report unhandled control requests. |

### F. Board I/O (Moondancer firmware, facedancer mode)

| Tool | Description |
|---|---|
| `board_info` | Moondancer board info (name, firmware version, serial, part id, libgreat APIs). |
| `led_set` | Drive one of the 6 FPGA LEDs through the Moondancer firmware. |
| `gpio_list` | List the GPIO pins available through Moondancer (PMOD A pins A1-A4, A7-A10 and USER button). |
| `gpio_read` | Configure a pin as input and read it. 'USER' reads the user button. |
| `gpio_write` | Configure a pin as push-pull output and drive it high or low. |
| `board_debug_log` | Read the Moondancer firmware debug ring buffer (dmesg). |

### G. Custom gateware build

| Tool | Description |
|---|---|
| `gateware_toolchain_status` | Check the open-source ECP5 toolchain used by build_gateware (yosys, nextpnr-ecp5, ecppack): native installs (env overrides, PATH, OSS CAD Suite) or YoWASP packages. |
| `build_gateware` | Build an Amaranth design for the Cynthion ECP5 into a .bit bitstream in a subprocess (yosys -> nextpnr-ecp5 -> ecppack), with progress. |

The descriptions above are the first sentence of each tool's MCP description, generated from the server's `list_tools` output. Tools marked **(confirm=true)** are persistent or destructive.

Without hardware, these tools still work: `server_status`, `list_devices`, `list_bundled_assets`, `get_logs`, `decode_usb_packet`, `analyzer_status` / `analyzer_read` / `analyzer_summary` / `analyzer_transactions` / `analyzer_decode_classes` (on the last capture), `facedancer_list_device_kinds` / `facedancer_status` / `facedancer_logs` / `facedancer_events`, `gateware_toolchain_status` and `build_gateware`.

### Error codes

Errors read `[CODE] message`, optionally followed by a `Hint: ...` line.

| Code | Meaning | What to do |
|---|---|---|
| `[NO_DEVICE]` | No Cynthion detected | Plug in the CONTROL port; see `diagnose_connection` |
| `[WRONG_MODE]` | Device present but running the wrong gateware | Switch gateware, or keep `auto_load_gateware=true` |
| `[BUSY]` | USB port already in use (capture or emulation running) | `analyzer_stop` / `facedancer_stop` |
| `[DRIVER]` | libusb not found or access denied | Windows: WinUSB via Zadig; Linux: udev rules |
| `[CONFIRMATION_REQUIRED]` | Destructive tool called without `confirm=true` | Ask the user, then call again with `confirm=true` |
| `[INVALID_ARGUMENT]` | Invalid parameter | Fix the call |
| `[HARDWARE]` | JTAG, flash or I/O failure | `get_logs`, then `reconfigure_fpga` |
| `[UNSUPPORTED]` | Feature missing on this revision, firmware or host | - |
| `[TIMEOUT]` | Device did not answer or re-enumerate in time | Retry; check the cable |
| `[BUILD_FAILED]` | Gateware design or toolchain error | Read the log tail returned by `build_gateware` |

## Resources and prompts

| Resource | Content |
|---|---|
| `cynthion://status` | Server, device and activity status (same as `server_status`). |
| `cynthion://assets` | Bundled gateware and firmware assets. |
| `cynthion://capture/last.pcap` | Current analyzer buffer as a pcap file (LINKTYPE_USB_2_0). |
| `cynthion://logs` | Last 500 server log lines. |

| Prompt | Purpose |
|---|---|
| `capture_usb_traffic` | Step-by-step guide to capture and analyse the USB traffic of a device. |
| `emulate_keyboard` | Guide to emulate a USB keyboard and type text on the target host. |
| `diagnose_connection` | Checklist to diagnose why no Cynthion is detected. |

## Example workflows

### Capture USB traffic, decode it, open it in Wireshark or Packetry

Wiring: PC on **CONTROL**, observed host on **TARGET-C**, device under test on **TARGET-A**.

```text
analyzer_capture(seconds=10, speed="full", export_pcap_path="captures/device.pcap")
analyzer_summary()                                   # devices, endpoints, PIDs, errors
analyzer_transactions(address=3, endpoint=0)         # SETUP requests of device 3
analyzer_decode_classes(address=3)                   # descriptors, HID reports, serial data...
analyzer_export_pcap(path="captures/device.pcap")    # if not exported above
```

For longer or interactive sessions use `analyzer_start`, then `analyzer_status` / `analyzer_read`, then `analyzer_stop`. The pcap uses LINKTYPE_USB_2_0 (288), one record per packet with nanosecond timestamps; open it in **Wireshark** (`usbll` dissector) or **Packetry**. If a capture missed the enumeration, pass `hints` (device address to class) to `analyzer_decode_classes`.

### Emulate devices with Facedancer

The emulated device appears on **TARGET-C**; connect that port to the target host.

```text
# FTDI serial adapter: round-trip data with the target host
facedancer_start(kind="ftdi")
facedancer_serial_write(data="hello from cynthion")
facedancer_events()                  # data the host sent to the adapter
facedancer_stop()

# Keyboard: types into the focused window of the target host (US layout)
facedancer_start(kind="keyboard")
facedancer_type_text(text="hello")
facedancer_stop()

# Mass storage: synthetic FAT32 image, or params={"image_path": "<existing raw image>"}
facedancer_start(kind="mass_storage")
facedancer_stop()
```

`facedancer_list_device_kinds` lists every kind with its parameters and commands. With `kind="script"`, `script_path` points to a Python file that defines `create_device(params)` (returning a Facedancer `USBDevice`) and optionally `handle_command(device, command, args)`. Use `logging` rather than `print()` in scripts; the output is visible with `facedancer_logs`.

### Build and load a blinky

```text
gateware_toolchain_status()
build_gateware(source="examples/blinky.py")              # returns the .bit path
configure_bitstream(path="<bitstream path returned above>")
reconfigure_fpga()                                       # back to the gateware in flash
```

`configure_bitstream` loads into SRAM only: the design is lost at power-off or on `reconfigure_fpga`.

## Safety

- **Destructive or persistent operations need `confirm=true`.** `flash_gateware`, `flash_file`, `erase_flash` and `update_apollo_firmware` first return `[CONFIRMATION_REQUIRED]` with a description of the operation. The assistant must get explicit human approval before repeating the call with `confirm=true`. If a flash write is interrupted, recover with `run_gateware`, then `flash_gateware(target="analyzer", confirm=true)`; Apollo keeps its DFU bootloader.
- **Arbitrary code execution by design.** `facedancer_start(kind="script", script_path=...)` runs the given Python file in the worker process, and `build_gateware(source=...)` runs the given Python/Amaranth file in the build subprocess. Only use files you trust. All file paths passed to tools are used as-is.
- **Keyboard emulation types into whatever window has focus on the target host**, so it can run commands there. Only use Facedancer on machines you own or are authorised to test.
- **Captures are sensitive.** The analyzer and the USB proxy see all traffic of the observed device (keystrokes, passwords, file contents, tokens). Treat pcap files and logs accordingly.

## Limitations

- The analyzer stream is decoded in **pure Python**: sustained throughput is roughly **7-10 MB/s**. Bursts above that are buffered and decoded afterwards (backlog catch-up); very long high-speed bulk transfers can outrun it.
- **Full-speed capture is validated on hardware. High-speed capture is implemented but not yet validated.**
- **No USB host mode**: the Cynthion is used as an analyzer or as an emulated device, not as a USB host.
- Hardware validation was done on a single r1.4 board under Windows.

## Validated on hardware

Tested on a Cynthion r1.4 under Windows 11 with Python 3.10:

| Feature | Status |
|---|---|
| Device and mode detection | Validated |
| Analyzer: full-speed capture, packet / transaction / class decoding, pcap export | Validated |
| Analyzer: high-speed capture | Not yet validated |
| Gateware switching (analyzer / facedancer / selftest, SRAM) | Validated |
| SPI flash read | Validated |
| Facedancer FTDI emulation: serial round-trip with the target host | Validated |
| FPGA LEDs and USER button (facedancer mode) | Validated |
| Blinky build (YoWASP toolchain on Windows) and SRAM load | Validated |

## Development

```bash
pip install -e ".[dev]"
python -m pytest                  # no hardware needed: USB access is mocked
python -m pytest -m "not slow"    # skip the tests that spawn subprocesses
ruff check src tests examples
```

- The test suite needs **no Cynthion**. Tests marked `slow` spawn real subprocesses (stdio server, gateware elaboration, Facedancer worker).
- `CYNTHION_MCP_SKIP_SLOW=1` skips the smoke test that launches the real Facedancer worker against the USB stack (CI sets it). That test also skips itself when a real Cynthion is plugged in.
- Never `print()` to stdout from server code: stdout carries the JSON-RPC stream.

Project layout:

```text
src/cynthion_mcp/
  server.py                  FastMCP instance, tools, resources, prompts, main()
  common.py                  errors, log ring, stdout guard, hardware lock, activity registry
  device.py                  Apollo discovery, mode detection, info, LEDs, JTAG
  gateware.py                bundled assets, SRAM configuration, flash, SoC firmware, DFU, selftest
  gateware_build.py          ECP5 toolchain discovery and build orchestration
  gateware_build_runner.py   build subprocess (elaborate, yosys, nextpnr-ecp5, ecppack)
  analyzer.py                analyzer gateware driver, capture manager (reader + parser threads)
  usbdecode.py               stdlib-only stream parser, PID/CRC, transactions, pcap writer
  usbclass.py                stdlib-only USB class-level decoder
  facedancer_runner.py       parent side of the Facedancer worker process
  facedancer_worker.py       child process running the emulated device
  board_io.py                LEDs / GPIO / info through the Moondancer firmware
examples/blinky.py           minimal Amaranth design for build_gateware
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE). The Cynthion gateware and firmware used by the tools are not part of this repository; they come from the `cynthion` package under their own licenses.
