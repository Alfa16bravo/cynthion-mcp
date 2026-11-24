# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- Class decoder: complete-split SETUP tokens (devices behind a high-speed hub) no longer break control transfers;
  a bus reset reports pending control transfers ("aborted by reset") instead of dropping them; SET_ADDRESS moves
  the device model only after an ACKed status stage and never replaces a learned model; FTDI baud decoding of
  multi-port channels and the H-series 12 / 8 Mbaud encodings.
- `analyzer_decode_classes`: during a capture, `next_seq` points at the first item still open so it comes back
  completed on the next page.
- `build_gateware`: stage progress now reaches the client; the build can be cancelled (the process tree is
  killed) and is killed when the server exits; `extra_args` strings accept values with spaces
  (`nextpnr_opts=--seed 3`); the log file is never written after it is closed.
- `gateware_toolchain_status` probes OSS CAD Suite tools with their `bin`/`lib` folders on `PATH`.
- `facedancer_events`: `types` documents the real event values and also matches host event names and data sources.
- README: the default output folder is `~/cynthion_mcp`.
- `pyfwup` and `pygreat` are declared dependencies (imported directly).

## [0.1.0] - 2026-11-20

Initial public release.

### Added
- MCP server (FastMCP, stdio) with 50 tools, 4 resources and 3 prompts for the Great Scott Gadgets Cynthion.
- Discovery and side-effect-free mode detection (Apollo, analyzer, facedancer, gateware stub).
- Apollo / FPGA control: LED pattern, FPGA reconfigure / offline, JTAG scan and debug registers.
- Gateware management: bundled analyzer / facedancer / selftest gateware in SRAM or flash, arbitrary bitstreams,
  SPI flash read / write / erase / info, Apollo DFU firmware update, hardware self-test.
  Persistent and destructive operations require `confirm=true`.
- USB analyzer: background capture with a two-thread reader/parser pipeline, packet, transaction and class-level
  decoding (control, HID, CDC-ACM, mass storage, CH34x / FTDI / CP210x serial), summary and pcap export
  (LINKTYPE_USB_2_0).
- Facedancer emulation in a worker process: keyboard, FTDI serial adapter, mass storage, USB proxy and user scripts.
- Board I/O through the Moondancer firmware: LEDs, PMOD A GPIOs, USER button, firmware debug log.
- Custom gateware builds (`build_gateware`) with YoWASP or a native OSS CAD Suite toolchain, plus `examples/blinky.py`.
- Hardware-free test suite and GitHub Actions CI (Linux, Windows, macOS; Python 3.10 to 3.12).

[Unreleased]: https://github.com/Alfa16bravo/cynthion-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Alfa16bravo/cynthion-mcp/releases/tag/v0.1.0
