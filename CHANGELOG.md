# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-24

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
