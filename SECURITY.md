# Security Policy

## Supported versions

Only the latest release of `cynthion-mcp` receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private vulnerability reporting
instead: on the repository page, go to **Security > Report a vulnerability**
(https://github.com/Alfa16bravo/cynthion-mcp/security/advisories/new).

Include a description of the problem, the affected version, steps to reproduce and the potential impact.
You should get a first answer within a few days. Please give us reasonable time to release a fix before
disclosing the issue publicly.

## Scope and expected behaviour

Some capabilities are powerful **by design** and are not vulnerabilities in themselves:

- `facedancer_start(kind="script")` and `build_gateware` execute the Python file they are given.
- Keyboard emulation types into the focused window of the target host.
- Flash, erase and firmware-update tools modify the board persistently (they require `confirm=true`).
- Analyzer captures and pcap files contain all USB traffic of the observed device.

Reports about bypassing the `confirm=true` safeguard, writing to stdout in a way that corrupts the MCP stream,
path handling that escapes what a caller asked for, or code execution without one of the explicit tools above
are in scope.
