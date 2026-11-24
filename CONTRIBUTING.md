# Contributing

Thanks for your interest in `cynthion-mcp`. Issues and pull requests are welcome.

## Setup

```bash
git clone https://github.com/Alfa16bravo/cynthion-mcp.git
cd cynthion-mcp
pip install -e ".[dev]"
```

## Before opening a pull request

- Run the tests: `python -m pytest`. They need **no hardware** (USB access is mocked).
  `python -m pytest -m "not slow"` skips the tests that spawn subprocesses.
- Run the linter: `ruff check src tests examples`.
- Add or update tests for behaviour changes, and update `README.md` / `CHANGELOG.md` when tools change.
- If you changed hardware-facing code, say in the pull request which board revision and OS you tested on,
  or that it is untested on hardware.

## Code rules

- **Never write to stdout from server code paths.** stdout carries the MCP JSON-RPC stream; use `logging`.
- Keep heavy imports (`apollo_fpga`, `cynthion`, `facedancer`, `usb`, `amaranth`) lazy so the server starts without them.
- Blocking USB calls run in threads (`anyio.to_thread.run_sync`) and take the hardware lock.
- Tools that persist or destroy data must require `confirm=true`.
- Errors are raised as the project's error classes so they reach the client as `[CODE] message` with an optional hint.

## Reporting bugs

Include the output of the `server_status` tool, your OS, Python version, board revision and the relevant
`get_logs` lines. Remove serial numbers and any captured data you do not want to share.

For security issues, see [SECURITY.md](SECURITY.md) instead of opening a public issue.
