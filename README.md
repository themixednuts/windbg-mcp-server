# windbg-mcp-server

MCP server for WinDbg debugging integration. Enables AI assistants to analyze crash dumps and debug live processes through DbgEng.

## Requirements

- Windows 10/11
- [Debugging Tools for Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/) (Windows SDK)
- Rust 1.75+ (nightly for edition 2024)

## Build

```bash
cargo build --release
```

## Usage

```bash
# Add to Claude Code
claude mcp add windbg /path/to/windbg-mcp-server.exe

# Permissive mode (enables memory writes, execution control)
claude mcp add windbg /path/to/windbg-mcp-server.exe -- --permissive
```

## Tools

| Tool | Description |
|------|-------------|
| `open_dump` | Open crash dump (.dmp) |
| `attach_process` | Attach to live process |
| `detach` | Detach from session |
| `execute` | Run WinDbg command |
| `analyze` | Run `!analyze -v` |
| `get_stack_trace` | Get call stack |
| `list_threads` | List threads |
| `list_modules` | List modules |
| `read_memory` | Read memory |
| `write_memory` | Write memory* |
| `disassemble` | Disassemble code |
| `get_registers` | Get CPU registers |
| `set_breakpoint` | Set breakpoint* |
| `go` | Continue execution* |
| `step` | Single-step* |

\* Requires `--permissive` flag

## Safety

| Operation | Default | Permissive |
|-----------|---------|------------|
| Memory write | Disabled | Enabled |
| Register write | Disabled | Enabled |
| Execution control | Disabled | Enabled |
| Live attach | Enabled | Enabled |

## License

MIT - Copyright (c) 2026 mixednuts
