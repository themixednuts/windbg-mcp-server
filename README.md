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
claude mcp add-json windbg '{"command":"/path/to/windbg-mcp-server.exe","args":["--permissive"]}'
```

## Tools

| Tool | Description |
|------|-------------|
| `open_dump` | Open crash dump (.dmp) |
| `attach_process` | Attach to live process |
| `connect_remote` | Connect to remote WinDbg server |
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
| `remove_breakpoint` | Remove breakpoint* |
| `go` | Continue execution* |
| `step` | Single-step* |
| `break_execution` | Break into debugger* |

\* Requires `--permissive` flag

## Remote Debugging

To connect to a remote WinDbg session:

1. Start a debug server in WinDbg:
   ```
   .server tcp:port=5005
   ```

2. Use `connect_remote` with the connection string:
   ```
   tcp:server=hostname,port=5005
   ```

## Safety

| Operation | Default | Permissive |
|-----------|---------|------------|
| Memory write | Disabled | Enabled |
| Register write | Disabled | Enabled |
| Execution control | Disabled | Enabled |
| Live attach | Enabled | Enabled |

## License

MIT - Copyright (c) 2026 mixednuts
