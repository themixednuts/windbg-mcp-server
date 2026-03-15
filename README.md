# windbg-mcp-server

MCP server for WinDbg debugging integration. Enables AI assistants to analyze crash dumps and debug live processes through DbgEng.

## Requirements

- Windows 10/11
- [Debugging Tools for Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/) (Windows SDK)
- Rust 1.85+ (edition 2024)

## Build

```bash
# Standard build (stdio transport only)
cargo build --release

# With HTTP transport support
cargo build --release --features http
```

## Usage

### stdio (default)

```bash
# Add to Claude Code
claude mcp add windbg /path/to/windbg-mcp-server.exe

# Permissive mode (enables memory writes, execution control)
claude mcp add-json windbg '{"command":"/path/to/windbg-mcp-server.exe","args":["--permissive"]}'
```

### HTTP (requires `http` feature)

```bash
# Stateful — sessions persist across requests
windbg-mcp-server --http --port 8080

# Stateless — each request is independent, direct JSON responses
windbg-mcp-server --http --stateless --port 8080

# Both modes support --permissive
windbg-mcp-server --http --port 8080 --permissive
```

## Tools

| Tool | Description |
|------|-------------|
| `open_dump` | Open crash dump (.dmp) |
| `attach_process` | Attach to live process |
| `connect_remote` | Connect to remote WinDbg server |
| `detach` | Detach from session |
| `list_sessions` | List active sessions |
| `execute` | Run WinDbg command |
| `analyze` | Run `!analyze -v` |
| `get_stack_trace` | Get call stack |
| `list_threads` | List threads |
| `switch_thread` | Switch thread context |
| `list_modules` | List loaded modules |
| `read_memory` | Read memory |
| `search_memory` | Search memory for byte pattern |
| `write_memory` | Write memory* |
| `resolve_symbol` | Resolve symbol to address or vice versa |
| `get_type_info` | Get type layout information |
| `disassemble` | Disassemble code |
| `get_registers` | Get CPU registers |
| `set_breakpoint` | Set breakpoint* |
| `remove_breakpoint` | Remove breakpoint* |
| `go` | Continue execution* |
| `step` | Single-step* |
| `break_execution` | Break into debugger* |
| `load_script` | Load a JavaScript debugging script |
| `unload_script` | Unload a script |
| `run_script` | Load, execute, and unload a script |
| `invoke_script` | Invoke a function from a loaded script |
| `eval` | Evaluate a JavaScript expression (dx) |
| `list_scripts` | List loaded scripts |

\* Requires `--permissive` flag

## Prompts

Pre-built debugging workflows that guide the assistant through multi-step analysis:

| Prompt | Description |
|--------|-------------|
| `crash_triage` | Open a dump, run !analyze, inspect threads and modules, summarize root cause |
| `thread_analysis` | Enumerate threads, check for deadlocks, analyze lock contention |
| `memory_investigation` | Inspect heap state, search for corruption patterns, analyze suspect addresses |

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

By default, dangerous operations are disabled. Use `--permissive` to enable them.

| Operation | Default | Permissive |
|-----------|---------|------------|
| Memory write | Disabled | Enabled |
| Register write | Disabled | Enabled |
| Execution control | Disabled | Enabled |
| Live attach | Enabled | Enabled |
| Command execution | Enabled (some blocked) | Enabled (all) |

## License

MIT
