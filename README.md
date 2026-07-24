# windbg-mcp-server

MCP server for WinDbg debugging integration. Enables AI assistants to analyze crash dumps and debug live processes through DbgEng.

## Requirements

- Windows 10/11
- [Debugging Tools for Windows](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/) (Windows SDK)
- Rust 1.85+ (edition 2024)

## Install

```bash
# From this repo
cargo install --path . --force

# Or via cargo-binstall (GitHub release binaries)
cargo binstall --git https://github.com/themixednuts/windbg-mcp-server
```

## Build

```bash
# Default build includes stdio + Streamable HTTP
cargo build --release
```

## Usage

### stdio (default)

```bash
# Add to Claude Code
claude mcp add windbg /path/to/windbg-mcp-server.exe

# Permissive mode (enables memory writes, execution control)
claude mcp add-json windbg '{"command":"/path/to/windbg-mcp-server.exe","args":["--permissive"]}'
```

Stdio mode exits when the parent MCP host dies, and on startup reclaims any
same-parent leftover `windbg-mcp-server` processes from a host that dropped the
child handle without terminating it (common on reconnect).

### HTTP (Streamable HTTP at `/mcp`)

```bash
# Stateful — MCP sessions persist (default port 8081 to avoid Ghidra's 8080)
windbg-mcp-server --http --permissive

# Explicit bind/port
windbg-mcp-server --http --bind 127.0.0.1 --port 8081 --permissive

# Stateless — each request is independent, direct JSON responses
windbg-mcp-server --http --stateless --port 8081
```

OpenCode stdio MCP example (`opencode.json`) — host launches the server:

```json
{
  "mcp": {
    "windbg": {
      "type": "local",
      "command": ["windbg-mcp-server", "--permissive"],
      "enabled": true
    }
  }
}
```

HTTP remote alternative: `{"type":"remote","url":"http://127.0.0.1:8081/mcp","enabled":true}` after `windbg-mcp-server --http --permissive`.

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
