#!/usr/bin/env python3
"""Test script for WinDbg MCP Server - uses newline-delimited JSON"""

import subprocess
import json
import sys
import time
import threading

SERVER_PATH = r"E:\Projects\windbg\target\release\windbg-mcp-server.exe"

def send_message(proc, msg):
    """Send a JSON-RPC message (newline-delimited)"""
    json_str = json.dumps(msg)
    proc.stdin.write((json_str + "\n").encode('utf-8'))
    proc.stdin.flush()
    print(f">>> {json_str[:100]}{'...' if len(json_str) > 100 else ''}")

def read_message(proc, timeout=10):
    """Read a JSON-RPC response (newline-delimited)"""
    line = proc.stdout.readline()
    if not line:
        return None
    result = json.loads(line.decode('utf-8').strip())
    result_str = json.dumps(result)
    print(f"<<< {result_str[:200]}{'...' if len(result_str) > 200 else ''}")
    return result

def main():
    print("=== Testing WinDbg MCP Server ===\n")

    # Start server
    proc = subprocess.Popen(
        [SERVER_PATH, "--permissive"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Read stderr in background
    def read_stderr():
        for line in proc.stderr:
            text = line.decode().strip()
            # Only show errors, not info
            if "ERROR" in text or "WARN" in text:
                print(f"[stderr] {text}")

    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    stderr_thread.start()

    time.sleep(0.5)
    print("Server started.\n")

    try:
        # 1. Initialize
        print("1. Initialize...")
        send_message(proc, {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "test-client",
                    "version": "1.0"
                }
            }
        })

        resp = read_message(proc)
        if not resp:
            print("ERROR: No response to initialize!")
            return

        server_name = resp.get("result", {}).get("serverInfo", {}).get("name", "unknown")
        print(f"   Connected to: {server_name}\n")

        # 2. Initialized notification
        print("2. Send initialized notification...")
        send_message(proc, {
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })
        time.sleep(0.2)
        print()

        # 3. List tools
        print("3. List tools...")
        send_message(proc, {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        })

        resp = read_message(proc)
        if resp and "result" in resp:
            tools = resp["result"].get("tools", [])
            print(f"   Found {len(tools)} tools:")
            for t in tools[:5]:
                print(f"     - {t['name']}: {t.get('description', '')[:50]}...")
            if len(tools) > 5:
                print(f"     ... and {len(tools) - 5} more")
        print()

        # 4. Attach to NewWorld (non-invasive)
        print("4. Attach to NewWorld (PID 25052, non-invasive)...")
        send_message(proc, {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "attach_process",
                "arguments": {
                    "pid": 25052,
                    "non_invasive": True
                }
            }
        })

        resp = read_message(proc)
        session_id = None
        if resp and "result" in resp:
            content = resp["result"].get("content", [])
            if content:
                text = content[0].get("text", "{}")
                data = json.loads(text)
                if data.get("success") and data.get("data"):
                    session_id = data["data"].get("session_id")
                    print(f"   Session ID: {session_id}")
                    print(f"   Target: {data['data'].get('target', 'unknown')}")
                else:
                    print(f"   ERROR: {data.get('error', 'unknown error')}")
        print()

        if session_id:
            # 5. Execute '|' command (process info)
            print("5. Execute '|' command (process info)...")
            send_message(proc, {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "execute",
                    "arguments": {
                        "session_id": session_id,
                        "command": "|"
                    }
                }
            })
            resp = read_message(proc)
            if resp and "result" in resp:
                content = resp["result"].get("content", [])
                if content:
                    data = json.loads(content[0].get("text", "{}"))
                    if data.get("data", {}).get("output"):
                        print(f"   Output: {data['data']['output'][:200]}")
            print()

            # 6. List modules (first few)
            print("6. List modules...")
            send_message(proc, {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "list_modules",
                    "arguments": {
                        "session_id": session_id
                    }
                }
            })
            resp = read_message(proc)
            if resp and "result" in resp:
                content = resp["result"].get("content", [])
                if content:
                    data = json.loads(content[0].get("text", "{}"))
                    modules = data.get("data", {}).get("modules", [])
                    if modules:
                        print(f"   Found {len(modules)} modules:")
                        for m in modules[:5]:
                            print(f"     - {m.get('name', 'unknown')}: {m.get('base_address', '?')}")
                        if len(modules) > 5:
                            print(f"     ... and {len(modules) - 5} more")
                    else:
                        print(f"   Response: {data}")
            print()

            # 7. Get stack trace
            print("7. Get stack trace (current thread)...")
            send_message(proc, {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "get_stack_trace",
                    "arguments": {
                        "session_id": session_id,
                        "max_frames": 5
                    }
                }
            })
            resp = read_message(proc)
            if resp and "result" in resp:
                content = resp["result"].get("content", [])
                if content:
                    data = json.loads(content[0].get("text", "{}"))
                    frames = data.get("data", {}).get("frames", [])
                    if frames:
                        print(f"   Stack frames:")
                        for f in frames[:5]:
                            func = f.get("function", "unknown")
                            mod = f.get("module", "?")
                            print(f"     #{f.get('frame_number', '?')} {mod}!{func}")
                    else:
                        print(f"   Response: {data}")
            print()

            # 8. Get registers
            print("8. Get registers...")
            send_message(proc, {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "get_registers",
                    "arguments": {
                        "session_id": session_id
                    }
                }
            })
            resp = read_message(proc)
            if resp and "result" in resp:
                content = resp["result"].get("content", [])
                if content:
                    data = json.loads(content[0].get("text", "{}"))
                    regs = data.get("data", {}).get("registers", [])
                    if regs:
                        print(f"   Registers:")
                        for r in regs[:6]:
                            print(f"     {r.get('name', '?')}: {r.get('value', '?')}")
                        if len(regs) > 6:
                            print(f"     ... and {len(regs) - 6} more")
                    else:
                        print(f"   Response: {data}")
            print()

            # 9. Eval (JavaScript/dx)
            print("9. Eval '@$curprocess' (debugger data model)...")
            send_message(proc, {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {
                    "name": "eval",
                    "arguments": {
                        "session_id": session_id,
                        "code": "@$curprocess"
                    }
                }
            })
            resp = read_message(proc)
            if resp and "result" in resp:
                content = resp["result"].get("content", [])
                if content:
                    data = json.loads(content[0].get("text", "{}"))
                    output = data.get("data", {}).get("output", "")
                    if output:
                        print(f"   Output: {output[:300]}")
            print()

            # 10. Detach
            print("10. Detach...")
            send_message(proc, {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "detach",
                    "arguments": {
                        "session_id": session_id
                    }
                }
            })
            resp = read_message(proc)
            if resp and "result" in resp:
                content = resp["result"].get("content", [])
                if content:
                    data = json.loads(content[0].get("text", "{}"))
                    print(f"   Success: {data.get('success', False)}")
            print()

        print("=== Test Complete ===")

    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except:
            proc.kill()

if __name__ == "__main__":
    main()
