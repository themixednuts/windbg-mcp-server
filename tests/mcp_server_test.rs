//! Integration tests for the WinDbg MCP Server.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

/// Helper to send a JSON-RPC message.
fn send_message(stdin: &mut impl Write, message: &str) {
    writeln!(stdin, "{}", message).unwrap();
    stdin.flush().unwrap();
}

/// Helper to read a line from the reader.
fn read_line(reader: &mut impl BufRead) -> Option<String> {
    let mut response = String::new();
    match reader.read_line(&mut response) {
        Ok(0) => None, // EOF
        Ok(_) => Some(response),
        Err(_) => None,
    }
}

#[test]
fn test_server_initialize() {
    let mut child = Command::new("cargo")
        .args(["run", "--quiet"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start server");

    let mut stdin = child.stdin.take().expect("Failed to get stdin");
    let stdout = child.stdout.take().expect("Failed to get stdout");
    let mut reader = BufReader::new(stdout);

    // Send initialize request
    let init_request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;
    send_message(&mut stdin, init_request);

    let response = read_line(&mut reader);
    assert!(response.is_some(), "Should receive initialize response");

    let response = response.unwrap();
    println!("Initialize response: {}", response);

    assert!(
        response.contains("windbg-mcp-server"),
        "Response should contain server name"
    );
    assert!(
        response.contains("0.1.0"),
        "Response should contain version"
    );
    assert!(
        response.contains("tools"),
        "Response should mention tools capability"
    );

    // Clean up
    drop(stdin);
    let _ = child.wait();
}

#[test]
fn test_server_protocol_flow() {
    // This test verifies the full initialization flow
    let mut child = Command::new("cargo")
        .args(["run", "--quiet"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start server");

    let mut stdin = child.stdin.take().expect("Failed to get stdin");
    let stdout = child.stdout.take().expect("Failed to get stdout");
    let mut reader = BufReader::new(stdout);

    // Step 1: Initialize
    let init_request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;
    send_message(&mut stdin, init_request);

    let response = read_line(&mut reader);
    assert!(response.is_some(), "Should receive initialize response");
    let init_response = response.unwrap();

    // Verify it's a proper JSON-RPC response
    assert!(
        init_response.contains(r#""jsonrpc":"2.0""#),
        "Should be valid JSON-RPC"
    );
    assert!(
        init_response.contains(r#""id":1"#),
        "Should have correct ID"
    );
    assert!(init_response.contains("result"), "Should have result");

    // Clean up
    drop(stdin);
    let _ = child.wait();
}

#[test]
fn test_server_reports_capabilities() {
    let mut child = Command::new("cargo")
        .args(["run", "--quiet"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start server");

    let mut stdin = child.stdin.take().expect("Failed to get stdin");
    let stdout = child.stdout.take().expect("Failed to get stdout");
    let mut reader = BufReader::new(stdout);

    let init_request = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}"#;
    send_message(&mut stdin, init_request);

    let response = read_line(&mut reader).unwrap();

    // Parse response to verify capabilities
    assert!(
        response.contains("capabilities"),
        "Should report capabilities"
    );
    assert!(response.contains("tools"), "Should have tools capability");
    assert!(
        response.contains("instructions"),
        "Should have instructions"
    );
    assert!(
        response.contains("WinDbg"),
        "Instructions should mention WinDbg"
    );

    drop(stdin);
    let _ = child.wait();
}

// Note: Testing tools/list and tools/call requires maintaining the connection
// after the initialized notification. This is challenging in synchronous tests
// because the server expects a persistent connection. In production, Claude Code
// maintains this connection.
