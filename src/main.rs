//! WinDbg MCP Server entry point.
//!
//! Supports two transports:
//! - **stdio** (default): for Claude Code, Cursor, and other local MCP clients
//! - **HTTP** (`--http`): Streamable HTTP at `/mcp` (OpenCode remote, browsers, etc.)

use anyhow::{Context, Result};
use clap::Parser;
use rmcp::ServiceExt;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use windbg_mcp_server::{SafetyConfig, WinDbgServer};

/// MCP server for WinDbg / DbgEng debugging.
#[derive(Debug, Parser)]
#[command(name = "windbg-mcp-server", version, about)]
struct Args {
    /// Enable memory writes, breakpoints, and execution control.
    #[arg(long)]
    permissive: bool,

    /// Serve Streamable HTTP instead of stdio.
    #[arg(long)]
    http: bool,

    /// HTTP listen port (only with `--http`).
    #[arg(long, default_value_t = 8081)]
    port: u16,

    /// HTTP bind address (only with `--http`).
    #[arg(long, default_value = "127.0.0.1")]
    bind: String,

    /// Stateless HTTP: no MCP sessions, JSON responses (only with `--http`).
    #[arg(long)]
    stateless: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Logging goes to stderr so stdio MCP traffic stays clean on stdout.
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    info!("Starting WinDbg MCP Server v{}", env!("CARGO_PKG_VERSION"));

    let safety_config = if args.permissive {
        info!("Running with permissive safety configuration (all operations enabled)");
        SafetyConfig::permissive()
    } else {
        info!("Running with default safety configuration");
        SafetyConfig::default()
    };

    if args.http {
        #[cfg(feature = "http")]
        {
            serve_http(args, safety_config).await?;
        }
        #[cfg(not(feature = "http"))]
        {
            anyhow::bail!(
                "--http requires the `http` feature. Rebuild with: cargo build --features http"
            );
        }
    } else {
        serve_stdio(safety_config).await?;
    }

    info!("Server shutting down");
    Ok(())
}

async fn serve_stdio(safety_config: SafetyConfig) -> Result<()> {
    // MCP hosts sometimes drop the child Process handle on reconnect without
    // killing it. Reclaim any same-parent leftovers, then exit if our parent dies.
    windbg_mcp_server::process_guard::reclaim_stale_stdio_siblings();
    let _transport_marker = windbg_mcp_server::process_guard::TransportMarker::acquire("stdio");

    let server = WinDbgServer::new(safety_config);
    let transport = rmcp::transport::stdio();
    info!("Listening on stdio");
    let service = server.serve(transport).await.context("stdio serve failed")?;

    tokio::select! {
        result = service.waiting() => {
            result.context("stdio service ended with error")?;
            info!("Stdio transport closed");
        }
        _ = windbg_mcp_server::process_guard::wait_for_parent_exit() => {
            info!("Parent process exited; shutting down stdio server");
        }
    }

    Ok(())
}

#[cfg(feature = "http")]
async fn serve_http(args: Args, safety_config: SafetyConfig) -> Result<()> {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
        session::local::LocalSessionManager, session::never::NeverSessionManager,
    };
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

    let _transport_marker = windbg_mcp_server::process_guard::TransportMarker::acquire("http");

    // One shared debugger backend for all MCP HTTP sessions/requests.
    let server = WinDbgServer::new(safety_config);
    let cancel = CancellationToken::new();

    let config = StreamableHttpServerConfig::default()
        .with_stateful_mode(!args.stateless)
        .with_json_response(args.stateless)
        .with_cancellation_token(cancel.clone())
        .with_allowed_hosts([
            "localhost".to_string(),
            "127.0.0.1".to_string(),
            "::1".to_string(),
            format!("localhost:{}", args.port),
            format!("127.0.0.1:{}", args.port),
            format!("[::1]:{}", args.port),
        ]);

    // OpenCode / Ghidra-style clients expect the MCP endpoint at `/mcp`.
    let app = if args.stateless {
        info!("Mode: stateless (no sessions, direct JSON responses)");
        let service = StreamableHttpService::new(
            {
                let server = server.clone();
                move || Ok(server.clone())
            },
            Arc::new(NeverSessionManager::default()),
            config,
        );
        axum::Router::new().nest_service("/mcp", service)
    } else {
        info!("Mode: stateful (session tracking, streaming responses)");
        let service = StreamableHttpService::new(
            {
                let server = server.clone();
                move || Ok(server.clone())
            },
            LocalSessionManager::default().into(),
            config,
        );
        axum::Router::new().nest_service("/mcp", service)
    };

    let addr = format!("{}:{}", args.bind, args.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind {addr}"))?;

    info!("Listening on http://{addr}/mcp");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            info!("Shutting down HTTP server");
            cancel.cancel();
        })
        .await
        .context("HTTP server error")?;

    Ok(())
}
