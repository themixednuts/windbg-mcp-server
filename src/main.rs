//! WinDbg MCP Server entry point.
//!
//! Supports two transports:
//! - **stdio** (default): for use with Claude Code and other MCP clients
//! - **HTTP** (requires `http` feature): Streamable HTTP transport with
//!   optional stateful session tracking

use rmcp::ServiceExt;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use windbg_mcp_server::{SafetyConfig, WinDbgServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let permissive = args.iter().any(|a| a == "--permissive");
    let use_http = args.iter().any(|a| a == "--http");

    // Initialize logging to stderr (stdout is used for MCP stdio communication)
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    info!("Starting WinDbg MCP Server v{}", env!("CARGO_PKG_VERSION"));

    let safety_config = if permissive {
        info!("Running with permissive safety configuration (all operations enabled)");
        SafetyConfig::permissive()
    } else {
        info!("Running with default safety configuration");
        SafetyConfig::default()
    };

    if use_http {
        #[cfg(feature = "http")]
        {
            serve_http(args, safety_config).await?;
        }
        #[cfg(not(feature = "http"))]
        {
            eprintln!(
                "error: --http requires the `http` feature. \
                 Rebuild with: cargo build --features http"
            );
            std::process::exit(1);
        }
    } else {
        serve_stdio(safety_config).await?;
    }

    info!("Server shutting down");
    Ok(())
}

async fn serve_stdio(safety_config: SafetyConfig) -> Result<(), Box<dyn std::error::Error>> {
    let server = WinDbgServer::new(safety_config);
    let transport = rmcp::transport::stdio();
    info!("Listening on stdio");
    let service = server.serve(transport).await?;
    service.waiting().await?;
    Ok(())
}

#[cfg(feature = "http")]
async fn serve_http(
    args: Vec<String>,
    safety_config: SafetyConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    use rmcp::transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
    };
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

    let port = args
        .windows(2)
        .find(|w| w[0] == "--port")
        .and_then(|w| w[1].parse::<u16>().ok())
        .unwrap_or(8080);

    let stateless = args.iter().any(|a| a == "--stateless");

    let cancel = CancellationToken::new();

    let config = StreamableHttpServerConfig {
        stateful_mode: !stateless,
        json_response: stateless,
        cancellation_token: cancel.clone(),
        ..Default::default()
    };

    let app = if stateless {
        info!("Mode: stateless (no sessions, direct JSON responses)");
        let svc = StreamableHttpService::new(
            move || Ok(WinDbgServer::new(safety_config.clone())),
            Arc::new(
                rmcp::transport::streamable_http_server::session::never::NeverSessionManager {},
            ),
            config,
        );
        axum::Router::new().fallback_service(svc)
    } else {
        info!("Mode: stateful (session tracking, streaming responses)");
        let svc = StreamableHttpService::new(
            move || Ok(WinDbgServer::new(safety_config.clone())),
            Arc::new(
                rmcp::transport::streamable_http_server::session::local::LocalSessionManager::default(),
            ),
            config,
        );
        axum::Router::new().fallback_service(svc)
    };

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port)).await?;
    info!("Listening on http://0.0.0.0:{port}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            info!("Shutting down HTTP server");
            cancel.cancel();
        })
        .await?;

    Ok(())
}
