//! WinDbg MCP Server - Entry Point
//!
//! A Model Context Protocol (MCP) server that provides debugging capabilities
//! through the Windows Debug Engine (DbgEng).

use rmcp::ServiceExt;
use rmcp::transport::stdio;
use tracing::info;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};
use windbg_mcp_server::{SafetyConfig, WinDbgServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging to stderr (stdout is used for MCP communication)
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    info!("Starting WinDbg MCP Server v{}", env!("CARGO_PKG_VERSION"));

    // Parse command line arguments for configuration
    let args: Vec<String> = std::env::args().collect();
    let permissive = args.iter().any(|a| a == "--permissive");

    let safety_config = if permissive {
        info!("Running with permissive safety configuration (all operations enabled)");
        SafetyConfig::permissive()
    } else {
        info!("Running with default safety configuration");
        info!("  - Memory write: disabled");
        info!("  - Register write: disabled");
        info!("  - Execution control: disabled");
        info!("  - Live attach: enabled");
        info!("  - Command execution: enabled (some commands blocked)");
        SafetyConfig::default()
    };

    // Create the server
    let server = WinDbgServer::new(safety_config);

    // Create stdio transport and run
    let transport = stdio();

    info!("Server ready, waiting for connections on stdio...");

    // Serve the server using the tool router
    let service = server.serve(transport).await?;

    // Wait for the service to complete (keeps server running)
    service.waiting().await?;

    info!("Server shutting down");
    Ok(())
}
