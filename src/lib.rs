//! WinDbg MCP Server
//!
//! A Model Context Protocol (MCP) server that provides debugging capabilities
//! through the Windows Debug Engine (DbgEng).

pub mod config;
pub mod debugger;
pub mod process_guard;
pub mod schema_compat;
pub mod server;
pub mod types;

pub use config::SafetyConfig;
pub use debugger::{DebugSession, SessionManager};
pub use server::WinDbgServer;
