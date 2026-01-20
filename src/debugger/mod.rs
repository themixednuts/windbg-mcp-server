//! Debugger module providing DbgEng wrapper and session management.

mod client;
mod output;
mod session;

pub use client::DebugClient;
pub use output::OutputCapture;
pub use session::{DebugSession, SessionManager};
