//! Debugger module providing DbgEng wrapper and session management.

mod client;
mod output;
mod session;
mod thread;

pub use client::{DebugClient, DebugError};
pub use output::OutputCapture;
pub use session::{DebugSession, SessionManager};
pub use thread::DebuggerThread;
