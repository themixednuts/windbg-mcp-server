//! Output capture for DbgEng commands.

use parking_lot::Mutex;
use std::sync::Arc;

/// Captures output from DbgEng commands.
#[derive(Debug, Clone)]
pub struct OutputCapture {
    buffer: Arc<Mutex<String>>,
}

impl OutputCapture {
    /// Create a new output capture.
    pub fn new() -> Self {
        Self {
            buffer: Arc::new(Mutex::new(String::new())),
        }
    }

    /// Append text to the output buffer.
    pub fn append(&self, text: &str) {
        let mut buffer = self.buffer.lock();
        buffer.push_str(text);
    }

    /// Take the captured output, clearing the buffer.
    pub fn take(&self) -> String {
        let mut buffer = self.buffer.lock();
        std::mem::take(&mut *buffer)
    }

    /// Clear the output buffer.
    pub fn clear(&self) {
        let mut buffer = self.buffer.lock();
        buffer.clear();
    }

    /// Get a clone of the current output without clearing.
    pub fn get(&self) -> String {
        let buffer = self.buffer.lock();
        buffer.clone()
    }

    /// Check if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        let buffer = self.buffer.lock();
        buffer.is_empty()
    }
}

impl Default for OutputCapture {
    fn default() -> Self {
        Self::new()
    }
}
