//! Output capture for DbgEng commands using IDebugOutputCallbacks.

use parking_lot::Mutex;
use std::ffi::CStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use windows::Win32::System::Diagnostics::Debug::Extensions::{
    DEBUG_OUTPUT_DEBUGGEE, DEBUG_OUTPUT_DEBUGGEE_PROMPT, DEBUG_OUTPUT_ERROR,
    DEBUG_OUTPUT_EXTENSION_WARNING, DEBUG_OUTPUT_NORMAL, DEBUG_OUTPUT_PROMPT,
    DEBUG_OUTPUT_PROMPT_REGISTERS, DEBUG_OUTPUT_STATUS, DEBUG_OUTPUT_SYMBOLS, DEBUG_OUTPUT_WARNING,
    IDebugClient5, IDebugOutputCallbacks, IDebugOutputCallbacks_Impl,
};
use windows_core::{PCSTR, implement};

/// Output classification based on DbgEng output mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputType {
    Normal,
    Error,
    Warning,
    Verbose,
    Prompt,
    PromptRegisters,
    ExtensionWarning,
    Debuggee,
    DebuggeePrompt,
    Symbols,
    Status,
    Unknown(u32),
}

impl From<u32> for OutputType {
    fn from(mask: u32) -> Self {
        match mask {
            DEBUG_OUTPUT_NORMAL => OutputType::Normal,
            DEBUG_OUTPUT_ERROR => OutputType::Error,
            DEBUG_OUTPUT_WARNING => OutputType::Warning,
            DEBUG_OUTPUT_PROMPT => OutputType::Prompt,
            DEBUG_OUTPUT_PROMPT_REGISTERS => OutputType::PromptRegisters,
            DEBUG_OUTPUT_EXTENSION_WARNING => OutputType::ExtensionWarning,
            DEBUG_OUTPUT_DEBUGGEE => OutputType::Debuggee,
            DEBUG_OUTPUT_DEBUGGEE_PROMPT => OutputType::DebuggeePrompt,
            DEBUG_OUTPUT_SYMBOLS => OutputType::Symbols,
            DEBUG_OUTPUT_STATUS => OutputType::Status,
            other => OutputType::Unknown(other),
        }
    }
}

/// A segment of captured output with its type.
#[derive(Debug, Clone)]
pub struct OutputSegment {
    pub output_type: OutputType,
    pub text: String,
}

/// Thread-safe buffer for captured output.
#[derive(Debug, Default)]
struct OutputBufferInner {
    /// Combined text output (all types).
    text: String,
    /// Segmented output preserving type information.
    segments: Vec<OutputSegment>,
    /// Error output separately tracked.
    errors: String,
}

/// Shared output buffer with interior mutability.
#[derive(Clone, Default)]
pub struct OutputBuffer {
    inner: Arc<Mutex<OutputBufferInner>>,
    mask_filter: Arc<AtomicU32>,
}

impl std::fmt::Debug for OutputBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputBuffer")
            .field("inner", &"<locked>")
            .finish()
    }
}

impl OutputBuffer {
    /// Create a new output buffer.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(OutputBufferInner::default())),
            mask_filter: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Create a buffer that only captures specific output types.
    pub fn with_mask_filter(mask: u32) -> Self {
        let buf = Self::new();
        buf.mask_filter.store(mask, Ordering::SeqCst);
        buf
    }

    /// Set the output mask filter. 0 = capture all.
    pub fn set_mask_filter(&self, mask: u32) {
        self.mask_filter.store(mask, Ordering::SeqCst);
    }

    /// Check if a mask should be captured.
    fn should_capture(&self, mask: u32) -> bool {
        let filter = self.mask_filter.load(Ordering::SeqCst);
        filter == 0 || (mask & filter) != 0
    }

    /// Append text with its output type.
    pub fn append(&self, mask: u32, text: &str) {
        if !self.should_capture(mask) {
            return;
        }

        let output_type = OutputType::from(mask);
        let mut inner = self.inner.lock();

        inner.text.push_str(text);
        inner.segments.push(OutputSegment {
            output_type,
            text: text.to_string(),
        });

        if matches!(
            output_type,
            OutputType::Error | OutputType::Warning | OutputType::ExtensionWarning
        ) {
            inner.errors.push_str(text);
        }
    }

    /// Take all captured text, clearing the buffer.
    pub fn take(&self) -> String {
        let mut inner = self.inner.lock();
        inner.segments.clear();
        inner.errors.clear();
        std::mem::take(&mut inner.text)
    }

    /// Take segmented output, clearing the buffer.
    pub fn take_segments(&self) -> Vec<OutputSegment> {
        let mut inner = self.inner.lock();
        inner.text.clear();
        inner.errors.clear();
        std::mem::take(&mut inner.segments)
    }

    /// Take only error output, clearing error buffer.
    pub fn take_errors(&self) -> String {
        let mut inner = self.inner.lock();
        std::mem::take(&mut inner.errors)
    }

    /// Get text without clearing.
    pub fn get(&self) -> String {
        self.inner.lock().text.clone()
    }

    /// Get errors without clearing.
    pub fn get_errors(&self) -> String {
        self.inner.lock().errors.clone()
    }

    /// Clear all buffers.
    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.text.clear();
        inner.segments.clear();
        inner.errors.clear();
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().text.is_empty()
    }

    /// Check if there are errors.
    pub fn has_errors(&self) -> bool {
        !self.inner.lock().errors.is_empty()
    }
}

/// IDebugOutputCallbacks implementation that captures output to a shared buffer.
#[implement(IDebugOutputCallbacks)]
pub struct DebugOutputCallbacks {
    buffer: OutputBuffer,
}

impl DebugOutputCallbacks {
    /// Create new callbacks with a shared buffer.
    pub fn new(buffer: OutputBuffer) -> Self {
        Self { buffer }
    }
}

impl IDebugOutputCallbacks_Impl for DebugOutputCallbacks_Impl {
    fn Output(&self, mask: u32, text: &PCSTR) -> windows_core::Result<()> {
        // Safety: text is provided by DbgEng and should be valid for the duration of this call
        let text_str = if text.is_null() {
            String::new()
        } else {
            // PCSTR.as_ptr() returns *const u8, but CStr expects *const i8
            unsafe { CStr::from_ptr(text.as_ptr() as *const i8) }
                .to_string_lossy()
                .into_owned()
        };

        if !text_str.is_empty() {
            self.buffer.append(mask, &text_str);
        }

        Ok(())
    }
}

/// High-level output capture manager for a debug client.
pub struct OutputCapture {
    buffer: OutputBuffer,
    callbacks: IDebugOutputCallbacks,
    installed: bool,
}

impl OutputCapture {
    /// Create a new output capture instance.
    pub fn new() -> Self {
        let buffer = OutputBuffer::new();
        let callbacks_impl = DebugOutputCallbacks::new(buffer.clone());
        let callbacks: IDebugOutputCallbacks = callbacks_impl.into();

        Self {
            buffer,
            callbacks,
            installed: false,
        }
    }

    /// Create with a specific mask filter.
    pub fn with_mask_filter(mask: u32) -> Self {
        let buffer = OutputBuffer::with_mask_filter(mask);
        let callbacks_impl = DebugOutputCallbacks::new(buffer.clone());
        let callbacks: IDebugOutputCallbacks = callbacks_impl.into();

        Self {
            buffer,
            callbacks,
            installed: false,
        }
    }

    /// Install callbacks on a debug client. Returns previous callbacks if any.
    pub fn install(
        &mut self,
        client: &IDebugClient5,
    ) -> windows::core::Result<Option<IDebugOutputCallbacks>> {
        let previous = unsafe { client.GetOutputCallbacks().ok() };
        unsafe { client.SetOutputCallbacks(&self.callbacks)? };
        self.installed = true;
        Ok(previous)
    }

    /// Uninstall callbacks, optionally restoring previous callbacks.
    pub fn uninstall(
        &mut self,
        client: &IDebugClient5,
        restore: Option<&IDebugOutputCallbacks>,
    ) -> windows::core::Result<()> {
        if self.installed {
            unsafe { client.SetOutputCallbacks(restore)? };
            self.installed = false;
        }
        Ok(())
    }

    /// Check if callbacks are installed.
    pub fn is_installed(&self) -> bool {
        self.installed
    }

    /// Get the underlying buffer.
    pub fn buffer(&self) -> &OutputBuffer {
        &self.buffer
    }

    /// Clear captured output.
    pub fn clear(&self) {
        self.buffer.clear();
    }

    /// Take all captured output.
    pub fn take(&self) -> String {
        self.buffer.take()
    }

    /// Take segmented output.
    pub fn take_segments(&self) -> Vec<OutputSegment> {
        self.buffer.take_segments()
    }

    /// Get output without clearing.
    pub fn get(&self) -> String {
        self.buffer.get()
    }

    /// Check if there's any output.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Check if there are errors in the output.
    pub fn has_errors(&self) -> bool {
        self.buffer.has_errors()
    }

    /// Get only error output.
    pub fn get_errors(&self) -> String {
        self.buffer.get_errors()
    }
}

impl Default for OutputCapture {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for OutputCapture {
    fn drop(&mut self) {
        // Note: We can't uninstall here because we don't have the client reference.
        // The caller must ensure uninstall() is called before dropping if needed.
        if self.installed {
            tracing::warn!("OutputCapture dropped while still installed");
        }
    }
}
