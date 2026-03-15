//! DbgEng client wrapper using direct COM interfaces.

use super::output::OutputCapture;
use crate::types::*;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Once;
use thiserror::Error;
use windows::{
    Win32::System::{
        Com::{COINIT_MULTITHREADED, CoInitializeEx},
        Diagnostics::Debug::Extensions::*,
        LibraryLoader::SetDllDirectoryW,
        Registry::{HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ, RegOpenKeyExW, RegQueryValueExW},
    },
    core::{Interface, PCWSTR, w},
};

// Execution status constants from DbgEng (used for is_running check)
const DEBUG_STATUS_GO: u32 = 1;
const DEBUG_STATUS_GO_HANDLED: u32 = 2;
const DEBUG_STATUS_GO_NOT_HANDLED: u32 = 3;
const DEBUG_STATUS_STEP_OVER: u32 = 4;
const DEBUG_STATUS_STEP_INTO: u32 = 5;
const DEBUG_STATUS_BREAK: u32 = 6;
const DEBUG_STATUS_NO_DEBUGGEE: u32 = 7;
const DEBUG_STATUS_STEP_BRANCH: u32 = 8;
const DEBUG_STATUS_REVERSE_GO: u32 = 11;
const DEBUG_STATUS_REVERSE_STEP_BRANCH: u32 = 12;
const DEBUG_STATUS_REVERSE_STEP_OVER: u32 = 13;
const DEBUG_STATUS_REVERSE_STEP_INTO: u32 = 14;

// Exception codes
const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC0000005;
const EXCEPTION_BREAKPOINT: u32 = 0x80000003;
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
const EXCEPTION_STACK_OVERFLOW: u32 = 0xC00000FD;
const EXCEPTION_INT_DIVIDE_BY_ZERO: u32 = 0xC0000094;
const EXCEPTION_INT_OVERFLOW: u32 = 0xC0000095;
const EXCEPTION_PRIV_INSTRUCTION: u32 = 0xC0000096;
const EXCEPTION_ILLEGAL_INSTRUCTION: u32 = 0xC000001D;
const EXCEPTION_ARRAY_BOUNDS_EXCEEDED: u32 = 0xC000008C;
const EXCEPTION_FLT_DENORMAL_OPERAND: u32 = 0xC000008D;
const EXCEPTION_FLT_DIVIDE_BY_ZERO: u32 = 0xC000008E;
const STATUS_HEAP_CORRUPTION: u32 = 0xC0000374;
const STATUS_STACK_BUFFER_OVERRUN: u32 = 0xC0000409;

/// Static initialization for DLL preloading.
static INIT_DLL_PATH: Once = Once::new();

/// Preloads the correct dbgeng.dll from Debugging Tools installation.
///
/// This is necessary because Windows has a built-in dbgeng.dll that lacks full functionality
/// (e.g., remote debugging support). We need to explicitly load the one from Windows SDK
/// or Debugging Tools installation BEFORE any dbgeng functions are called.
///
/// Uses LoadLibraryExW with LOAD_WITH_ALTERED_SEARCH_PATH to ensure we load from the
/// specified path and not from System32.
fn setup_dbgeng_dll_path() {
    use windows::Win32::System::LibraryLoader::{
        GetModuleHandleW, LOAD_WITH_ALTERED_SEARCH_PATH, LoadLibraryExW,
    };

    INIT_DLL_PATH.call_once(|| {
        // Check if dbgeng.dll is already loaded
        unsafe {
            let already_loaded = GetModuleHandleW(w!("dbgeng.dll"));
            if already_loaded.is_ok() {
                tracing::warn!("dbgeng.dll is ALREADY loaded before our setup!");
            } else {
                tracing::debug!("dbgeng.dll is NOT yet loaded - good");
            }
        }

        if let Some(debugger_path) = find_debugger_path() {
            tracing::info!("Found debugger path: {}", debugger_path.display());

            // Set the DLL directory first for dependent DLLs
            let dir_path = to_wide_string(&debugger_path.to_string_lossy());
            unsafe {
                let result = SetDllDirectoryW(PCWSTR(dir_path.as_ptr()));
                tracing::debug!("SetDllDirectoryW result: {:?}", result);
            }

            // Preload dbgeng.dll and its dependencies with full path
            // LOAD_WITH_ALTERED_SEARCH_PATH ensures dependencies are loaded from same directory
            let dlls_to_load = ["dbghelp.dll", "dbgcore.dll", "dbgeng.dll"];

            for dll_name in &dlls_to_load {
                let dll_path = debugger_path.join(dll_name);
                tracing::debug!(
                    "Checking {}: exists={}",
                    dll_path.display(),
                    dll_path.exists()
                );

                if dll_path.exists() {
                    let wide_path = to_wide_string(&dll_path.to_string_lossy());

                    unsafe {
                        let handle = LoadLibraryExW(
                            PCWSTR(wide_path.as_ptr()),
                            None,
                            LOAD_WITH_ALTERED_SEARCH_PATH,
                        );
                        match &handle {
                            Ok(h) => tracing::info!("Loaded {}: handle={:?}", dll_name, h),
                            Err(e) => tracing::error!("FAILED to load {}: {}", dll_name, e),
                        }
                    }
                }
            }

            // Verify which dbgeng.dll is now loaded
            unsafe {
                let loaded = GetModuleHandleW(w!("dbgeng.dll"));
                tracing::debug!("After preload, dbgeng.dll handle: {:?}", loaded);
            }
        } else {
            tracing::warn!(
                "Could not find Debugging Tools installation. \
                 Remote connections may fail with ERROR_SERVER_DISABLED."
            );
        }
    });
}

/// Find the Debugging Tools installation path.
fn find_debugger_path() -> Option<PathBuf> {
    // Try registry first - Windows SDK installation
    if let Some(path) = find_debugger_from_registry() {
        return Some(path);
    }

    // Try common installation paths
    let common_paths = [
        // Windows SDK x64
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64",
        // Windows SDK x86
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86",
        // Standalone Debugging Tools x64
        r"C:\Program Files\Debugging Tools for Windows (x64)",
        // Standalone Debugging Tools x86
        r"C:\Program Files (x86)\Debugging Tools for Windows (x86)",
        // Alternative SDK location
        r"C:\Program Files\Windows Kits\10\Debuggers\x64",
    ];

    for path_str in &common_paths {
        let path = PathBuf::from(path_str);
        if path.join("dbgeng.dll").exists() {
            return Some(path);
        }
    }

    // Try to find WinDbgX in WindowsApps (Store app)
    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        let windbg_preview = PathBuf::from(local_app_data)
            .parent()
            .map(|p| p.join("Local"))
            .unwrap_or_default()
            .parent()
            .map(|p| p.join("Microsoft").join("WindowsApps"))
            .unwrap_or_default();

        if windbg_preview.exists() {
            // Look for WinDbg Preview folder
            if let Ok(entries) = std::fs::read_dir(&windbg_preview) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with("Microsoft.WinDbg_") {
                        let dbgeng_path = entry.path().join("dbgeng.dll");
                        if dbgeng_path.exists() {
                            return Some(entry.path());
                        }
                    }
                }
            }
        }
    }

    None
}

/// Try to find debugger path from Windows registry.
fn find_debugger_from_registry() -> Option<PathBuf> {
    use windows::Win32::System::Registry::REG_VALUE_TYPE;

    unsafe {
        let mut key = std::mem::zeroed();
        let subkey = w!("SOFTWARE\\Microsoft\\Windows Kits\\Installed Roots");

        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, Some(0), KEY_READ, &mut key).is_err() {
            return None;
        }

        // Query WindowsDebuggersRoot10
        let value_name = w!("WindowsDebuggersRoot10");
        let mut data_type = REG_VALUE_TYPE::default();
        let mut data_size = 0u32;

        // First call to get size
        let _ = RegQueryValueExW(
            key,
            value_name,
            None,
            Some(&mut data_type),
            None,
            Some(&mut data_size),
        );

        if data_size == 0 || data_type != REG_SZ {
            return None;
        }

        let mut buffer = vec![0u16; (data_size / 2) as usize];
        if RegQueryValueExW(
            key,
            value_name,
            None,
            Some(&mut data_type),
            Some(buffer.as_mut_ptr() as *mut u8),
            Some(&mut data_size),
        )
        .is_ok()
        {
            // Remove null terminator
            while buffer.last() == Some(&0) {
                buffer.pop();
            }

            let root_path = String::from_utf16_lossy(&buffer);

            // Append x64 or x86 based on target architecture
            #[cfg(target_pointer_width = "64")]
            let arch_path = PathBuf::from(&root_path).join("x64");
            #[cfg(target_pointer_width = "32")]
            let arch_path = PathBuf::from(&root_path).join("x86");

            if arch_path.join("dbgeng.dll").exists() {
                return Some(arch_path);
            }
        }

        None
    }
}

/// Convert a string to wide (UTF-16) string for Windows APIs.
fn to_wide_string(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Errors that can occur during debug operations.
#[derive(Debug, Error)]
pub enum DebugError {
    #[error("Failed to create debug client: {0}")]
    ClientCreation(String),

    #[error("Failed to open dump file: {0}")]
    OpenDump(String),

    #[error("Failed to attach to process: {0}")]
    AttachProcess(String),

    #[error("Failed to connect to remote: {0}")]
    ConnectRemote(String),

    #[error("Failed to execute command: {0}")]
    ExecuteCommand(String),

    #[error("Failed to read memory: {0}")]
    ReadMemory(String),

    #[error("Failed to write memory: {0}")]
    WriteMemory(String),

    #[error("Failed to get registers: {0}")]
    GetRegisters(String),

    #[error("Failed to get stack trace: {0}")]
    GetStackTrace(String),

    #[error("Failed to get modules: {0}")]
    GetModules(String),

    #[error("Failed to resolve symbol: {0}")]
    ResolveSymbol(String),

    #[error("Failed to disassemble: {0}")]
    Disassemble(String),

    #[error("Failed to get threads: {0}")]
    GetThreads(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("DbgEng error: {0}")]
    DbgEng(String),

    #[error("Windows error: {0}")]
    Windows(#[from] windows::core::Error),

    #[error("Not implemented: {0}")]
    NotImplemented(String),
}

/// Result type for debug operations.
pub type DebugResult<T> = Result<T, DebugError>;

/// Debug client wrapping DbgEng COM interfaces.
pub struct DebugClient {
    client: IDebugClient5,
    control: IDebugControl4,
    data_spaces: IDebugDataSpaces4,
    symbols: IDebugSymbols3,
    registers: IDebugRegisters2,
    system_objects: IDebugSystemObjects4,
    advanced: IDebugAdvanced3,
    output: OutputCapture,
}

impl DebugClient {
    /// Create a new debug client.
    pub fn new() -> DebugResult<Self> {
        // Ensure we use the correct dbgeng.dll from Debugging Tools
        setup_dbgeng_dll_path();

        unsafe {
            // Initialize COM
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);

            // Create the debug client using DebugCreate (windows 0.62+ API)
            let client: IDebugClient5 =
                DebugCreate().map_err(|e| DebugError::ClientCreation(e.to_string()))?;

            Self::from_client(client)
        }
    }

    /// Connect to a remote debugging server.
    ///
    /// Connection string examples:
    /// - `tcp:server=localhost,port=5005`
    /// - `npipe:pipe=windbg_session`
    /// - `tcp:port=5005` (for server mode)
    pub fn connect_remote(connection_string: &str) -> DebugResult<Self> {
        use std::ffi::CString;
        use windows_core::PCSTR;

        // Ensure we use the correct dbgeng.dll from Debugging Tools
        setup_dbgeng_dll_path();

        unsafe {
            // Initialize COM
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);

            // Convert connection string to C string
            let conn_cstr = CString::new(connection_string).map_err(|e| {
                DebugError::ConnectRemote(format!("Invalid connection string: {}", e))
            })?;

            // Connect to remote debugging server
            let mut client_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
            DebugConnect(
                PCSTR(conn_cstr.as_ptr() as *const u8),
                &IDebugClient5::IID,
                &mut client_ptr,
            )
            .map_err(|e| DebugError::ConnectRemote(format!("Failed to connect: {}", e)))?;

            // Convert raw pointer to interface
            let client: IDebugClient5 = std::mem::transmute(client_ptr);

            Self::from_client(client)
        }
    }

    /// Create DebugClient from an existing IDebugClient5 interface.
    fn from_client(client: IDebugClient5) -> DebugResult<Self> {
        // Query for other interfaces
        let control: IDebugControl4 = client.cast().map_err(|e| {
            DebugError::ClientCreation(format!("Failed to get IDebugControl4: {}", e))
        })?;

        let data_spaces: IDebugDataSpaces4 = client.cast().map_err(|e| {
            DebugError::ClientCreation(format!("Failed to get IDebugDataSpaces4: {}", e))
        })?;

        let symbols: IDebugSymbols3 = client.cast().map_err(|e| {
            DebugError::ClientCreation(format!("Failed to get IDebugSymbols3: {}", e))
        })?;

        let registers: IDebugRegisters2 = client.cast().map_err(|e| {
            DebugError::ClientCreation(format!("Failed to get IDebugRegisters2: {}", e))
        })?;

        let system_objects: IDebugSystemObjects4 = client.cast().map_err(|e| {
            DebugError::ClientCreation(format!("Failed to get IDebugSystemObjects4: {}", e))
        })?;

        let advanced: IDebugAdvanced3 = client.cast().map_err(|e| {
            DebugError::ClientCreation(format!("Failed to get IDebugAdvanced3: {}", e))
        })?;

        // Create and install output capture callbacks
        let mut output = OutputCapture::new();
        output.install(&client).map_err(|e| {
            DebugError::ClientCreation(format!("Failed to install output callbacks: {}", e))
        })?;

        Ok(Self {
            client,
            control,
            data_spaces,
            symbols,
            registers,
            system_objects,
            advanced,
            output,
        })
    }

    /// Open a crash dump file.
    pub fn open_dump(&mut self, path: &Path) -> DebugResult<String> {
        let path_str = path.to_string_lossy();
        let wide_path = to_wide_string(&path_str);

        unsafe {
            self.client
                .OpenDumpFileWide(PCWSTR(wide_path.as_ptr()), 0)
                .map_err(|e| DebugError::OpenDump(e.to_string()))?;

            // Wait for the dump to be fully loaded
            self.wait_for_event()?;

            // Get initial info about the dump
            let output = self.execute_command("||")?;
            Ok(output)
        }
    }

    /// Attach to a live process.
    pub fn attach_process(&mut self, pid: u32, non_invasive: bool) -> DebugResult<()> {
        let flags = if non_invasive {
            DEBUG_ATTACH_NONINVASIVE
        } else {
            DEBUG_ATTACH_DEFAULT
        };

        unsafe {
            self.client
                .AttachProcess(0, pid, flags)
                .map_err(|e| DebugError::AttachProcess(e.to_string()))?;

            self.wait_for_event()?;
        }
        Ok(())
    }

    /// Detach from the current target.
    pub fn detach(&mut self) -> DebugResult<()> {
        unsafe {
            self.client
                .DetachProcesses()
                .map_err(|e| DebugError::DbgEng(e.to_string()))?;
        }
        Ok(())
    }

    /// Execute a debugger command and return the output.
    /// Automatically breaks into the debugger if the target is running.
    pub fn execute_command(&mut self, command: &str) -> DebugResult<String> {
        // Ensure we're in break state before executing commands
        // Skip for "g" command since that's meant to resume execution
        if command.trim() != "g" {
            self.ensure_break_state()?;
        }

        // Clear any previous output
        self.output.clear();

        let wide_command = to_wide_string(command);

        unsafe {
            // Execute the command - output will be captured by our IDebugOutputCallbacks
            self.control
                .ExecuteWide(
                    DEBUG_OUTCTL_THIS_CLIENT,
                    PCWSTR(wide_command.as_ptr()),
                    DEBUG_EXECUTE_DEFAULT,
                )
                .map_err(|e| DebugError::ExecuteCommand(format!("{}: {}", command, e)))?;
        }

        // Return captured output
        Ok(self.output.take())
    }

    /// Wait for a debug event.
    fn wait_for_event(&mut self) -> DebugResult<()> {
        unsafe {
            self.control
                .WaitForEvent(0, u32::MAX)
                .map_err(|e| DebugError::DbgEng(format!("Wait for event failed: {}", e)))?;
        }
        Ok(())
    }

    /// Get the call stack.
    pub fn get_stack_trace(&mut self, max_frames: u32) -> DebugResult<Vec<StackFrame>> {
        let output = self.execute_command(&format!("k {}", max_frames))?;
        Ok(parse_stack_trace(&output))
    }

    /// Get the list of threads.
    pub fn get_threads(&mut self) -> DebugResult<Vec<ThreadInfo>> {
        let output = self.execute_command("~*")?;
        Ok(parse_thread_list(&output))
    }

    /// Switch to a different thread.
    pub fn switch_thread(&mut self, thread_id: u32) -> DebugResult<()> {
        self.execute_command(&format!("~{}s", thread_id))?;
        Ok(())
    }

    /// Read memory from the target.
    pub fn read_memory(&mut self, address: u64, size: u32) -> DebugResult<Vec<u8>> {
        // Ensure we're in break state
        self.ensure_break_state()?;

        let mut buffer = vec![0u8; size as usize];
        let mut bytes_read = 0u32;

        unsafe {
            self.data_spaces
                .ReadVirtual(
                    address,
                    buffer.as_mut_ptr() as *mut _,
                    size,
                    Some(&mut bytes_read),
                )
                .map_err(|e| DebugError::ReadMemory(e.to_string()))?;
        }

        buffer.truncate(bytes_read as usize);
        Ok(buffer)
    }

    /// Search memory for a pattern.
    pub fn search_memory(
        &mut self,
        start: u64,
        length: u64,
        pattern: &[u8],
        max_results: u32,
    ) -> DebugResult<Vec<u64>> {
        let pattern_hex = pattern
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let command = format!("s -b {:x} L{:x} {}", start, length, pattern_hex);
        let output = self.execute_command(&command)?;

        let mut matches = Vec::new();
        for line in output.lines() {
            if let Some(addr_str) = line.split_whitespace().next()
                && let Some(addr) = parse_address(addr_str)
            {
                matches.push(addr);
                if matches.len() >= max_results as usize {
                    break;
                }
            }
        }

        Ok(matches)
    }

    /// Write memory to the target.
    pub fn write_memory(&mut self, address: u64, data: &[u8]) -> DebugResult<u32> {
        // Ensure we're in break state
        self.ensure_break_state()?;

        let mut bytes_written = 0u32;

        unsafe {
            self.data_spaces
                .WriteVirtual(
                    address,
                    data.as_ptr() as *const _,
                    data.len() as u32,
                    Some(&mut bytes_written),
                )
                .map_err(|e| DebugError::WriteMemory(e.to_string()))?;
        }

        Ok(bytes_written)
    }

    /// Resolve a symbol to an address or vice versa.
    pub fn resolve_symbol(&mut self, symbol: &str) -> DebugResult<ResolveSymbolResponse> {
        // Try to parse as address first
        if let Some(addr) = parse_address(symbol) {
            // Address to symbol
            let output = self.execute_command(&format!("ln {:x}", addr))?;
            let (name, module) = parse_symbol_output(&output);
            Ok(ResolveSymbolResponse {
                name,
                address: format!("0x{:x}", addr),
                module,
                symbol_type: None,
            })
        } else {
            // Symbol to address
            let output = self.execute_command(&format!("x {}", symbol))?;
            if let Some((addr, name, module)) = parse_symbol_address(&output) {
                Ok(ResolveSymbolResponse {
                    name: Some(name),
                    address: format!("0x{:x}", addr),
                    module: Some(module),
                    symbol_type: None,
                })
            } else {
                Err(DebugError::ResolveSymbol(format!(
                    "Symbol not found: {}",
                    symbol
                )))
            }
        }
    }

    /// Get the list of loaded modules.
    pub fn get_modules(&mut self) -> DebugResult<Vec<ModuleInfo>> {
        let output = self.execute_command("lm")?;
        Ok(parse_module_list(&output))
    }

    /// Get type information.
    pub fn get_type_info(
        &mut self,
        module: &str,
        type_name: &str,
    ) -> DebugResult<GetTypeInfoResponse> {
        let output = self.execute_command(&format!("dt {}!{}", module, type_name))?;
        parse_type_info(&output, type_name)
    }

    /// Get register values.
    pub fn get_registers(&mut self, specific: &[String]) -> DebugResult<Vec<RegisterValue>> {
        let command = if specific.is_empty() {
            "r".to_string()
        } else {
            format!("r {}", specific.join(","))
        };
        let output = self.execute_command(&command)?;
        Ok(parse_registers(&output))
    }

    /// Disassemble instructions at an address.
    pub fn disassemble(&mut self, address: &str, count: u32) -> DebugResult<Vec<DisassemblyLine>> {
        let command = format!("u {} L{}", address, count);
        let output = self.execute_command(&command)?;
        Ok(parse_disassembly(&output))
    }

    /// Run !analyze -v and parse the output.
    pub fn analyze(&mut self, verbose: bool) -> DebugResult<AnalyzeResponse> {
        let command = if verbose { "!analyze -v" } else { "!analyze" };
        let output = self.execute_command(command)?;
        Ok(parse_analyze_output(&output))
    }

    /// Set a breakpoint.
    pub fn set_breakpoint(&mut self, address: &str, condition: Option<&str>) -> DebugResult<u32> {
        let command = if let Some(cond) = condition {
            format!("bp {} \"{}\"", address, cond)
        } else {
            format!("bp {}", address)
        };
        self.execute_command(&command)?;

        // Get the breakpoint ID from the list
        let output = self.execute_command("bl")?;
        Ok(parse_latest_breakpoint_id(&output).unwrap_or(0))
    }

    /// Remove a breakpoint.
    pub fn remove_breakpoint(&mut self, id: u32) -> DebugResult<()> {
        self.execute_command(&format!("bc {}", id))?;
        Ok(())
    }

    /// Continue execution.
    pub fn go(&mut self) -> DebugResult<()> {
        self.execute_command("g")?;
        Ok(())
    }

    /// Single step.
    pub fn step(&mut self, step_type: StepType) -> DebugResult<String> {
        let command = match step_type {
            StepType::Into => "t",
            StepType::Over => "p",
            StepType::Out => "gu",
        };
        self.execute_command(command)?;

        // Get current instruction pointer
        let output = self.execute_command("r rip")?;
        Ok(output)
    }

    /// Break into the debugger.
    pub fn break_execution(&mut self) -> DebugResult<()> {
        unsafe {
            self.control
                .SetInterrupt(DEBUG_INTERRUPT_ACTIVE)
                .map_err(|e| DebugError::DbgEng(e.to_string()))?;
        }
        Ok(())
    }

    /// Get the current execution status.
    pub fn get_execution_status(&self) -> DebugResult<u32> {
        unsafe {
            self.control
                .GetExecutionStatus()
                .map_err(|e| DebugError::DbgEng(format!("Failed to get execution status: {}", e)))
        }
    }

    /// Check if the debugger is currently in a running state.
    pub fn is_running(&self) -> bool {
        match self.get_execution_status() {
            Ok(status) => matches!(
                status,
                DEBUG_STATUS_GO
                    | DEBUG_STATUS_GO_HANDLED
                    | DEBUG_STATUS_GO_NOT_HANDLED
                    | DEBUG_STATUS_STEP_OVER
                    | DEBUG_STATUS_STEP_INTO
                    | DEBUG_STATUS_STEP_BRANCH
                    | DEBUG_STATUS_REVERSE_GO
                    | DEBUG_STATUS_REVERSE_STEP_BRANCH
                    | DEBUG_STATUS_REVERSE_STEP_OVER
                    | DEBUG_STATUS_REVERSE_STEP_INTO
            ),
            Err(_) => false,
        }
    }

    /// Ensure the debugger is in break state before executing commands.
    /// If the target is running, breaks into it and waits.
    /// Returns Ok(true) if we had to break, Ok(false) if already broken.
    pub fn ensure_break_state(&mut self) -> DebugResult<bool> {
        if self.is_running() {
            tracing::info!("Target is running, breaking into debugger...");
            self.break_execution()?;
            // Wait for break to take effect (short timeout)
            let _ = self.wait_for_event_with_timeout(5000);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Wait for a debug event with timeout.
    ///
    /// Returns Ok(true) if an event occurred, Ok(false) if timed out.
    pub fn wait_for_event_with_timeout(&mut self, timeout_ms: u32) -> DebugResult<bool> {
        unsafe {
            let result = self.control.WaitForEvent(0, timeout_ms);
            match result {
                Ok(()) => Ok(true),
                Err(e) => {
                    // S_FALSE (0x00000001) means timeout - not an error
                    // E_PENDING means still waiting
                    // E_UNEXPECTED can mean no target or timeout
                    let code = e.code().0 as u32;
                    if code == 1 || code == 0x8000000A || e.code().is_ok() {
                        // Timeout or pending - target still running
                        Ok(false)
                    } else {
                        Err(DebugError::DbgEng(format!(
                            "Wait for event failed: {} (0x{:08x})",
                            e,
                            e.code().0
                        )))
                    }
                }
            }
        }
    }

    /// Continue execution and wait for an event with timeout.
    ///
    /// This is the main method for blocking execution control.
    /// If a timeout occurs, automatically breaks into the debugger so subsequent
    /// commands can be executed.
    pub fn go_and_wait(&mut self, timeout_ms: u32) -> DebugResult<GoAndWaitResponse> {
        // First, continue execution
        self.execute_command("g")?;

        // Wait for an event
        let event_occurred = self.wait_for_event_with_timeout(timeout_ms)?;

        if !event_occurred {
            // Timeout - target is still running, break into it
            tracing::info!(
                "go_and_wait: timeout after {}ms, breaking into debugger",
                timeout_ms
            );
            self.break_execution()?;

            // Wait for the break to take effect
            let _ = self.wait_for_event_with_timeout(5000);

            // Get current state after break
            let ip = self.execute_command("r rip").ok();
            let instruction_pointer = ip
                .as_ref()
                .and_then(|s| s.split('=').nth(1).map(|v| v.trim().to_string()));
            let thread_id = self.get_current_thread_id().ok();

            return Ok(GoAndWaitResponse {
                is_running: false,
                stop_reason: Some(StopReason::Timeout),
                instruction_pointer,
                thread_id,
                breakpoint_id: None,
                exception: None,
                exit_code: None,
                message: format!(
                    "Timeout after {}ms - execution was stopped. No breakpoint or event occurred.",
                    timeout_ms
                ),
            });
        }

        // Event occurred - gather information about what happened
        self.build_stop_response()
    }

    /// Build a response describing why execution stopped.
    fn build_stop_response(&mut self) -> DebugResult<GoAndWaitResponse> {
        // Get execution status to determine stop reason
        let status = self.get_execution_status().unwrap_or(DEBUG_STATUS_BREAK);

        // Get current instruction pointer
        let ip = self.execute_command("r rip").ok();
        let instruction_pointer = ip
            .as_ref()
            .and_then(|s| s.split('=').nth(1).map(|v| v.trim().to_string()));

        // Get current thread ID
        let thread_id = self.get_current_thread_id().ok();

        // Parse current IP as address for breakpoint matching
        let current_ip = instruction_pointer.as_ref().and_then(|s| parse_address(s));

        // Check if we stopped at a breakpoint by comparing current IP to breakpoint addresses
        let bp_list = self.get_breakpoints().unwrap_or_default();
        let hit_breakpoint = current_ip.and_then(|ip| {
            bp_list.iter().find(|bp| {
                // Parse the breakpoint address and compare
                bp.resolved_address
                    .as_ref()
                    .or(Some(&bp.address))
                    .and_then(|addr| parse_address(addr))
                    .is_some_and(|bp_addr| bp_addr == ip)
            })
        });

        // Check for exception
        let exception_info = self.get_exception_info().ok();
        let has_exception = exception_info.as_ref().is_some_and(|e| e.has_exception);
        let exc = exception_info.and_then(|e| e.exception);

        // Determine stop reason
        let (stop_reason, exception, breakpoint_id, exit_code, message) =
            if let Some(bp) = hit_breakpoint {
                // We're at a breakpoint address
                let symbol_info = bp
                    .symbol
                    .as_ref()
                    .map(|s| format!(" ({})", s))
                    .unwrap_or_default();
                (
                    StopReason::Breakpoint,
                    None,
                    Some(bp.id),
                    None,
                    format!("Breakpoint {} hit at {}{}", bp.id, bp.address, symbol_info),
                )
            } else if has_exception {
                let is_breakpoint = exc.as_ref().is_some_and(|e| e.code == EXCEPTION_BREAKPOINT);
                let is_single_step = exc
                    .as_ref()
                    .is_some_and(|e| e.code == EXCEPTION_SINGLE_STEP);

                if is_breakpoint {
                    // int 3 but not at a user breakpoint
                    (
                        StopReason::Breakpoint,
                        None,
                        None,
                        None,
                        "Breakpoint exception (int 3)".to_string(),
                    )
                } else if is_single_step {
                    (
                        StopReason::SingleStep,
                        None,
                        None,
                        None,
                        "Single step completed".to_string(),
                    )
                } else {
                    let msg = exc
                        .as_ref()
                        .map(|e| format!("Exception: {} at {}", e.name, e.address))
                        .unwrap_or_else(|| "Exception occurred".to_string());
                    (StopReason::Exception, exc, None, None, msg)
                }
            } else {
                // Check execution status for other stop reasons
                match status {
                    DEBUG_STATUS_NO_DEBUGGEE => (
                        StopReason::ProcessExit,
                        None,
                        None,
                        Some(0),
                        "Process exited".to_string(),
                    ),
                    _ => (
                        StopReason::Unknown,
                        None,
                        None,
                        None,
                        "Execution stopped".to_string(),
                    ),
                }
            };

        Ok(GoAndWaitResponse {
            is_running: false,
            stop_reason: Some(stop_reason),
            instruction_pointer,
            thread_id,
            breakpoint_id,
            exception,
            exit_code,
            message,
        })
    }

    /// Get exception information.
    pub fn get_exception_info_raw(&mut self) -> DebugResult<String> {
        self.execute_command(".exr -1")
    }

    /// Get structured exception information.
    pub fn get_exception_info(&mut self) -> DebugResult<GetExceptionInfoResponse> {
        let output = self.execute_command(".exr -1")?;
        let exception = parse_exception_record(&output);

        Ok(GetExceptionInfoResponse {
            has_exception: exception.is_some(),
            exception,
            raw_output: output,
        })
    }

    /// Get list of breakpoints using the debugger interface.
    pub fn get_breakpoints(&mut self) -> DebugResult<Vec<BreakpointInfo>> {
        let output = self.execute_command("bl")?;
        Ok(parse_breakpoint_list(&output))
    }

    /// Set a data breakpoint (hardware watchpoint).
    pub fn set_data_breakpoint(
        &mut self,
        address: &str,
        size: u32,
        access: DataBreakpointAccess,
    ) -> DebugResult<u32> {
        let access_char = match access {
            DataBreakpointAccess::Read => "r",
            DataBreakpointAccess::Write => "w",
            DataBreakpointAccess::ReadWrite => "rw",
            DataBreakpointAccess::Execute => "e",
        };
        let command = format!("ba {} {} {}", access_char, size, address);
        self.execute_command(&command)?;

        let output = self.execute_command("bl")?;
        Ok(parse_latest_breakpoint_id(&output).unwrap_or(0))
    }

    /// Get extended register information using IDebugRegisters2.
    pub fn get_extended_registers(
        &mut self,
        include_vector: bool,
        include_float: bool,
        include_debug: bool,
    ) -> DebugResult<GetExtendedRegistersResponse> {
        let mut general = Vec::new();
        let mut vector = Vec::new();
        let mut float = Vec::new();
        let mut debug_regs = Vec::new();
        let mut segment = Vec::new();
        let mut flags_reg = None;

        unsafe {
            let num_registers = self
                .registers
                .GetNumberRegisters()
                .map_err(|e| DebugError::GetRegisters(e.to_string()))?;

            for i in 0..num_registers {
                let mut name_buf = [0u16; 64];
                let mut desc = DEBUG_REGISTER_DESCRIPTION::default();

                let mut name_size = 0u32;
                if self
                    .registers
                    .GetDescriptionWide(
                        i,
                        Some(&mut name_buf[..]),
                        Some(&mut name_size),
                        Some(&mut desc),
                    )
                    .is_ok()
                {
                    let name = String::from_utf16_lossy(
                        &name_buf[..name_buf.iter().position(|&c| c == 0).unwrap_or(0)],
                    );

                    let mut value = DEBUG_VALUE::default();
                    if self.registers.GetValue(i, &mut value).is_ok() {
                        let (value_str, reg_type) = format_register_value(&value, &desc, &name);

                        let reg_info = RegisterInfo {
                            name: name.clone(),
                            value: value_str,
                            register_type: reg_type,
                            size_bits: desc.Type * 8,
                            index: i,
                            parent: None,
                        };

                        match reg_type {
                            RegisterType::General | RegisterType::InstructionPointer => {
                                general.push(reg_info)
                            }
                            RegisterType::Flags => {
                                flags_reg =
                                    Some(parse_flags_register(value.Anonymous.Anonymous.I64));
                            }
                            RegisterType::Vector if include_vector => vector.push(reg_info),
                            RegisterType::Float if include_float => float.push(reg_info),
                            RegisterType::Debug if include_debug => debug_regs.push(reg_info),
                            RegisterType::Segment => segment.push(reg_info),
                            _ => {}
                        }
                    }
                }
            }
        }

        Ok(GetExtendedRegistersResponse {
            general,
            flags: flags_reg,
            vector,
            float,
            debug: debug_regs,
            segment,
        })
    }

    /// Get current thread ID using IDebugSystemObjects4.
    pub fn get_current_thread_id(&mut self) -> DebugResult<u32> {
        unsafe {
            self.system_objects
                .GetCurrentThreadId()
                .map_err(|e| DebugError::GetThreads(e.to_string()))
        }
    }

    /// Get current process ID using IDebugSystemObjects4.
    pub fn get_current_process_id(&mut self) -> DebugResult<u32> {
        unsafe {
            self.system_objects
                .GetCurrentProcessId()
                .map_err(|e| DebugError::DbgEng(e.to_string()))
        }
    }

    /// Get number of threads using IDebugSystemObjects4.
    pub fn get_number_threads(&mut self) -> DebugResult<u32> {
        unsafe {
            self.system_objects
                .GetNumberThreads()
                .map_err(|e| DebugError::GetThreads(e.to_string()))
        }
    }

    /// Get process information.
    pub fn get_process_info(&mut self) -> DebugResult<GetProcessInfoResponse> {
        let output = self.execute_command("|")?;
        let process = parse_process_info(&output);

        let thread_count = self.get_number_threads().unwrap_or(0);

        let modules = self.get_modules()?;
        let module_count = modules.len() as u32;

        Ok(GetProcessInfoResponse {
            process,
            thread_count,
            module_count,
        })
    }

    /// Get symbol information using IDebugSymbols3.
    pub fn get_symbol_info(
        &mut self,
        pattern: &str,
        max_results: u32,
    ) -> DebugResult<Vec<SymbolInfo>> {
        let output = self.execute_command(&format!("x {}", pattern))?;
        Ok(parse_symbol_info_list(&output, max_results))
    }

    /// Get source line information for an address.
    pub fn get_source_line(&mut self, address: u64) -> DebugResult<GetSourceLineResponse> {
        unsafe {
            let mut file_buf = [0u16; 260];
            let mut line = 0u32;
            let mut displacement = 0u64;

            let result = self.symbols.GetLineByOffsetWide(
                address,
                Some(&mut line),
                Some(&mut file_buf),
                Some(&mut 0),
                Some(&mut displacement),
            );

            if result.is_ok() {
                let file = String::from_utf16_lossy(
                    &file_buf[..file_buf.iter().position(|&c| c == 0).unwrap_or(0)],
                );

                Ok(GetSourceLineResponse {
                    line: Some(LineInfo {
                        file,
                        line,
                        column: None,
                        address: format!("0x{:x}", address),
                        end_address: None,
                    }),
                    displacement: Some(displacement),
                })
            } else {
                Ok(GetSourceLineResponse {
                    line: None,
                    displacement: None,
                })
            }
        }
    }

    /// Get memory regions.
    pub fn get_memory_regions(
        &mut self,
        start: Option<u64>,
        end: Option<u64>,
    ) -> DebugResult<Vec<MemoryRegionInfo>> {
        let start_addr = start.unwrap_or(0);
        let command = if let Some(end_addr) = end {
            format!("!address {:x} {:x}", start_addr, end_addr)
        } else {
            "!address".to_string()
        };

        let output = self.execute_command(&command)?;
        Ok(parse_memory_regions(&output))
    }

    /// Get the module base address for a given address.
    pub fn get_module_by_offset(&mut self, address: u64) -> DebugResult<Option<ModuleInfo>> {
        unsafe {
            let mut base = 0u64;
            let mut index = 0u32;

            if self
                .symbols
                .GetModuleByOffset(address, 0, Some(&mut index), Some(&mut base))
                .is_ok()
            {
                let mut name_buf = [0u16; 260];
                let mut size = 0u32;

                if self
                    .symbols
                    .GetModuleNameStringWide(
                        DEBUG_MODNAME_MODULE,
                        index,
                        base,
                        Some(&mut name_buf),
                        Some(&mut size),
                    )
                    .is_ok()
                {
                    let name = String::from_utf16_lossy(
                        &name_buf[..name_buf.iter().position(|&c| c == 0).unwrap_or(0)],
                    );

                    let mut params = DEBUG_MODULE_PARAMETERS::default();
                    let bases = [base];
                    let _ =
                        self.symbols
                            .GetModuleParameters(1, Some(bases.as_ptr()), 0, &mut params);

                    return Ok(Some(ModuleInfo {
                        name,
                        base_address: format!("0x{:x}", base),
                        size: params.Size as u64,
                        image_path: None,
                        symbol_status: match params.SymbolType {
                            DEBUG_SYMTYPE_DEFERRED => "Deferred".to_string(),
                            DEBUG_SYMTYPE_PDB => "Symbols loaded".to_string(),
                            DEBUG_SYMTYPE_EXPORT => "Export symbols only".to_string(),
                            _ => "No symbols".to_string(),
                        },
                        version: None,
                    }));
                }
            }
            Ok(None)
        }
    }

    /// Get thread context for a specific thread.
    pub fn get_thread_context(&mut self, thread_id: Option<u32>) -> DebugResult<ThreadContext> {
        // Switch to thread if specified
        if let Some(tid) = thread_id {
            self.switch_thread(tid)?;
        }

        let current_tid = self.get_current_thread_id()?;
        let regs = self.get_registers(&[])?;

        let mut rip = 0u64;
        let mut rsp = 0u64;
        let mut rbp = 0u64;
        let mut flags_value = 0u64;

        for reg in &regs {
            match reg.name.to_lowercase().as_str() {
                "rip" | "eip" => rip = parse_address(&reg.value).unwrap_or(0),
                "rsp" | "esp" => rsp = parse_address(&reg.value).unwrap_or(0),
                "rbp" | "ebp" => rbp = parse_address(&reg.value).unwrap_or(0),
                "rflags" | "eflags" => flags_value = parse_address(&reg.value).unwrap_or(0),
                _ => {}
            }
        }

        // Get segment registers
        let seg_output = self.execute_command("r cs,ds,es,fs,gs,ss")?;
        let segment_registers = parse_registers(&seg_output);

        Ok(ThreadContext {
            thread_id: current_tid,
            rip,
            rsp,
            rbp,
            general_registers: regs,
            flags: Some(parse_flags_register(flags_value)),
            segment_registers,
        })
    }

    /// Get the exception thread ID using IDebugAdvanced3.
    pub fn get_exception_thread(&mut self) -> DebugResult<Option<u32>> {
        unsafe {
            let mut thread_id = 0u32;
            let mut out_size = 0u32;
            let result = self.advanced.Request(
                DEBUG_REQUEST_TARGET_EXCEPTION_THREAD,
                None,
                0,
                Some(&mut thread_id as *mut u32 as *mut _),
                std::mem::size_of::<u32>() as u32,
                Some(&mut out_size),
            );

            if result.is_ok() && out_size > 0 {
                Ok(Some(thread_id))
            } else {
                Ok(None)
            }
        }
    }

    /// Get system version information using IDebugAdvanced3.
    pub fn get_system_version_info(&mut self) -> DebugResult<String> {
        // Use the advanced interface to get detailed system info
        let output = self.execute_command("vertarget")?;
        Ok(output)
    }

    /// Read a minidump stream using IDebugAdvanced3.
    pub fn read_minidump_stream(&mut self, stream_type: u32) -> DebugResult<Vec<u8>> {
        unsafe {
            // First, query the size needed
            let mut request = DEBUG_READ_USER_MINIDUMP_STREAM {
                StreamType: stream_type,
                Flags: 0,
                Offset: 0,
                Buffer: std::ptr::null_mut(),
                BufferSize: 0,
                BufferUsed: 0,
            };

            let request_size = std::mem::size_of::<DEBUG_READ_USER_MINIDUMP_STREAM>() as u32;

            // Get the required buffer size
            let _ = self.advanced.Request(
                DEBUG_REQUEST_READ_USER_MINIDUMP_STREAM,
                Some(&request as *const _ as *const _),
                request_size,
                Some(&mut request as *mut _ as *mut _),
                request_size,
                None,
            );

            if request.BufferUsed == 0 {
                return Ok(Vec::new());
            }

            // Allocate buffer and read the stream
            let mut buffer = vec![0u8; request.BufferUsed as usize];
            request.Buffer = buffer.as_mut_ptr() as *mut _;
            request.BufferSize = buffer.len() as u32;

            let result = self.advanced.Request(
                DEBUG_REQUEST_READ_USER_MINIDUMP_STREAM,
                Some(&request as *const _ as *const _),
                request_size,
                Some(&mut request as *mut _ as *mut _),
                request_size,
                None,
            );

            if result.is_ok() {
                buffer.truncate(request.BufferUsed as usize);
                Ok(buffer)
            } else {
                Ok(Vec::new())
            }
        }
    }
}

impl Drop for DebugClient {
    fn drop(&mut self) {
        // Uninstall output callbacks before dropping
        let _ = self.output.uninstall(&self.client, None);
    }
}

// ============================================================================
// Parsing helpers
// ============================================================================

fn parse_address(s: &str) -> Option<u64> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    // Remove any backtick (used in 64-bit addresses)
    let s = s.replace('`', "");
    u64::from_str_radix(&s, 16).ok()
}

fn parse_stack_trace(output: &str) -> Vec<StackFrame> {
    let mut frames = Vec::new();
    let mut frame_number = 0;

    for line in output.lines().skip(1) {
        // Skip header line
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            let frame = StackFrame {
                frame_number,
                instruction_pointer: parts.get(1).unwrap_or(&"").to_string(),
                return_address: parts.get(2).map(|s| s.to_string()),
                stack_pointer: parts.first().map(|s| s.to_string()),
                module: None,
                function: parts.get(3..).map(|p| p.join(" ")),
                source_file: None,
                source_line: None,
                displacement: None,
            };
            frames.push(frame);
            frame_number += 1;
        }
    }

    frames
}

fn parse_thread_list(output: &str) -> Vec<ThreadInfo> {
    let mut threads = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let is_current = line.starts_with('.');
        let line = line.trim_start_matches('.');
        let line = line.trim_start_matches('#');

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2
            && let Ok(thread_id) = parts[0].trim_end_matches(':').parse::<u32>()
        {
            let system_id = parts
                .get(1)
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);

            let thread = ThreadInfo {
                thread_id,
                system_id,
                state: parts.get(2).map(|s| s.to_string()),
                current_frame: parts.get(3..).map(|p| p.join(" ")),
                is_current,
            };
            threads.push(thread);
        }
    }

    threads
}

fn parse_symbol_output(output: &str) -> (Option<String>, Option<String>) {
    // Parse output like:
    // (address)   module!function+offset
    for line in output.lines() {
        if let Some(idx) = line.find('!') {
            let module = line[..idx].split_whitespace().last();
            let rest = &line[idx + 1..];
            let name = rest.split('+').next();
            return (
                name.map(|s| s.trim().to_string()),
                module.map(|s| s.to_string()),
            );
        }
    }
    (None, None)
}

fn parse_symbol_address(output: &str) -> Option<(u64, String, String)> {
    // Parse output like:
    // address module!symbol
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2
            && let Some(addr) = parse_address(parts[0])
            && let Some(idx) = parts[1].find('!')
        {
            let module = &parts[1][..idx];
            let name = &parts[1][idx + 1..];
            return Some((addr, name.to_string(), module.to_string()));
        }
    }
    None
}

fn parse_module_list(output: &str) -> Vec<ModuleInfo> {
    let mut modules = Vec::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3
            && let (Some(start), Some(end)) = (parse_address(parts[0]), parse_address(parts[1]))
        {
            let size = end.saturating_sub(start);
            let name = parts[2].to_string();

            let symbol_status = if line.contains("(pdb symbols)") {
                "Symbols loaded".to_string()
            } else if line.contains("(export symbols)") {
                "Export symbols only".to_string()
            } else if line.contains("(deferred)") {
                "Deferred".to_string()
            } else {
                "No symbols".to_string()
            };

            modules.push(ModuleInfo {
                name,
                base_address: format!("0x{:x}", start),
                size,
                image_path: None,
                symbol_status,
                version: None,
            });
        }
    }

    modules
}

fn parse_type_info(output: &str, type_name: &str) -> DebugResult<GetTypeInfoResponse> {
    let mut fields = Vec::new();
    let mut total_size = 0u32;

    for line in output.lines() {
        // Parse lines like: +0x000 FieldName : Type
        let line = line.trim();
        if line.starts_with('+') {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() >= 3
                && let Some(offset) = parse_offset(parts[0])
            {
                let name = parts[1].trim_end_matches(':').to_string();
                let field_type = parts[2].to_string();

                fields.push(TypeFieldInfo {
                    name,
                    field_type,
                    offset,
                    size: 0, // Would need additional parsing
                });

                total_size = total_size.max(offset);
            }
        }
    }

    Ok(GetTypeInfoResponse {
        name: type_name.to_string(),
        size: total_size,
        fields,
    })
}

fn parse_offset(s: &str) -> Option<u32> {
    let s = s.trim_start_matches('+').trim_start_matches("0x");
    u32::from_str_radix(s, 16).ok()
}

fn parse_registers(output: &str) -> Vec<RegisterValue> {
    let mut registers = Vec::new();

    for line in output.lines() {
        // Parse lines like: rax=0000000000000000 rbx=...
        for part in line.split_whitespace() {
            if let Some(idx) = part.find('=') {
                let name = part[..idx].to_string();
                let value = part[idx + 1..].to_string();
                registers.push(RegisterValue { name, value });
            }
        }
    }

    registers
}

fn parse_disassembly(output: &str) -> Vec<DisassemblyLine> {
    let mut instructions = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse lines like:
        // address bytes instruction
        // or: module!function+offset:
        // address bytes instruction

        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            let address = parts[0].to_string();
            let (bytes, instruction) = if parts.len() >= 3 {
                (parts[1].to_string(), parts[2].to_string())
            } else {
                (String::new(), parts[1].to_string())
            };

            // Check for symbol prefix
            let symbol = if address.contains('!') {
                Some(address.clone())
            } else {
                None
            };

            instructions.push(DisassemblyLine {
                address,
                bytes,
                instruction,
                symbol,
            });
        }
    }

    instructions
}

fn parse_analyze_output(output: &str) -> AnalyzeResponse {
    let mut response = AnalyzeResponse {
        raw_output: output.to_string(),
        exception_code: None,
        exception_description: None,
        faulting_module: None,
        faulting_function: None,
        bugcheck_code: None,
    };

    for line in output.lines() {
        let line = line.trim();

        if line.starts_with("EXCEPTION_CODE:") || line.starts_with("ExceptionCode:") {
            response.exception_code = line.split(':').nth(1).map(|s| s.trim().to_string());
        } else if line.starts_with("EXCEPTION_CODE_STR:") {
            response.exception_description = line.split(':').nth(1).map(|s| s.trim().to_string());
        } else if line.starts_with("MODULE_NAME:") {
            response.faulting_module = line.split(':').nth(1).map(|s| s.trim().to_string());
        } else if line.starts_with("SYMBOL_NAME:") || line.starts_with("IMAGE_NAME:") {
            if response.faulting_function.is_none() {
                response.faulting_function = line.split(':').nth(1).map(|s| s.trim().to_string());
            }
        } else if line.starts_with("BUGCHECK_CODE:") || line.starts_with("BugCheck") {
            response.bugcheck_code = line.split(':').nth(1).map(|s| s.trim().to_string());
        }
    }

    response
}

fn parse_latest_breakpoint_id(output: &str) -> Option<u32> {
    // Parse breakpoint list output to find the latest ID
    let mut max_id = None;
    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if !parts.is_empty()
            && let Ok(id) = parts[0].trim_end_matches(':').parse::<u32>()
        {
            max_id = Some(max_id.map_or(id, |m: u32| m.max(id)));
        }
    }
    max_id
}

fn parse_breakpoint_list(output: &str) -> Vec<BreakpointInfo> {
    let mut breakpoints = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        // Parse lines like: "0 e 00007ff6`12345678 0001 (0001) 0:**** module!func"
        if let Ok(id) = parts[0].parse::<u32>() {
            let state = match parts.get(1) {
                Some(&"e") => BreakpointState::Enabled,
                Some(&"d") => BreakpointState::Disabled,
                _ => BreakpointState::Enabled,
            };

            let address = parts.get(2).unwrap_or(&"").to_string();

            // Determine breakpoint type from the line
            let breakpoint_type =
                if line.contains(" ba ") || line.contains("(r") || line.contains("(w") {
                    BreakpointType::Data
                } else if line.contains(" hbp ") {
                    BreakpointType::Hardware
                } else {
                    BreakpointType::Software
                };

            // Extract symbol if present
            let symbol = parts
                .iter()
                .find(|p| p.contains('!'))
                .map(|s| s.to_string());
            let module = symbol
                .as_ref()
                .and_then(|s| s.split('!').next().map(String::from));

            breakpoints.push(BreakpointInfo {
                id,
                breakpoint_type,
                state,
                address: address.clone(),
                resolved_address: Some(address),
                module,
                symbol,
                condition: None,
                hit_count: 0,
                data_access: None,
                data_size: None,
            });
        }
    }

    breakpoints
}

fn parse_exception_record(output: &str) -> Option<ExceptionRecord> {
    let mut code: Option<u32> = None;
    let mut address: Option<u64> = None;
    let mut flags = 0u32;
    let mut num_parameters = 0u32;
    let mut parameters = Vec::new();
    let mut first_chance = true;

    for line in output.lines() {
        let line = line.trim();

        if line.starts_with("ExceptionCode:") {
            if let Some(code_str) = line.split(':').nth(1) {
                let code_str = code_str.trim();
                code = parse_address(code_str).map(|v| v as u32);
            }
        } else if line.starts_with("ExceptionAddress:") {
            if let Some(addr_str) = line.split(':').nth(1) {
                address = parse_address(addr_str.trim());
            }
        } else if line.starts_with("ExceptionFlags:") {
            if let Some(flags_str) = line.split(':').nth(1) {
                flags = parse_address(flags_str.trim()).unwrap_or(0) as u32;
            }
        } else if line.starts_with("NumberParameters:") {
            if let Some(num_str) = line.split(':').nth(1) {
                num_parameters = num_str.trim().parse().unwrap_or(0);
            }
        } else if line.contains("first chance") {
            first_chance = true;
        } else if line.contains("second chance") {
            first_chance = false;
        } else if line.starts_with("Parameter[")
            && let Some(param_str) = line.split(':').nth(1)
            && let Some(param) = parse_address(param_str.trim())
        {
            parameters.push(param);
        }
    }

    code.map(|c| ExceptionRecord {
        code: c,
        code_hex: format!("0x{:08x}", c),
        name: exception_code_to_name(c),
        flags,
        address: address.map(|a| format!("0x{:x}", a)).unwrap_or_default(),
        first_chance,
        num_parameters,
        parameters,
        nested: None,
    })
}

fn exception_code_to_name(code: u32) -> String {
    match code {
        EXCEPTION_ACCESS_VIOLATION => "EXCEPTION_ACCESS_VIOLATION".to_string(),
        EXCEPTION_BREAKPOINT => "EXCEPTION_BREAKPOINT".to_string(),
        EXCEPTION_SINGLE_STEP => "EXCEPTION_SINGLE_STEP".to_string(),
        EXCEPTION_STACK_OVERFLOW => "EXCEPTION_STACK_OVERFLOW".to_string(),
        EXCEPTION_INT_DIVIDE_BY_ZERO => "EXCEPTION_INT_DIVIDE_BY_ZERO".to_string(),
        EXCEPTION_INT_OVERFLOW => "EXCEPTION_INT_OVERFLOW".to_string(),
        EXCEPTION_PRIV_INSTRUCTION => "EXCEPTION_PRIV_INSTRUCTION".to_string(),
        EXCEPTION_ILLEGAL_INSTRUCTION => "EXCEPTION_ILLEGAL_INSTRUCTION".to_string(),
        EXCEPTION_ARRAY_BOUNDS_EXCEEDED => "EXCEPTION_ARRAY_BOUNDS_EXCEEDED".to_string(),
        EXCEPTION_FLT_DENORMAL_OPERAND => "EXCEPTION_FLT_DENORMAL_OPERAND".to_string(),
        EXCEPTION_FLT_DIVIDE_BY_ZERO => "EXCEPTION_FLT_DIVIDE_BY_ZERO".to_string(),
        STATUS_HEAP_CORRUPTION => "STATUS_HEAP_CORRUPTION".to_string(),
        STATUS_STACK_BUFFER_OVERRUN => "STATUS_STACK_BUFFER_OVERRUN".to_string(),
        _ => format!("UNKNOWN_EXCEPTION_0x{:08x}", code),
    }
}

fn parse_process_info(output: &str) -> ProcessInfo {
    let mut pid = 0u32;
    let mut name = String::new();
    let mut exe_path = None;

    for line in output.lines() {
        let line = line.trim();
        // Parse lines like: ".  0	id: 1234	create	name: process.exe"
        if let Some(id_pos) = line.find("id:") {
            let after_id = &line[id_pos + 3..];
            if let Some(pid_str) = after_id.split_whitespace().next() {
                pid = pid_str.trim_end_matches('.').parse().unwrap_or(0);
            }
        }

        if let Some(name_pos) = line.find("name:") {
            name = line[name_pos + 5..].trim().to_string();
        }

        if line.contains("Image path:") {
            exe_path = line.split(':').nth(1).map(|s| s.trim().to_string());
        }
    }

    ProcessInfo {
        pid,
        name,
        exe_path,
        command_line: None,
        parent_pid: None,
        creation_time: None,
        is_wow64: false,
    }
}

fn parse_symbol_info_list(output: &str, max_results: u32) -> Vec<SymbolInfo> {
    let mut symbols = Vec::new();

    for line in output.lines() {
        if symbols.len() >= max_results as usize {
            break;
        }

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse lines like: "00007ff6`12345678 module!symbol"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2
            && let Some(addr) = parse_address(parts[0])
        {
            let full_name = parts[1];
            if let Some(idx) = full_name.find('!') {
                let module = &full_name[..idx];
                let name = &full_name[idx + 1..];

                symbols.push(SymbolInfo {
                    name: name.to_string(),
                    address: format!("0x{:x}", addr),
                    module: module.to_string(),
                    symbol_type: SymbolType::Unknown,
                    size: None,
                    flags: 0,
                    type_name: None,
                });
            }
        }
    }

    symbols
}

fn parse_memory_regions(output: &str) -> Vec<MemoryRegionInfo> {
    let mut regions = Vec::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("BaseAddress") || line.starts_with("-") {
            continue;
        }

        // Parse lines from !address output
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3
            && let Some(base) = parse_address(parts[0])
        {
            let size = parts.get(1).and_then(|s| parse_address(s)).unwrap_or(0);

            let state = if line.contains("MEM_COMMIT") {
                MemoryState::Commit
            } else if line.contains("MEM_RESERVE") {
                MemoryState::Reserve
            } else {
                MemoryState::Free
            };

            let memory_type = if line.contains("MEM_IMAGE") {
                Some(MemoryType::Image)
            } else if line.contains("MEM_MAPPED") {
                Some(MemoryType::Mapped)
            } else if line.contains("MEM_PRIVATE") {
                Some(MemoryType::Private)
            } else {
                None
            };

            let protection = MemoryProtection {
                read: line.contains("PAGE_READ") || line.contains("PAGE_EXECUTE_READ"),
                write: line.contains("PAGE_READWRITE") || line.contains("PAGE_WRITECOPY"),
                execute: line.contains("PAGE_EXECUTE"),
                guard: line.contains("PAGE_GUARD"),
                no_cache: line.contains("PAGE_NOCACHE"),
            };

            regions.push(MemoryRegionInfo {
                base_address: format!("0x{:x}", base),
                size,
                state,
                protection,
                memory_type,
                module: None,
                usage: None,
            });
        }
    }

    regions
}

fn format_register_value(
    value: &DEBUG_VALUE,
    _desc: &DEBUG_REGISTER_DESCRIPTION,
    name: &str,
) -> (String, RegisterType) {
    let name_lower = name.to_lowercase();

    // Determine register type from name
    let reg_type = if name_lower == "rip" || name_lower == "eip" || name_lower == "pc" {
        RegisterType::InstructionPointer
    } else if name_lower == "rflags" || name_lower == "eflags" || name_lower == "flags" {
        RegisterType::Flags
    } else if name_lower.starts_with("xmm")
        || name_lower.starts_with("ymm")
        || name_lower.starts_with("zmm")
    {
        RegisterType::Vector
    } else if name_lower.starts_with("st") || name_lower.starts_with("mm") {
        RegisterType::Float
    } else if name_lower.starts_with("dr") {
        RegisterType::Debug
    } else if name_lower == "cs"
        || name_lower == "ds"
        || name_lower == "es"
        || name_lower == "fs"
        || name_lower == "gs"
        || name_lower == "ss"
    {
        RegisterType::Segment
    } else {
        RegisterType::General
    };

    // Format value based on type
    let value_str = unsafe {
        if name_lower.starts_with("xmm") || name_lower.starts_with("ymm") {
            // Vector registers - format as hex bytes
            format!(
                "{:016x}{:016x}",
                value.Anonymous.Anonymous.I64, value.Anonymous.Anonymous.I64
            )
        } else {
            format!("{:016x}", value.Anonymous.Anonymous.I64)
        }
    };

    (value_str, reg_type)
}

fn parse_flags_register(value: u64) -> FlagsRegister {
    FlagsRegister {
        value,
        cf: (value & 0x0001) != 0,
        pf: (value & 0x0004) != 0,
        af: (value & 0x0010) != 0,
        zf: (value & 0x0040) != 0,
        sf: (value & 0x0080) != 0,
        tf: (value & 0x0100) != 0,
        if_flag: (value & 0x0200) != 0,
        df: (value & 0x0400) != 0,
        of: (value & 0x0800) != 0,
    }
}
