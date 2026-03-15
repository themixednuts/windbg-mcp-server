//! Debug session management.

use super::client::{DebugClient, DebugError, DebugResult};
use crate::config::SafetyConfig;
use crate::types::*;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

/// A debug session representing an active debugging target.
pub struct DebugSession {
    /// Unique session identifier
    pub id: String,
    /// Session type (dump or live)
    pub session_type: SessionType,
    /// Target description (path or process info)
    pub target: String,
    /// The debug client for this session
    client: DebugClient,
    /// Safety configuration
    safety_config: SafetyConfig,
    /// Whether the session is active
    active: bool,
}

unsafe impl Send for DebugSession {}
unsafe impl Sync for DebugSession {}

impl DebugSession {
    /// Create a new session by opening a dump file.
    pub fn open_dump(
        path: PathBuf,
        symbol_path: Option<String>,
        safety_config: SafetyConfig,
    ) -> DebugResult<Self> {
        let mut client = DebugClient::new()?;

        // Set symbol path if provided
        if let Some(sym_path) = &symbol_path {
            client.execute_command(&format!(".sympath {}", sym_path))?;
        }

        let _summary = client.open_dump(&path)?;
        let id = Uuid::new_v4().to_string();

        Ok(Self {
            id,
            session_type: SessionType::Dump,
            target: path.to_string_lossy().to_string(),
            client,
            safety_config,
            active: true,
        })
    }

    /// Create a new session by attaching to a process.
    pub fn attach_process(
        pid: u32,
        non_invasive: bool,
        safety_config: SafetyConfig,
    ) -> DebugResult<Self> {
        safety_config
            .check_live_attach()
            .map_err(|e| DebugError::AttachProcess(e.to_string()))?;

        let mut client = DebugClient::new()?;
        client.attach_process(pid, non_invasive)?;

        let id = Uuid::new_v4().to_string();

        // Get process name
        let output = client.execute_command("|")?;
        let target = format!("Process {} - {}", pid, output.lines().next().unwrap_or(""));

        Ok(Self {
            id,
            session_type: SessionType::Live,
            target,
            client,
            safety_config,
            active: true,
        })
    }

    /// Create a new session by connecting to a remote debugging server.
    ///
    /// Connection string examples:
    /// - `tcp:server=localhost,port=5005`
    /// - `npipe:pipe=windbg_session`
    pub fn connect_remote(
        connection_string: &str,
        safety_config: SafetyConfig,
    ) -> DebugResult<Self> {
        let mut client = DebugClient::connect_remote(connection_string)?;

        let id = Uuid::new_v4().to_string();

        // Try to get target info
        let output = client.execute_command("||").unwrap_or_default();
        let target = format!(
            "Remote: {} - {}",
            connection_string,
            output.lines().next().unwrap_or("connected")
        );

        Ok(Self {
            id,
            session_type: SessionType::Remote,
            target,
            client,
            safety_config,
            active: true,
        })
    }

    /// Close the session.
    pub fn close(&mut self) -> DebugResult<()> {
        if self.active {
            self.client.detach()?;
            self.active = false;
        }
        Ok(())
    }

    /// Check if the session is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Execute a debugger command.
    pub fn execute_command(&mut self, command: &str) -> DebugResult<ExecuteCommandResponse> {
        self.safety_config
            .is_command_allowed(command)
            .map_err(|e| DebugError::ExecuteCommand(e.to_string()))?;

        let output = self.client.execute_command(command)?;
        Ok(ExecuteCommandResponse { output })
    }

    /// Run !analyze.
    pub fn analyze(&mut self, verbose: bool) -> DebugResult<AnalyzeResponse> {
        self.client.analyze(verbose)
    }

    /// Get stack trace.
    pub fn get_stack_trace(
        &mut self,
        thread_id: Option<u32>,
        max_frames: u32,
    ) -> DebugResult<GetStackTraceResponse> {
        if let Some(tid) = thread_id {
            self.client.switch_thread(tid)?;
        }

        let frames = self.client.get_stack_trace(max_frames)?;
        let current_thread = thread_id.unwrap_or(0);

        Ok(GetStackTraceResponse {
            thread_id: current_thread,
            frames,
        })
    }

    /// Get thread list.
    pub fn get_threads(&mut self) -> DebugResult<ListThreadsResponse> {
        let threads = self.client.get_threads()?;
        Ok(ListThreadsResponse { threads })
    }

    /// Switch thread.
    pub fn switch_thread(&mut self, thread_id: u32) -> DebugResult<SwitchThreadResponse> {
        self.client.switch_thread(thread_id)?;
        Ok(SwitchThreadResponse { thread_id })
    }

    /// Read memory.
    pub fn read_memory(
        &mut self,
        address: &str,
        size: u32,
        format: MemoryFormat,
    ) -> DebugResult<ReadMemoryResponse> {
        self.safety_config
            .check_memory_read_size(size as u64)
            .map_err(|e| DebugError::ReadMemory(e.to_string()))?;

        let addr = parse_address_str(address)?;
        let data = self.client.read_memory(addr, size)?;

        let content = match format {
            MemoryFormat::Hex => format_hex(&data),
            MemoryFormat::Ascii => format_ascii(&data),
            MemoryFormat::Unicode => format_unicode(&data),
            MemoryFormat::Bytes => format_bytes(&data),
        };

        let raw_hex = data
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        Ok(ReadMemoryResponse {
            address: format!("0x{:x}", addr),
            bytes_read: data.len() as u32,
            content,
            raw_hex: Some(raw_hex),
        })
    }

    /// Search memory.
    pub fn search_memory(
        &mut self,
        start: &str,
        length: u64,
        pattern: &str,
        max_results: u32,
    ) -> DebugResult<SearchMemoryResponse> {
        self.safety_config
            .check_search_range(length)
            .map_err(|e| DebugError::ReadMemory(e.to_string()))?;

        let start_addr = parse_address_str(start)?;
        let pattern_bytes = parse_hex_pattern(pattern)?;

        let matches = self
            .client
            .search_memory(start_addr, length, &pattern_bytes, max_results)?;
        let match_strings: Vec<String> = matches.iter().map(|a| format!("0x{:x}", a)).collect();

        Ok(SearchMemoryResponse {
            matches: match_strings,
            count: matches.len() as u32,
        })
    }

    /// Write memory.
    pub fn write_memory(&mut self, address: &str, data: &str) -> DebugResult<WriteMemoryResponse> {
        self.safety_config
            .check_memory_write()
            .map_err(|e| DebugError::WriteMemory(e.to_string()))?;

        let addr = parse_address_str(address)?;
        let data_bytes = parse_hex_pattern(data)?;

        let bytes_written = self.client.write_memory(addr, &data_bytes)?;

        Ok(WriteMemoryResponse { bytes_written })
    }

    /// Resolve symbol.
    pub fn resolve_symbol(&mut self, symbol: &str) -> DebugResult<ResolveSymbolResponse> {
        self.client.resolve_symbol(symbol)
    }

    /// Get modules.
    pub fn get_modules(&mut self) -> DebugResult<ListModulesResponse> {
        let modules = self.client.get_modules()?;
        Ok(ListModulesResponse { modules })
    }

    /// Get type info.
    pub fn get_type_info(
        &mut self,
        module: &str,
        type_name: &str,
    ) -> DebugResult<GetTypeInfoResponse> {
        self.client.get_type_info(module, type_name)
    }

    /// Get registers.
    pub fn get_registers(&mut self, specific: &[String]) -> DebugResult<GetRegistersResponse> {
        let registers = self.client.get_registers(specific)?;
        Ok(GetRegistersResponse { registers })
    }

    /// Disassemble.
    pub fn disassemble(&mut self, address: &str, count: u32) -> DebugResult<DisassembleResponse> {
        let instructions = self.client.disassemble(address, count)?;
        Ok(DisassembleResponse { instructions })
    }

    /// Set breakpoint.
    pub fn set_breakpoint(
        &mut self,
        address: &str,
        condition: Option<&str>,
    ) -> DebugResult<SetBreakpointResponse> {
        self.safety_config
            .check_execution_control()
            .map_err(|e| DebugError::DbgEng(e.to_string()))?;

        let bp_id = self.client.set_breakpoint(address, condition)?;

        Ok(SetBreakpointResponse {
            breakpoint_id: bp_id,
            address: address.to_string(),
        })
    }

    /// Remove breakpoint.
    pub fn remove_breakpoint(&mut self, id: u32) -> DebugResult<RemoveBreakpointResponse> {
        self.client.remove_breakpoint(id)?;
        Ok(RemoveBreakpointResponse {
            message: format!("Breakpoint {} removed", id),
        })
    }

    /// Continue execution.
    pub fn go(&mut self) -> DebugResult<ExecutionControlResponse> {
        self.safety_config
            .check_execution_control()
            .map_err(|e| DebugError::DbgEng(e.to_string()))?;

        self.client.go()?;
        Ok(ExecutionControlResponse {
            state: Some("Running".to_string()),
        })
    }

    /// Continue execution and wait for an event.
    ///
    /// This blocks until a debug event occurs (breakpoint, exception, etc.)
    /// or the timeout expires. Default timeout is 30 seconds.
    pub fn go_and_wait(&mut self, timeout_ms: u32) -> DebugResult<GoAndWaitResponse> {
        self.safety_config
            .check_execution_control()
            .map_err(|e| DebugError::DbgEng(e.to_string()))?;

        self.client.go_and_wait(timeout_ms)
    }

    /// Step execution.
    pub fn step(&mut self, step_type: StepType) -> DebugResult<StepResponse> {
        self.safety_config
            .check_execution_control()
            .map_err(|e| DebugError::DbgEng(e.to_string()))?;

        let ip = self.client.step(step_type)?;
        Ok(StepResponse {
            instruction_pointer: Some(ip),
        })
    }

    /// Break execution.
    pub fn break_execution(&mut self) -> DebugResult<ExecutionControlResponse> {
        self.safety_config
            .check_execution_control()
            .map_err(|e| DebugError::DbgEng(e.to_string()))?;

        self.client.break_execution()?;
        Ok(ExecutionControlResponse {
            state: Some("Broken".to_string()),
        })
    }

    /// Get exception info (raw output).
    pub fn get_exception_info_raw(&mut self) -> DebugResult<String> {
        self.client.get_exception_info_raw()
    }

    /// Get structured exception info.
    pub fn get_exception_info(&mut self) -> DebugResult<GetExceptionInfoResponse> {
        self.client.get_exception_info()
    }

    /// Get session info.
    pub fn get_info(&self) -> SessionInfo {
        SessionInfo {
            session_id: self.id.clone(),
            session_type: self.session_type,
            target: self.target.clone(),
            active: self.active,
        }
    }
}

/// Manages multiple debug sessions.
pub struct SessionManager {
    sessions: RwLock<HashMap<String, Arc<RwLock<DebugSession>>>>,
    safety_config: SafetyConfig,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(safety_config: SafetyConfig) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            safety_config,
        }
    }

    /// Open a dump file and create a session.
    pub fn open_dump(
        &self,
        path: PathBuf,
        symbol_path: Option<String>,
    ) -> DebugResult<SessionInfo> {
        let session = DebugSession::open_dump(path, symbol_path, self.safety_config.clone())?;
        let info = session.get_info();
        let id = session.id.clone();

        let mut sessions = self.sessions.write();
        sessions.insert(id, Arc::new(RwLock::new(session)));

        Ok(info)
    }

    /// Attach to a process and create a session.
    pub fn attach_process(&self, pid: u32, non_invasive: bool) -> DebugResult<SessionInfo> {
        let session = DebugSession::attach_process(pid, non_invasive, self.safety_config.clone())?;
        let info = session.get_info();
        let id = session.id.clone();

        let mut sessions = self.sessions.write();
        sessions.insert(id, Arc::new(RwLock::new(session)));

        Ok(info)
    }

    /// Connect to a remote debugging server and create a session.
    pub fn connect_remote(&self, connection_string: &str) -> DebugResult<SessionInfo> {
        let session = DebugSession::connect_remote(connection_string, self.safety_config.clone())?;
        let info = session.get_info();
        let id = session.id.clone();

        let mut sessions = self.sessions.write();
        sessions.insert(id, Arc::new(RwLock::new(session)));

        Ok(info)
    }

    /// Get a session by ID.
    pub fn get_session(&self, id: &str) -> Option<Arc<RwLock<DebugSession>>> {
        let sessions = self.sessions.read();
        sessions.get(id).cloned()
    }

    /// Close and remove a session.
    pub fn close_session(&self, id: &str) -> DebugResult<()> {
        let session = {
            let mut sessions = self.sessions.write();
            sessions.remove(id)
        };

        if let Some(session) = session {
            let mut session = session.write();
            session.close()?;
        }

        Ok(())
    }

    /// List all sessions.
    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.read();
        sessions.values().map(|s| s.read().get_info()).collect()
    }

    /// Execute an operation on a session.
    pub fn with_session<F, T>(&self, id: &str, f: F) -> DebugResult<T>
    where
        F: FnOnce(&mut DebugSession) -> DebugResult<T>,
    {
        let session = self
            .get_session(id)
            .ok_or_else(|| DebugError::SessionNotFound(id.to_string()))?;

        let mut session = session.write();
        f(&mut session)
    }
}

// ============================================================================
// Helper functions
// ============================================================================

fn parse_address_str(s: &str) -> DebugResult<u64> {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    let s = s.replace('`', "");
    u64::from_str_radix(&s, 16).map_err(|_| DebugError::InvalidAddress(s.to_string()))
}

fn parse_hex_pattern(s: &str) -> DebugResult<Vec<u8>> {
    let s = s.replace(' ', "");
    let mut bytes = Vec::new();

    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if i + 1 < chars.len() {
            let hex_str: String = chars[i..i + 2].iter().collect();
            let byte = u8::from_str_radix(&hex_str, 16)
                .map_err(|_| DebugError::InvalidAddress(format!("Invalid hex: {}", hex_str)))?;
            bytes.push(byte);
            i += 2;
        } else {
            return Err(DebugError::InvalidAddress(
                "Hex pattern must have even number of characters".to_string(),
            ));
        }
    }

    Ok(bytes)
}

fn format_hex(data: &[u8]) -> String {
    let mut result = String::new();
    for (i, chunk) in data.chunks(16).enumerate() {
        result.push_str(&format!("{:08x}: ", i * 16));
        for byte in chunk {
            result.push_str(&format!("{:02x} ", byte));
        }
        result.push('\n');
    }
    result
}

fn format_ascii(data: &[u8]) -> String {
    data.iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

fn format_unicode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let code = u16::from_le_bytes([data[i], data[i + 1]]);
        if let Some(c) = char::from_u32(code as u32) {
            result.push(c);
        }
        i += 2;
    }
    result
}

fn format_bytes(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}
