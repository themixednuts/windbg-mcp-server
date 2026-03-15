//! MCP server handler — tools, prompts, and server configuration.

use crate::config::SafetyConfig;
use crate::debugger::DebuggerThread;
use crate::types::*;
use rmcp::handler::server::router::prompt::PromptRouter;
use rmcp::handler::server::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    GetPromptRequestParams, GetPromptResult, ListPromptsResult, PaginatedRequestParams,
    PromptMessage, PromptMessageRole, ServerCapabilities, ServerInfo,
};
use rmcp::service::RequestContext;
use rmcp::{
    ErrorData as McpError, Json, RoleServer, ServerHandler, prompt, prompt_handler, prompt_router,
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ============================================================================
// Tool Parameter Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OpenDumpParams {
    /// Path to the crash dump file (.dmp)
    pub path: String,
    /// Optional symbol path (uses _NT_SYMBOL_PATH if not provided)
    pub symbol_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttachParams {
    /// Process ID to attach to
    pub pid: u32,
    /// Whether to attach non-invasively (default: false)
    #[serde(default)]
    pub non_invasive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConnectRemoteParams {
    /// Remote connection string (e.g., "tcp:server=localhost,port=5005" or "npipe:pipe=name")
    pub connection_string: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionIdParam {
    /// Session ID
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExecuteParams {
    /// Session ID
    pub session_id: String,
    /// Command to execute
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnalyzeParams {
    /// Session ID
    pub session_id: String,
    /// Whether to include verbose output (default: true)
    #[serde(default = "default_true")]
    pub verbose: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StackTraceParams {
    /// Session ID
    pub session_id: String,
    /// Thread ID (uses current thread if not specified)
    pub thread_id: Option<u32>,
    /// Maximum number of frames (default: 50)
    #[serde(default = "default_max_frames")]
    pub max_frames: u32,
}

fn default_max_frames() -> u32 {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SwitchThreadParams {
    /// Session ID
    pub session_id: String,
    /// Thread ID to switch to
    pub thread_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReadMemoryParams {
    /// Session ID
    pub session_id: String,
    /// Memory address (hex string or symbol)
    pub address: String,
    /// Number of bytes to read (default: 256)
    #[serde(default = "default_length")]
    pub length: u32,
    /// Output format
    #[serde(default)]
    pub format: MemoryFormat,
}

fn default_length() -> u32 {
    256
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SearchMemoryParams {
    /// Session ID
    pub session_id: String,
    /// Start address
    pub start_address: String,
    /// Search length in bytes
    pub length: u64,
    /// Pattern to search for (hex bytes, e.g., "4D 5A 90")
    pub pattern: String,
    /// Maximum number of results (default: 100)
    #[serde(default = "default_max_results")]
    pub max_results: u32,
}

fn default_max_results() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WriteMemoryParams {
    /// Session ID
    pub session_id: String,
    /// Memory address
    pub address: String,
    /// Data to write (hex bytes)
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResolveSymbolParams {
    /// Session ID
    pub session_id: String,
    /// Symbol name to resolve to address
    pub symbol: Option<String>,
    /// Address to resolve to symbol
    pub address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TypeInfoParams {
    /// Session ID
    pub session_id: String,
    /// Module name
    pub module: String,
    /// Type name
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegistersParams {
    /// Session ID
    pub session_id: String,
    /// Specific registers to retrieve (all if empty)
    #[serde(default)]
    pub registers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DisassembleParams {
    /// Session ID
    pub session_id: String,
    /// Start address or symbol
    pub address: String,
    /// Number of instructions (default: 10)
    #[serde(default = "default_count")]
    pub count: u32,
}

fn default_count() -> u32 {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BreakpointParams {
    /// Session ID
    pub session_id: String,
    /// Address or symbol for breakpoint
    pub address: String,
    /// Optional condition expression
    pub condition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RemoveBreakpointParams {
    /// Session ID
    pub session_id: String,
    /// Breakpoint ID to remove
    pub breakpoint_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StepParams {
    /// Session ID
    pub session_id: String,
    /// Step type
    #[serde(default)]
    pub step_type: StepType,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GoParams {
    /// Session ID
    pub session_id: String,
    /// Optional timeout in milliseconds to wait for an event (breakpoint, exception, etc.).
    /// If provided, the tool will block until an event occurs or the timeout expires.
    /// If not provided (or 0), execution continues without waiting (non-blocking).
    pub wait_timeout_ms: Option<u32>,
}

// ============================================================================
// JavaScript Scripting Parameter Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LoadScriptParams {
    /// Session ID
    pub session_id: String,
    /// Path to the JavaScript script file (.js)
    pub script_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct UnloadScriptParams {
    /// Session ID
    pub session_id: String,
    /// Path to the script to unload
    pub script_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RunScriptParams {
    /// Session ID
    pub session_id: String,
    /// Path to the JavaScript script file (.js)
    pub script_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct InvokeScriptParams {
    /// Session ID
    pub session_id: String,
    /// Function name to invoke (e.g., "myFunction" or "MyNamespace.myFunction")
    pub function: String,
    /// Arguments to pass to the function (as JSON-like string, e.g., "arg1, arg2")
    #[serde(default)]
    pub args: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EvalScriptParams {
    /// Session ID
    pub session_id: String,
    /// JavaScript code to evaluate using dx command
    pub code: String,
}

// ============================================================================
// Prompt Parameter Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CrashTriageParams {
    /// Path to the crash dump file (.dmp)
    pub dump_path: String,
    /// Optional symbol path
    pub symbol_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ThreadAnalysisParams {
    /// Session ID of an active debug session
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryInvestigationParams {
    /// Session ID of an active debug session
    pub session_id: String,
    /// Suspect address to start investigation (hex string or symbol)
    pub address: Option<String>,
}

// ============================================================================
// WinDbg MCP Server
// ============================================================================

/// WinDbg MCP Server.
#[derive(Clone)]
pub struct WinDbgServer {
    debugger: DebuggerThread,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
    #[allow(dead_code)]
    prompt_router: PromptRouter<Self>,
}

impl WinDbgServer {
    /// Create a new WinDbg MCP server.
    pub fn new(safety_config: SafetyConfig) -> Self {
        let (debugger, _handle) = DebuggerThread::spawn(safety_config);
        Self {
            debugger,
            tool_router: Self::tool_router(),
            prompt_router: Self::prompt_router(),
        }
    }

    /// Create a server with default safety configuration.
    pub fn with_defaults() -> Self {
        Self::new(SafetyConfig::default())
    }

    /// Create a server with permissive safety configuration.
    pub fn permissive() -> Self {
        Self::new(SafetyConfig::permissive())
    }
}

// ============================================================================
// Tools
// ============================================================================

#[tool_router]
impl WinDbgServer {
    // ==================== Session Management ====================

    /// Open a crash dump file (.dmp) for analysis. Returns a session ID to use with other tools.
    #[tool(annotations(destructive_hint = false, idempotent_hint = false, open_world_hint = false))]
    async fn open_dump(
        &self,
        Parameters(OpenDumpParams { path, symbol_path }): Parameters<OpenDumpParams>,
    ) -> Result<Json<SessionInfo>, McpError> {
        self.debugger
            .open_dump(PathBuf::from(&path), symbol_path)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error opening dump: {e}"), None))
    }

    /// Attach to a live process for debugging. Optionally attach non-invasively.
    #[tool(annotations(destructive_hint = false, idempotent_hint = false, open_world_hint = false))]
    async fn attach_process(
        &self,
        Parameters(AttachParams { pid, non_invasive }): Parameters<AttachParams>,
    ) -> Result<Json<SessionInfo>, McpError> {
        self.debugger
            .attach_process(pid, non_invasive)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error attaching to process: {e}"), None))
    }

    /// Connect to a remote WinDbg debugging server. Use this to attach to an existing WinDbg session that has started a server with .server command.
    #[tool(annotations(destructive_hint = false, idempotent_hint = false, open_world_hint = false))]
    async fn connect_remote(
        &self,
        Parameters(ConnectRemoteParams { connection_string }): Parameters<ConnectRemoteParams>,
    ) -> Result<Json<SessionInfo>, McpError> {
        self.debugger
            .connect_remote(connection_string)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error connecting to remote: {e}"), None))
    }

    /// Detach from a debug session and close it.
    #[tool(annotations(destructive_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn detach(
        &self,
        Parameters(SessionIdParam { session_id }): Parameters<SessionIdParam>,
    ) -> Result<Json<DetachResponse>, McpError> {
        self.debugger
            .detach(session_id)
            .await
            .map(|()| {
                Json(DetachResponse {
                    message: "Session detached".to_string(),
                })
            })
            .map_err(|e| McpError::internal_error(format!("Error detaching: {e}"), None))
    }

    /// List all active debug sessions.
    #[tool(annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn list_sessions(&self) -> Result<Json<ListSessionsResponse>, McpError> {
        let sessions = self.debugger.list_sessions().await;
        Ok(Json(ListSessionsResponse { sessions }))
    }

    // ==================== Command Execution ====================

    /// Execute a WinDbg command and return the output. Some dangerous commands are blocked by safety policy.
    #[tool(annotations(open_world_hint = true))]
    async fn execute(
        &self,
        Parameters(ExecuteParams {
            session_id,
            command,
        }): Parameters<ExecuteParams>,
    ) -> Result<Json<ExecuteCommandResponse>, McpError> {
        self.debugger
            .execute(session_id, command)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error executing command: {e}"), None))
    }

    /// Run !analyze -v to automatically analyze the crash dump and identify the root cause.
    #[tool(annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn analyze(
        &self,
        Parameters(AnalyzeParams {
            session_id,
            verbose,
        }): Parameters<AnalyzeParams>,
    ) -> Result<Json<ExecuteCommandResponse>, McpError> {
        let cmd = if verbose { "!analyze -v" } else { "!analyze" };
        self.debugger
            .execute(session_id, cmd.to_string())
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error analyzing: {e}"), None))
    }

    // ==================== JavaScript Scripting ====================

    /// Load a JavaScript debugging script (.js). The script remains loaded until unloaded or session ends.
    #[tool(annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = true))]
    async fn load_script(
        &self,
        Parameters(LoadScriptParams {
            session_id,
            script_path,
        }): Parameters<LoadScriptParams>,
    ) -> Result<Json<ExecuteCommandResponse>, McpError> {
        let cmd = format!(".scriptload \"{}\"", script_path.replace('\\', "\\\\"));
        self.debugger
            .execute(session_id, cmd)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error loading script: {e}"), None))
    }

    /// Unload a previously loaded JavaScript script.
    #[tool(annotations(destructive_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn unload_script(
        &self,
        Parameters(UnloadScriptParams {
            session_id,
            script_path,
        }): Parameters<UnloadScriptParams>,
    ) -> Result<Json<ExecuteCommandResponse>, McpError> {
        let cmd = format!(".scriptunload \"{}\"", script_path.replace('\\', "\\\\"));
        self.debugger
            .execute(session_id, cmd)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error unloading script: {e}"), None))
    }

    /// Load and immediately execute a JavaScript script. The script is unloaded after execution.
    #[tool(annotations(open_world_hint = true))]
    async fn run_script(
        &self,
        Parameters(RunScriptParams {
            session_id,
            script_path,
        }): Parameters<RunScriptParams>,
    ) -> Result<Json<ExecuteCommandResponse>, McpError> {
        let cmd = format!(".scriptrun \"{}\"", script_path.replace('\\', "\\\\"));
        self.debugger
            .execute(session_id, cmd)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error running script: {e}"), None))
    }

    /// Invoke a function from a loaded JavaScript script using dx command.
    #[tool(annotations(open_world_hint = true))]
    async fn invoke_script(
        &self,
        Parameters(InvokeScriptParams {
            session_id,
            function,
            args,
        }): Parameters<InvokeScriptParams>,
    ) -> Result<Json<ExecuteCommandResponse>, McpError> {
        let cmd = if args.is_empty() {
            format!("dx @$scriptContents.{function}()")
        } else {
            format!("dx @$scriptContents.{function}({args})")
        };
        self.debugger
            .execute(session_id, cmd)
            .await
            .map(Json)
            .map_err(|e| {
                McpError::internal_error(format!("Error invoking script function: {e}"), None)
            })
    }

    /// Evaluate a JavaScript expression using the dx command. Useful for querying debugger data model.
    #[tool(annotations(read_only_hint = true, open_world_hint = true))]
    async fn eval(
        &self,
        Parameters(EvalScriptParams { session_id, code }): Parameters<EvalScriptParams>,
    ) -> Result<Json<ExecuteCommandResponse>, McpError> {
        let cmd = format!("dx {code}");
        self.debugger
            .execute(session_id, cmd)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error evaluating expression: {e}"), None))
    }

    /// List all currently loaded JavaScript scripts.
    #[tool(annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn list_scripts(
        &self,
        Parameters(SessionIdParam { session_id }): Parameters<SessionIdParam>,
    ) -> Result<Json<ExecuteCommandResponse>, McpError> {
        self.debugger
            .execute(session_id, ".scriptlist".to_string())
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error listing scripts: {e}"), None))
    }

    // ==================== Stack & Threads ====================

    /// Get the call stack for a thread. Shows function calls leading to the current location.
    #[tool(annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn get_stack_trace(
        &self,
        Parameters(StackTraceParams {
            session_id,
            thread_id,
            max_frames,
        }): Parameters<StackTraceParams>,
    ) -> Result<Json<GetStackTraceResponse>, McpError> {
        self.debugger
            .get_stack_trace(session_id, thread_id, max_frames)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error getting stack trace: {e}"), None))
    }

    /// List all threads in the target process.
    #[tool(annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn list_threads(
        &self,
        Parameters(SessionIdParam { session_id }): Parameters<SessionIdParam>,
    ) -> Result<Json<ListThreadsResponse>, McpError> {
        self.debugger
            .list_threads(session_id)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error listing threads: {e}"), None))
    }

    /// Switch the debugger context to a different thread.
    #[tool(annotations(destructive_hint = false, idempotent_hint = true, open_world_hint = false))]
    async fn switch_thread(
        &self,
        Parameters(SwitchThreadParams {
            session_id,
            thread_id,
        }): Parameters<SwitchThreadParams>,
    ) -> Result<Json<SwitchThreadResponse>, McpError> {
        self.debugger
            .switch_thread(session_id, thread_id)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error switching thread: {e}"), None))
    }

    // ==================== Memory ====================

    /// Read memory from the target process. Supports hex, ASCII, and Unicode formats.
    #[tool(annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn read_memory(
        &self,
        Parameters(ReadMemoryParams {
            session_id,
            address,
            length,
            format,
        }): Parameters<ReadMemoryParams>,
    ) -> Result<Json<ReadMemoryResponse>, McpError> {
        self.debugger
            .read_memory(session_id, address, length, format)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error reading memory: {e}"), None))
    }

    /// Search memory for a byte pattern.
    #[tool(annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn search_memory(
        &self,
        Parameters(SearchMemoryParams {
            session_id,
            start_address,
            length,
            pattern,
            max_results,
        }): Parameters<SearchMemoryParams>,
    ) -> Result<Json<SearchMemoryResponse>, McpError> {
        self.debugger
            .search_memory(session_id, start_address, length, pattern, max_results)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error searching memory: {e}"), None))
    }

    /// Write data to memory in the target process. Disabled by default for safety.
    #[tool(annotations(read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = false))]
    async fn write_memory(
        &self,
        Parameters(WriteMemoryParams {
            session_id,
            address,
            data,
        }): Parameters<WriteMemoryParams>,
    ) -> Result<Json<WriteMemoryResponse>, McpError> {
        self.debugger
            .write_memory(session_id, address, data)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error writing memory: {e}"), None))
    }

    // ==================== Symbols ====================

    /// Resolve a symbol name to an address or vice versa.
    #[tool(annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn resolve_symbol(
        &self,
        Parameters(ResolveSymbolParams {
            session_id,
            symbol,
            address,
        }): Parameters<ResolveSymbolParams>,
    ) -> Result<Json<ResolveSymbolResponse>, McpError> {
        self.debugger
            .resolve_symbol(session_id, symbol, address)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error resolving symbol: {e}"), None))
    }

    /// List all loaded modules (DLLs/EXEs) in the target process.
    #[tool(annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn list_modules(
        &self,
        Parameters(SessionIdParam { session_id }): Parameters<SessionIdParam>,
    ) -> Result<Json<ListModulesResponse>, McpError> {
        self.debugger
            .list_modules(session_id)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error listing modules: {e}"), None))
    }

    /// Get the layout information for a type (struct, class, enum).
    #[tool(annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn get_type_info(
        &self,
        Parameters(TypeInfoParams {
            session_id,
            module,
            type_name,
        }): Parameters<TypeInfoParams>,
    ) -> Result<Json<GetTypeInfoResponse>, McpError> {
        self.debugger
            .get_type_info(session_id, module, type_name)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error getting type info: {e}"), None))
    }

    // ==================== Registers & Disassembly ====================

    /// Get CPU register values.
    #[tool(annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn get_registers(
        &self,
        Parameters(RegistersParams {
            session_id,
            registers,
        }): Parameters<RegistersParams>,
    ) -> Result<Json<GetRegistersResponse>, McpError> {
        self.debugger
            .get_registers(session_id, registers)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error getting registers: {e}"), None))
    }

    /// Disassemble machine code at an address into assembly instructions.
    #[tool(annotations(read_only_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn disassemble(
        &self,
        Parameters(DisassembleParams {
            session_id,
            address,
            count,
        }): Parameters<DisassembleParams>,
    ) -> Result<Json<DisassembleResponse>, McpError> {
        self.debugger
            .disassemble(session_id, address, count)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error disassembling: {e}"), None))
    }

    // ==================== Live Debugging ====================

    /// Set a breakpoint at an address or symbol. Requires execution control to be enabled.
    #[tool(annotations(destructive_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn set_breakpoint(
        &self,
        Parameters(BreakpointParams {
            session_id,
            address,
            condition,
        }): Parameters<BreakpointParams>,
    ) -> Result<Json<SetBreakpointResponse>, McpError> {
        self.debugger
            .set_breakpoint(session_id, address, condition)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error setting breakpoint: {e}"), None))
    }

    /// Remove a breakpoint by its ID.
    #[tool(annotations(destructive_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn remove_breakpoint(
        &self,
        Parameters(RemoveBreakpointParams {
            session_id,
            breakpoint_id,
        }): Parameters<RemoveBreakpointParams>,
    ) -> Result<Json<RemoveBreakpointResponse>, McpError> {
        self.debugger
            .remove_breakpoint(session_id, breakpoint_id)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error removing breakpoint: {e}"), None))
    }

    /// Continue execution of the target process. Requires execution control to be enabled.
    /// If wait_timeout_ms is provided, blocks until an event occurs (breakpoint hit, exception,
    /// process exit) or timeout expires. Returns detailed event information when waiting.
    #[tool(annotations(destructive_hint = true, idempotent_hint = false, open_world_hint = false))]
    async fn go(
        &self,
        Parameters(GoParams {
            session_id,
            wait_timeout_ms,
        }): Parameters<GoParams>,
    ) -> Result<Json<GoAndWaitResponse>, McpError> {
        let timeout = wait_timeout_ms.unwrap_or(0);

        if timeout > 0 {
            self.debugger
                .go_and_wait(session_id, timeout)
                .await
                .map(Json)
                .map_err(|e| {
                    McpError::internal_error(format!("Error continuing execution: {e}"), None)
                })
        } else {
            self.debugger.go(session_id).await.map_err(|e| {
                McpError::internal_error(format!("Error continuing execution: {e}"), None)
            })?;

            Ok(Json(GoAndWaitResponse {
                is_running: true,
                stop_reason: None,
                instruction_pointer: None,
                thread_id: None,
                breakpoint_id: None,
                exception: None,
                exit_code: None,
                message:
                    "Execution continued (non-blocking). Use wait_timeout_ms to wait for events."
                        .to_string(),
            }))
        }
    }

    /// Single-step execution (into, over, or out). Requires execution control to be enabled.
    #[tool(annotations(destructive_hint = true, idempotent_hint = false, open_world_hint = false))]
    async fn step(
        &self,
        Parameters(StepParams {
            session_id,
            step_type,
        }): Parameters<StepParams>,
    ) -> Result<Json<StepResponse>, McpError> {
        self.debugger
            .step(session_id, step_type)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error stepping: {e}"), None))
    }

    /// Break into the debugger, pausing execution. Requires execution control to be enabled.
    #[tool(annotations(destructive_hint = true, idempotent_hint = true, open_world_hint = false))]
    async fn break_execution(
        &self,
        Parameters(SessionIdParam { session_id }): Parameters<SessionIdParam>,
    ) -> Result<Json<ExecutionControlResponse>, McpError> {
        self.debugger
            .break_execution(session_id)
            .await
            .map(Json)
            .map_err(|e| McpError::internal_error(format!("Error breaking execution: {e}"), None))
    }
}

// ============================================================================
// Prompts
// ============================================================================

#[prompt_router]
impl WinDbgServer {
    /// Guided crash dump triage workflow: open dump, run !analyze, inspect faulting thread, review modules.
    #[prompt]
    async fn crash_triage(
        &self,
        Parameters(CrashTriageParams {
            dump_path,
            symbol_path,
        }): Parameters<CrashTriageParams>,
    ) -> Result<GetPromptResult, McpError> {
        let sym_note = symbol_path
            .as_deref()
            .map(|p| format!("Symbol path: {p}\n"))
            .unwrap_or_default();

        Ok(GetPromptResult::new(vec![PromptMessage::new_text(
            PromptMessageRole::User,
            format!(
                "I need to triage a crash dump. Please follow these steps:\n\n\
                 {sym_note}\
                 1. Open the dump file at: {dump_path}\n\
                 2. Run `analyze` with verbose=true to get the automated analysis\n\
                 3. Get the stack trace for the faulting thread\n\
                 4. List all threads and identify any that look suspicious\n\
                 5. List loaded modules to check for known-bad or missing symbols\n\
                 6. If an exception occurred, examine the exception record\n\
                 7. Summarize findings with: root cause, faulting module, \
                    recommended next steps\n\n\
                 Be thorough but concise. Focus on actionable findings."
            ),
        )])
        .with_description("Step-by-step crash dump triage"))
    }

    /// Thread analysis workflow: enumerate threads, get stack traces, identify deadlocks or contention.
    #[prompt]
    async fn thread_analysis(
        &self,
        Parameters(ThreadAnalysisParams { session_id }): Parameters<ThreadAnalysisParams>,
    ) -> Result<GetPromptResult, McpError> {
        Ok(GetPromptResult::new(vec![PromptMessage::new_text(
            PromptMessageRole::User,
            format!(
                "Analyze threads in session {session_id} for deadlocks and contention:\n\n\
                 1. List all threads to get an overview\n\
                 2. Get stack traces for each thread (or the first 10 if many)\n\
                 3. Identify threads waiting on synchronization primitives \
                    (critical sections, mutexes, events, SRW locks)\n\
                 4. Check for circular wait patterns that indicate deadlocks\n\
                 5. Identify the thread holding each lock that others are waiting on\n\
                 6. Look for threads stuck in long-running operations\n\
                 7. Use `execute` with `!locks` to get kernel lock information\n\
                 8. Summarize: which threads are blocked, what they're waiting on, \
                    and whether a deadlock exists\n\n\
                 Focus on the wait chain and lock ordering."
            ),
        )])
        .with_description("Thread deadlock and contention analysis"))
    }

    /// Memory investigation workflow: inspect memory regions, search for patterns, analyze heap state.
    #[prompt]
    async fn memory_investigation(
        &self,
        Parameters(MemoryInvestigationParams {
            session_id,
            address,
        }): Parameters<MemoryInvestigationParams>,
    ) -> Result<GetPromptResult, McpError> {
        let addr_note = address
            .as_deref()
            .map(|a| format!("Start investigation at address: {a}\n"))
            .unwrap_or_default();

        Ok(GetPromptResult::new(vec![PromptMessage::new_text(
            PromptMessageRole::User,
            format!(
                "Investigate memory issues in session {session_id}:\n\n\
                 {addr_note}\
                 1. Use `execute` with `!address -summary` to get memory usage overview\n\
                 2. Use `execute` with `!heap -s` to summarize heap state\n\
                 3. If a suspect address is provided, read memory around it and \
                    check for corruption patterns (overwritten vtables, guard bytes, \
                    freed memory patterns like 0xfeeefeee or 0xdddddddd)\n\
                 4. Use `execute` with `!heap -p -a <address>` for page heap details \
                    if page heap is enabled\n\
                 5. Check for common corruption patterns:\n\
                    - Buffer overruns (look for NUL-terminated strings overflowing)\n\
                    - Use-after-free (look for 0xfeeefeee patterns)\n\
                    - Double-free (check heap entry state)\n\
                    - Stack overflow (check stack pointer vs stack limits)\n\
                 6. Resolve any symbols near the suspect address\n\
                 7. Summarize: type of corruption, likely cause, affected memory region"
            ),
        )])
        .with_description("Memory corruption and leak investigation"))
    }
}

// ============================================================================
// ServerHandler
// ============================================================================

#[tool_handler]
#[prompt_handler]
impl ServerHandler for WinDbgServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .build(),
        )
        .with_server_info(rmcp::model::Implementation::new(
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
        ))
        .with_instructions(
            "WinDbg MCP Server provides debugging capabilities through the Windows Debug Engine. \
             Use open_dump to open crash dumps or attach_process to attach to live processes. \
             After opening a session, use the returned session_id with other tools. \
             Use the crash_triage, thread_analysis, or memory_investigation prompts for \
             guided debugging workflows."
                .to_string(),
        )
    }
}
