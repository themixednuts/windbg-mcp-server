//! MCP server handler implementation using rmcp 0.13 macros.

use crate::config::SafetyConfig;
use crate::debugger::SessionManager;
use crate::types::*;
use parking_lot::RwLock;
use rmcp::handler::server::ServerHandler;
use rmcp::handler::server::tool::{ToolCallContext, ToolRouter};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParam, CallToolResult, Implementation, ListToolsResult, PaginatedRequestParam,
    ServerCapabilities, ServerInfo, ToolsCapability,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, Json, RoleServer, tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

// ============================================================================
// Tool Parameter Types (for tools that don't match existing request types)
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
    /// Output format: "hex", "ascii", or "unicode"
    #[serde(default)]
    pub format: String,
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
    /// Step type: "into", "over", or "out"
    #[serde(default = "default_step")]
    pub step_type: String,
}

fn default_step() -> String {
    "over".to_string()
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
// Response wrapper for simple results
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ToolResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T> ToolResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

// ============================================================================
// WinDbg MCP Server
// ============================================================================

/// WinDbg MCP Server.
#[derive(Clone)]
pub struct WinDbgServer {
    session_manager: Arc<RwLock<SessionManager>>,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

// COM objects are thread-safe when properly initialized with COINIT_MULTITHREADED
unsafe impl Send for WinDbgServer {}
unsafe impl Sync for WinDbgServer {}

#[tool_router]
impl WinDbgServer {
    /// Create a new WinDbg MCP server.
    pub fn new(safety_config: SafetyConfig) -> Self {
        Self {
            session_manager: Arc::new(RwLock::new(SessionManager::new(safety_config))),
            tool_router: Self::tool_router(),
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

    /// Get server info.
    pub fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: Default::default(),
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(false),
                }),
                ..Default::default()
            },
            server_info: Implementation {
                name: "windbg-mcp-server".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                title: None,
                icons: None,
                website_url: None,
            },
            instructions: Some(
                "WinDbg MCP Server provides debugging capabilities through the Windows Debug Engine. \
                 Use debug_open_dump to open crash dumps or debug_attach_process to attach to live processes. \
                 After opening a session, use the returned session_id with other tools."
                    .into(),
            ),
        }
    }

    // ==================== Session Management ====================

    #[tool(
        description = "Open a crash dump file (.dmp) for analysis. Returns a session ID to use with other tools."
    )]
    async fn open_dump(
        &self,
        params: Parameters<OpenDumpParams>,
    ) -> Result<Json<ToolResponse<SessionInfo>>, String> {
        let path = PathBuf::from(&params.0.path);
        match self
            .session_manager
            .write()
            .open_dump(path, params.0.symbol_path.clone())
        {
            Ok(info) => Ok(Json(ToolResponse::ok(info))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error opening dump: {}",
                e
            )))),
        }
    }

    #[tool(
        description = "Attach to a live process for debugging. Optionally attach non-invasively."
    )]
    async fn attach_process(
        &self,
        params: Parameters<AttachParams>,
    ) -> Result<Json<ToolResponse<SessionInfo>>, String> {
        match self
            .session_manager
            .write()
            .attach_process(params.0.pid, params.0.non_invasive)
        {
            Ok(info) => Ok(Json(ToolResponse::ok(info))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error attaching to process: {}",
                e
            )))),
        }
    }

    #[tool(description = "Detach from a debug session and close it.")]
    async fn detach(
        &self,
        params: Parameters<SessionIdParam>,
    ) -> Result<Json<ToolResponse<DetachResponse>>, String> {
        match self
            .session_manager
            .write()
            .close_session(&params.0.session_id)
        {
            Ok(()) => Ok(Json(ToolResponse::ok(DetachResponse { success: true }))),
            Err(e) => Ok(Json(ToolResponse::err(format!("Error detaching: {}", e)))),
        }
    }

    #[tool(description = "List all active debug sessions.")]
    async fn list_sessions(&self) -> Result<Json<ListSessionsResponse>, String> {
        let sessions = self.session_manager.read().list_sessions();
        Ok(Json(ListSessionsResponse { sessions }))
    }

    // ==================== Command Execution ====================

    #[tool(
        description = "Execute a WinDbg command and return the output. Some dangerous commands are blocked by safety policy."
    )]
    async fn execute(
        &self,
        params: Parameters<ExecuteParams>,
    ) -> Result<Json<ToolResponse<ExecuteCommandResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.execute_command(&params.0.command)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error executing command: {}",
                e
            )))),
        }
    }

    #[tool(
        description = "Run !analyze -v to automatically analyze the crash dump and identify the root cause."
    )]
    async fn analyze(
        &self,
        params: Parameters<AnalyzeParams>,
    ) -> Result<Json<ToolResponse<ExecuteCommandResponse>>, String> {
        let cmd = if params.0.verbose {
            "!analyze -v"
        } else {
            "!analyze"
        };
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| session.execute_command(cmd))
        {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!("Error analyzing: {}", e)))),
        }
    }

    // ==================== JavaScript Scripting ====================

    #[tool(
        description = "Load a JavaScript debugging script (.js). The script remains loaded until unloaded or session ends."
    )]
    async fn load_script(
        &self,
        params: Parameters<LoadScriptParams>,
    ) -> Result<Json<ToolResponse<ExecuteCommandResponse>>, String> {
        let cmd = format!(
            ".scriptload \"{}\"",
            params.0.script_path.replace('\\', "\\\\")
        );
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.execute_command(&cmd)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error loading script: {}",
                e
            )))),
        }
    }

    #[tool(description = "Unload a previously loaded JavaScript script.")]
    async fn unload_script(
        &self,
        params: Parameters<UnloadScriptParams>,
    ) -> Result<Json<ToolResponse<ExecuteCommandResponse>>, String> {
        let cmd = format!(
            ".scriptunload \"{}\"",
            params.0.script_path.replace('\\', "\\\\")
        );
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.execute_command(&cmd)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error unloading script: {}",
                e
            )))),
        }
    }

    #[tool(
        description = "Load and immediately execute a JavaScript script. The script is unloaded after execution."
    )]
    async fn run_script(
        &self,
        params: Parameters<RunScriptParams>,
    ) -> Result<Json<ToolResponse<ExecuteCommandResponse>>, String> {
        let cmd = format!(
            ".scriptrun \"{}\"",
            params.0.script_path.replace('\\', "\\\\")
        );
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.execute_command(&cmd)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error running script: {}",
                e
            )))),
        }
    }

    #[tool(description = "Invoke a function from a loaded JavaScript script using dx command.")]
    async fn invoke_script(
        &self,
        params: Parameters<InvokeScriptParams>,
    ) -> Result<Json<ToolResponse<ExecuteCommandResponse>>, String> {
        let cmd = if params.0.args.is_empty() {
            format!("dx @$scriptContents.{}()", params.0.function)
        } else {
            format!(
                "dx @$scriptContents.{}({})",
                params.0.function, params.0.args
            )
        };
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.execute_command(&cmd)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error invoking script function: {}",
                e
            )))),
        }
    }

    #[tool(
        description = "Evaluate a JavaScript expression using the dx command. Useful for querying debugger data model."
    )]
    async fn eval(
        &self,
        params: Parameters<EvalScriptParams>,
    ) -> Result<Json<ToolResponse<ExecuteCommandResponse>>, String> {
        let cmd = format!("dx {}", params.0.code);
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.execute_command(&cmd)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error evaluating expression: {}",
                e
            )))),
        }
    }

    #[tool(description = "List all currently loaded JavaScript scripts.")]
    async fn list_scripts(
        &self,
        params: Parameters<SessionIdParam>,
    ) -> Result<Json<ToolResponse<ExecuteCommandResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.execute_command(".scriptlist")
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error listing scripts: {}",
                e
            )))),
        }
    }

    // ==================== Stack & Threads ====================

    #[tool(
        description = "Get the call stack for a thread. Shows function calls leading to the current location."
    )]
    async fn get_stack_trace(
        &self,
        params: Parameters<StackTraceParams>,
    ) -> Result<Json<ToolResponse<GetStackTraceResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.get_stack_trace(params.0.thread_id, params.0.max_frames)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error getting stack trace: {}",
                e
            )))),
        }
    }

    #[tool(description = "List all threads in the target process.")]
    async fn list_threads(
        &self,
        params: Parameters<SessionIdParam>,
    ) -> Result<Json<ToolResponse<ListThreadsResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| session.get_threads())
        {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error listing threads: {}",
                e
            )))),
        }
    }

    #[tool(description = "Switch the debugger context to a different thread.")]
    async fn switch_thread(
        &self,
        params: Parameters<SwitchThreadParams>,
    ) -> Result<Json<ToolResponse<SwitchThreadResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.switch_thread(params.0.thread_id)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error switching thread: {}",
                e
            )))),
        }
    }

    // ==================== Memory ====================

    #[tool(
        description = "Read memory from the target process. Supports hex, ASCII, and Unicode formats."
    )]
    async fn read_memory(
        &self,
        params: Parameters<ReadMemoryParams>,
    ) -> Result<Json<ToolResponse<ReadMemoryResponse>>, String> {
        let fmt = match params.0.format.as_str() {
            "ascii" => MemoryFormat::Ascii,
            "unicode" => MemoryFormat::Unicode,
            _ => MemoryFormat::Hex,
        };
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.read_memory(&params.0.address, params.0.length, fmt)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error reading memory: {}",
                e
            )))),
        }
    }

    #[tool(description = "Search memory for a byte pattern.")]
    async fn search_memory(
        &self,
        params: Parameters<SearchMemoryParams>,
    ) -> Result<Json<ToolResponse<SearchMemoryResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.search_memory(
                    &params.0.start_address,
                    params.0.length,
                    &params.0.pattern,
                    params.0.max_results,
                )
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error searching memory: {}",
                e
            )))),
        }
    }

    #[tool(
        description = "Write data to memory in the target process. Disabled by default for safety."
    )]
    async fn write_memory(
        &self,
        params: Parameters<WriteMemoryParams>,
    ) -> Result<Json<ToolResponse<WriteMemoryResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.write_memory(&params.0.address, &params.0.data)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error writing memory: {}",
                e
            )))),
        }
    }

    // ==================== Symbols ====================

    #[tool(description = "Resolve a symbol name to an address or vice versa.")]
    async fn resolve_symbol(
        &self,
        params: Parameters<ResolveSymbolParams>,
    ) -> Result<Json<ToolResponse<ResolveSymbolResponse>>, String> {
        // Use symbol if provided, otherwise use address
        let query = params
            .0
            .symbol
            .as_deref()
            .or(params.0.address.as_deref())
            .unwrap_or("");
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.resolve_symbol(query)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error resolving symbol: {}",
                e
            )))),
        }
    }

    #[tool(description = "List all loaded modules (DLLs/EXEs) in the target process.")]
    async fn list_modules(
        &self,
        params: Parameters<SessionIdParam>,
    ) -> Result<Json<ToolResponse<ListModulesResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| session.get_modules())
        {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error listing modules: {}",
                e
            )))),
        }
    }

    #[tool(description = "Get the layout information for a type (struct, class, enum).")]
    async fn get_type_info(
        &self,
        params: Parameters<TypeInfoParams>,
    ) -> Result<Json<ToolResponse<GetTypeInfoResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.get_type_info(&params.0.module, &params.0.type_name)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error getting type info: {}",
                e
            )))),
        }
    }

    // ==================== Registers & Disassembly ====================

    #[tool(description = "Get CPU register values.")]
    async fn get_registers(
        &self,
        params: Parameters<RegistersParams>,
    ) -> Result<Json<ToolResponse<GetRegistersResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.get_registers(&params.0.registers)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error getting registers: {}",
                e
            )))),
        }
    }

    #[tool(description = "Disassemble machine code at an address into assembly instructions.")]
    async fn disassemble(
        &self,
        params: Parameters<DisassembleParams>,
    ) -> Result<Json<ToolResponse<DisassembleResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.disassemble(&params.0.address, params.0.count)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error disassembling: {}",
                e
            )))),
        }
    }

    // ==================== Live Debugging ====================

    #[tool(
        description = "Set a breakpoint at an address or symbol. Requires execution control to be enabled."
    )]
    async fn set_breakpoint(
        &self,
        params: Parameters<BreakpointParams>,
    ) -> Result<Json<ToolResponse<SetBreakpointResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.set_breakpoint(&params.0.address, params.0.condition.as_deref())
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error setting breakpoint: {}",
                e
            )))),
        }
    }

    #[tool(description = "Remove a breakpoint by its ID.")]
    async fn remove_breakpoint(
        &self,
        params: Parameters<RemoveBreakpointParams>,
    ) -> Result<Json<ToolResponse<RemoveBreakpointResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| {
                session.remove_breakpoint(params.0.breakpoint_id)
            }) {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error removing breakpoint: {}",
                e
            )))),
        }
    }

    #[tool(
        description = "Continue execution of the target process. Requires execution control to be enabled."
    )]
    async fn go(
        &self,
        params: Parameters<SessionIdParam>,
    ) -> Result<Json<ToolResponse<ExecutionControlResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| session.go())
        {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error continuing execution: {}",
                e
            )))),
        }
    }

    #[tool(
        description = "Single-step execution (into, over, or out). Requires execution control to be enabled."
    )]
    async fn step(
        &self,
        params: Parameters<StepParams>,
    ) -> Result<Json<ToolResponse<StepResponse>>, String> {
        let st = match params.0.step_type.as_str() {
            "into" => StepType::Into,
            "out" => StepType::Out,
            _ => StepType::Over,
        };
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| session.step(st))
        {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!("Error stepping: {}", e)))),
        }
    }

    #[tool(
        description = "Break into the debugger, pausing execution. Requires execution control to be enabled."
    )]
    async fn break_execution(
        &self,
        params: Parameters<SessionIdParam>,
    ) -> Result<Json<ToolResponse<ExecutionControlResponse>>, String> {
        match self
            .session_manager
            .read()
            .with_session(&params.0.session_id, |session| session.break_execution())
        {
            Ok(resp) => Ok(Json(ToolResponse::ok(resp))),
            Err(e) => Ok(Json(ToolResponse::err(format!(
                "Error breaking execution: {}",
                e
            )))),
        }
    }
}

// Implement ServerHandler trait for WinDbgServer
impl ServerHandler for WinDbgServer {
    fn get_info(&self) -> ServerInfo {
        WinDbgServer::get_info(self)
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParam>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: self.tool_router.list_all(),
            next_cursor: None,
            meta: None,
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let ctx = ToolCallContext::new(self, request, context);
        self.tool_router.call(ctx).await
    }
}
