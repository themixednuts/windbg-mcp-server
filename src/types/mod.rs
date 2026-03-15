//! Type definitions for MCP tool requests and responses.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ============================================================================
// Session Management Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OpenDumpRequest {
    /// Path to the crash dump file (.dmp)
    pub dump_path: String,
    /// Optional symbol path (uses _NT_SYMBOL_PATH if not provided)
    pub symbol_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct OpenDumpResponse {
    /// Unique session identifier
    pub session_id: String,
    /// Path to the opened dump file
    pub dump_path: String,
    /// Initial analysis summary
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttachProcessRequest {
    /// Process ID to attach to
    pub pid: u32,
    /// Whether to attach non-invasively (default: false)
    #[serde(default)]
    pub non_invasive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AttachProcessResponse {
    /// Unique session identifier
    pub session_id: String,
    /// Process ID attached to
    pub pid: u32,
    /// Process name
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DetachRequest {
    /// Session ID to detach from
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DetachResponse {
    /// Message confirming detach
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionInfo {
    /// Unique session identifier
    pub session_id: String,
    /// Type of session (dump or live)
    pub session_type: SessionType,
    /// Target description
    pub target: String,
    /// Whether session is active
    pub active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum SessionType {
    Dump,
    Live,
    Remote,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListSessionsResponse {
    /// List of active sessions
    pub sessions: Vec<SessionInfo>,
}

// ============================================================================
// Command Execution Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExecuteCommandRequest {
    /// Session ID to execute command in
    pub session_id: String,
    /// Debugger command to execute
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExecuteCommandResponse {
    /// Command output
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnalyzeRequest {
    /// Session ID to analyze
    pub session_id: String,
    /// Whether to include verbose output (default: true)
    #[serde(default = "default_true")]
    pub verbose: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct AnalyzeResponse {
    /// Raw analysis output
    pub raw_output: String,
    /// Exception code if applicable
    pub exception_code: Option<String>,
    /// Exception description
    pub exception_description: Option<String>,
    /// Faulting module
    pub faulting_module: Option<String>,
    /// Faulting function
    pub faulting_function: Option<String>,
    /// Bug check code (for kernel dumps)
    pub bugcheck_code: Option<String>,
}

// ============================================================================
// Stack & Thread Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetStackTraceRequest {
    /// Session ID
    pub session_id: String,
    /// Thread ID (uses current thread if not specified)
    pub thread_id: Option<u32>,
    /// Maximum number of frames to return
    #[serde(default = "default_max_frames")]
    pub max_frames: u32,
}

fn default_max_frames() -> u32 {
    50
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StackFrame {
    /// Frame number
    pub frame_number: u32,
    /// Instruction pointer
    pub instruction_pointer: String,
    /// Return address
    pub return_address: Option<String>,
    /// Stack pointer
    pub stack_pointer: Option<String>,
    /// Module name
    pub module: Option<String>,
    /// Function name
    pub function: Option<String>,
    /// Source file
    pub source_file: Option<String>,
    /// Source line number
    pub source_line: Option<u32>,
    /// Displacement from function start
    pub displacement: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetStackTraceResponse {
    /// Thread ID
    pub thread_id: u32,
    /// Stack frames
    pub frames: Vec<StackFrame>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListThreadsRequest {
    /// Session ID
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ThreadInfo {
    /// Thread ID
    pub thread_id: u32,
    /// Thread system ID
    pub system_id: u32,
    /// Thread state
    pub state: Option<String>,
    /// Current frame (top of stack)
    pub current_frame: Option<String>,
    /// Whether this is the current thread
    pub is_current: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListThreadsResponse {
    /// List of threads
    pub threads: Vec<ThreadInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SwitchThreadRequest {
    /// Session ID
    pub session_id: String,
    /// Thread ID to switch to
    pub thread_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SwitchThreadResponse {
    /// New current thread ID
    pub thread_id: u32,
}

// ============================================================================
// Memory Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum MemoryFormat {
    #[default]
    Hex,
    Ascii,
    Unicode,
    Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReadMemoryRequest {
    /// Session ID
    pub session_id: String,
    /// Memory address (hex string or decimal)
    pub address: String,
    /// Number of bytes to read
    pub size: u32,
    /// Output format
    #[serde(default)]
    pub format: MemoryFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ReadMemoryResponse {
    /// Address that was read
    pub address: String,
    /// Number of bytes read
    pub bytes_read: u32,
    /// Memory content (formatted according to request)
    pub content: String,
    /// Raw bytes as hex string
    pub raw_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SearchMemoryRequest {
    /// Session ID
    pub session_id: String,
    /// Start address
    pub start_address: String,
    /// Search length
    pub length: u64,
    /// Pattern to search for (hex bytes, e.g., "4D 5A 90")
    pub pattern: String,
    /// Maximum number of results
    #[serde(default = "default_max_results")]
    pub max_results: u32,
}

fn default_max_results() -> u32 {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SearchMemoryResponse {
    /// Found addresses
    pub matches: Vec<String>,
    /// Number of matches found
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WriteMemoryRequest {
    /// Session ID
    pub session_id: String,
    /// Memory address
    pub address: String,
    /// Data to write (hex bytes)
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct WriteMemoryResponse {
    /// Number of bytes written
    pub bytes_written: u32,
}

// ============================================================================
// Symbol Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResolveSymbolRequest {
    /// Session ID
    pub session_id: String,
    /// Symbol name or address to resolve
    pub symbol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ResolveSymbolResponse {
    /// Symbol name
    pub name: Option<String>,
    /// Symbol address
    pub address: String,
    /// Module containing the symbol
    pub module: Option<String>,
    /// Symbol type
    pub symbol_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListModulesRequest {
    /// Session ID
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ModuleInfo {
    /// Module name
    pub name: String,
    /// Base address
    pub base_address: String,
    /// Module size
    pub size: u64,
    /// Image path
    pub image_path: Option<String>,
    /// Symbol status
    pub symbol_status: String,
    /// Version info
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListModulesResponse {
    /// List of modules
    pub modules: Vec<ModuleInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetTypeInfoRequest {
    /// Session ID
    pub session_id: String,
    /// Module name
    pub module: String,
    /// Type name
    pub type_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TypeFieldInfo {
    /// Field name
    pub name: String,
    /// Field type
    pub field_type: String,
    /// Offset within structure
    pub offset: u32,
    /// Field size
    pub size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetTypeInfoResponse {
    /// Type name
    pub name: String,
    /// Type size
    pub size: u32,
    /// Type fields (for structs/classes)
    pub fields: Vec<TypeFieldInfo>,
}

// ============================================================================
// Register & Disassembly Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetRegistersRequest {
    /// Session ID
    pub session_id: String,
    /// Specific registers to retrieve (all if empty)
    #[serde(default)]
    pub registers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterValue {
    /// Register name
    pub name: String,
    /// Register value (hex)
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetRegistersResponse {
    /// Register values
    pub registers: Vec<RegisterValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DisassembleRequest {
    /// Session ID
    pub session_id: String,
    /// Start address (or symbol name)
    pub address: String,
    /// Number of instructions to disassemble
    #[serde(default = "default_instruction_count")]
    pub count: u32,
}

fn default_instruction_count() -> u32 {
    20
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DisassemblyLine {
    /// Instruction address
    pub address: String,
    /// Instruction bytes (hex)
    pub bytes: String,
    /// Assembly instruction
    pub instruction: String,
    /// Symbol info if available
    pub symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DisassembleResponse {
    /// Disassembly lines
    pub instructions: Vec<DisassemblyLine>,
}

// ============================================================================
// Live Debugging Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SetBreakpointRequest {
    /// Session ID
    pub session_id: String,
    /// Address or symbol for breakpoint
    pub address: String,
    /// Optional breakpoint condition
    pub condition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SetBreakpointResponse {
    /// Breakpoint ID
    pub breakpoint_id: u32,
    /// Resolved address
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RemoveBreakpointRequest {
    /// Session ID
    pub session_id: String,
    /// Breakpoint ID to remove
    pub breakpoint_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RemoveBreakpointResponse {
    /// Message confirming removal
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionControlRequest {
    /// Session ID
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionControlResponse {
    /// Current state after operation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StepRequest {
    /// Session ID
    pub session_id: String,
    /// Step type: "into", "over", or "out"
    #[serde(default = "default_step_type")]
    pub step_type: StepType,
}

fn default_step_type() -> StepType {
    StepType::Over
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum StepType {
    Into,
    #[default]
    Over,
    Out,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct StepResponse {
    /// New instruction pointer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_pointer: Option<String>,
}

// ============================================================================
// Breakpoint Types (Extended)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum BreakpointType {
    /// Software breakpoint (int 3)
    #[default]
    Software,
    /// Hardware breakpoint (debug registers)
    Hardware,
    /// Data breakpoint (memory watchpoint)
    Data,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum BreakpointState {
    #[default]
    Enabled,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DataBreakpointAccess {
    Read,
    Write,
    ReadWrite,
    Execute,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct BreakpointInfo {
    /// Breakpoint ID
    pub id: u32,
    /// Breakpoint type
    pub breakpoint_type: BreakpointType,
    /// Breakpoint state
    pub state: BreakpointState,
    /// Address or symbol
    pub address: String,
    /// Resolved address (hex)
    pub resolved_address: Option<String>,
    /// Module containing the breakpoint
    pub module: Option<String>,
    /// Symbol at breakpoint
    pub symbol: Option<String>,
    /// Condition expression
    pub condition: Option<String>,
    /// Hit count
    pub hit_count: u32,
    /// Data access type (for data breakpoints)
    pub data_access: Option<DataBreakpointAccess>,
    /// Data size (for data breakpoints)
    pub data_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListBreakpointsRequest {
    /// Session ID
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ListBreakpointsResponse {
    /// List of breakpoints
    pub breakpoints: Vec<BreakpointInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SetDataBreakpointRequest {
    /// Session ID
    pub session_id: String,
    /// Memory address to watch
    pub address: String,
    /// Size of memory region (1, 2, 4, or 8 bytes)
    pub size: u32,
    /// Access type to break on
    pub access: DataBreakpointAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SetDataBreakpointResponse {
    /// Breakpoint ID
    pub breakpoint_id: u32,
}

// ============================================================================
// Exception & Event Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DebugEventType {
    Exception,
    CreateThread,
    ExitThread,
    CreateProcess,
    ExitProcess,
    LoadModule,
    UnloadModule,
    SystemError,
    Breakpoint,
    SingleStep,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ExceptionRecord {
    /// Exception code
    pub code: u32,
    /// Exception code as hex string
    pub code_hex: String,
    /// Human-readable exception name
    pub name: String,
    /// Exception flags
    pub flags: u32,
    /// Address where exception occurred
    pub address: String,
    /// Whether this is a first-chance exception
    pub first_chance: bool,
    /// Number of parameters
    pub num_parameters: u32,
    /// Exception parameters
    pub parameters: Vec<u64>,
    /// Nested exception record (if any)
    pub nested: Option<Box<ExceptionRecord>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DebugEventInfo {
    /// Event type
    pub event_type: DebugEventType,
    /// Process ID
    pub process_id: u32,
    /// Thread ID
    pub thread_id: u32,
    /// Exception record (if event_type is Exception)
    pub exception: Option<ExceptionRecord>,
    /// Module info (if event_type is LoadModule/UnloadModule)
    pub module: Option<ModuleInfo>,
    /// Description of the event
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetExceptionInfoRequest {
    /// Session ID
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetExceptionInfoResponse {
    /// Whether an exception is present
    pub has_exception: bool,
    /// Exception record
    pub exception: Option<ExceptionRecord>,
    /// Raw exception output
    pub raw_output: String,
}

// ============================================================================
// Memory Region Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
pub struct MemoryProtection {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub guard: bool,
    pub no_cache: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemoryState {
    Commit,
    Reserve,
    Free,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MemoryType {
    Image,
    Mapped,
    Private,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MemoryRegionInfo {
    /// Base address of the region
    pub base_address: String,
    /// Size of the region in bytes
    pub size: u64,
    /// Memory state
    pub state: MemoryState,
    /// Memory protection
    pub protection: MemoryProtection,
    /// Memory type
    pub memory_type: Option<MemoryType>,
    /// Associated module (if any)
    pub module: Option<String>,
    /// Region usage description
    pub usage: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetMemoryRegionsRequest {
    /// Session ID
    pub session_id: String,
    /// Start address (optional, defaults to 0)
    pub start_address: Option<String>,
    /// End address (optional)
    pub end_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetMemoryRegionsResponse {
    /// Memory regions
    pub regions: Vec<MemoryRegionInfo>,
}

// ============================================================================
// Extended Register Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum RegisterType {
    /// General purpose register
    General,
    /// Floating point register
    Float,
    /// SSE/AVX vector register
    Vector,
    /// Segment register
    Segment,
    /// Control register
    Control,
    /// Debug register
    Debug,
    /// Flags register
    Flags,
    /// Instruction pointer
    InstructionPointer,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RegisterInfo {
    /// Register name
    pub name: String,
    /// Register value (hex)
    pub value: String,
    /// Register type
    pub register_type: RegisterType,
    /// Size in bits
    pub size_bits: u32,
    /// Register index
    pub index: u32,
    /// Sub-register of (e.g., "eax" is sub of "rax")
    pub parent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetExtendedRegistersRequest {
    /// Session ID
    pub session_id: String,
    /// Include vector registers (XMM, YMM)
    #[serde(default)]
    pub include_vector: bool,
    /// Include floating point registers
    #[serde(default)]
    pub include_float: bool,
    /// Include debug registers
    #[serde(default)]
    pub include_debug: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetExtendedRegistersResponse {
    /// General registers
    pub general: Vec<RegisterInfo>,
    /// Flags register with individual flags
    pub flags: Option<FlagsRegister>,
    /// Vector registers (XMM/YMM)
    pub vector: Vec<RegisterInfo>,
    /// Floating point registers
    pub float: Vec<RegisterInfo>,
    /// Debug registers
    pub debug: Vec<RegisterInfo>,
    /// Segment registers
    pub segment: Vec<RegisterInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct FlagsRegister {
    /// Raw value
    pub value: u64,
    /// Carry flag
    pub cf: bool,
    /// Parity flag
    pub pf: bool,
    /// Auxiliary carry flag
    pub af: bool,
    /// Zero flag
    pub zf: bool,
    /// Sign flag
    pub sf: bool,
    /// Trap flag
    pub tf: bool,
    /// Interrupt enable flag
    pub if_flag: bool,
    /// Direction flag
    pub df: bool,
    /// Overflow flag
    pub of: bool,
}

// ============================================================================
// Extended Symbol Types
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SymbolType {
    Function,
    Data,
    PublicSymbol,
    Label,
    Type,
    Constant,
    Parameter,
    Local,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SymbolInfo {
    /// Symbol name
    pub name: String,
    /// Symbol address
    pub address: String,
    /// Module containing the symbol
    pub module: String,
    /// Symbol type
    pub symbol_type: SymbolType,
    /// Symbol size (if known)
    pub size: Option<u64>,
    /// Symbol flags
    pub flags: u32,
    /// Type name (for typed symbols)
    pub type_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct LineInfo {
    /// Source file path
    pub file: String,
    /// Line number
    pub line: u32,
    /// Column (if available)
    pub column: Option<u32>,
    /// Start address of this line
    pub address: String,
    /// End address of this line (if available)
    pub end_address: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetSymbolInfoRequest {
    /// Session ID
    pub session_id: String,
    /// Symbol name or pattern (supports wildcards)
    pub symbol: String,
    /// Maximum number of results
    #[serde(default = "default_max_results")]
    pub max_results: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetSymbolInfoResponse {
    /// Matching symbols
    pub symbols: Vec<SymbolInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetSourceLineRequest {
    /// Session ID
    pub session_id: String,
    /// Address to look up
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetSourceLineResponse {
    /// Line information
    pub line: Option<LineInfo>,
    /// Displacement from line start
    pub displacement: Option<u64>,
}

// ============================================================================
// Thread Context Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ThreadContext {
    /// Thread ID
    pub thread_id: u32,
    /// Instruction pointer
    pub rip: u64,
    /// Stack pointer
    pub rsp: u64,
    /// Base pointer
    pub rbp: u64,
    /// General purpose registers
    pub general_registers: Vec<RegisterValue>,
    /// Flags
    pub flags: Option<FlagsRegister>,
    /// Segment registers (cs, ds, es, fs, gs, ss)
    pub segment_registers: Vec<RegisterValue>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetThreadContextRequest {
    /// Session ID
    pub session_id: String,
    /// Thread ID (uses current thread if not specified)
    pub thread_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetThreadContextResponse {
    /// Thread context
    pub context: ThreadContext,
}

// ============================================================================
// Process Information Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name
    pub name: String,
    /// Executable path
    pub exe_path: Option<String>,
    /// Command line
    pub command_line: Option<String>,
    /// Parent process ID
    pub parent_pid: Option<u32>,
    /// Creation time
    pub creation_time: Option<String>,
    /// Whether this is a WoW64 process
    pub is_wow64: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetProcessInfoRequest {
    /// Session ID
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GetProcessInfoResponse {
    /// Process information
    pub process: ProcessInfo,
    /// Number of threads
    pub thread_count: u32,
    /// Number of loaded modules
    pub module_count: u32,
}

// ============================================================================
// Execution Wait Types
// ============================================================================

/// The reason execution stopped after a go/continue command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// A breakpoint was hit
    Breakpoint,
    /// A single-step completed
    SingleStep,
    /// An exception occurred
    Exception,
    /// The process exited
    ProcessExit,
    /// A thread was created
    ThreadCreate,
    /// A thread exited
    ThreadExit,
    /// A module was loaded
    ModuleLoad,
    /// A module was unloaded
    ModuleUnload,
    /// The wait timed out (target still running)
    Timeout,
    /// Unknown stop reason
    Unknown,
}

/// Response from go_and_wait - contains information about why execution stopped.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GoAndWaitResponse {
    /// Whether the target is still running (true if timeout, false if stopped)
    pub is_running: bool,
    /// The reason execution stopped (None if still running/timeout)
    pub stop_reason: Option<StopReason>,
    /// Current instruction pointer (if stopped)
    pub instruction_pointer: Option<String>,
    /// Current thread ID (if stopped)
    pub thread_id: Option<u32>,
    /// Breakpoint ID that was hit (if stop_reason is Breakpoint)
    pub breakpoint_id: Option<u32>,
    /// Exception information (if stop_reason is Exception)
    pub exception: Option<ExceptionRecord>,
    /// Process exit code (if stop_reason is ProcessExit)
    pub exit_code: Option<u32>,
    /// Additional details/message about the stop
    pub message: String,
}
