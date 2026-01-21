//! Dedicated debugger thread for COM operations.
//!
//! COM interfaces must be called from the same thread that created them.
//! This module provides a dedicated thread for all debugger operations.

use super::client::DebugResult;
use super::session::SessionManager;
use crate::config::SafetyConfig;
use crate::types::*;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use tokio::sync::oneshot;

/// Commands that can be sent to the debugger thread.
pub enum DebugCommand {
    // Session management
    OpenDump {
        path: PathBuf,
        symbol_path: Option<String>,
        reply: oneshot::Sender<DebugResult<SessionInfo>>,
    },
    AttachProcess {
        pid: u32,
        non_invasive: bool,
        reply: oneshot::Sender<DebugResult<SessionInfo>>,
    },
    ConnectRemote {
        connection_string: String,
        reply: oneshot::Sender<DebugResult<SessionInfo>>,
    },
    Detach {
        session_id: String,
        reply: oneshot::Sender<DebugResult<()>>,
    },
    ListSessions {
        reply: oneshot::Sender<Vec<SessionInfo>>,
    },

    // Debug operations
    Execute {
        session_id: String,
        command: String,
        reply: oneshot::Sender<DebugResult<ExecuteCommandResponse>>,
    },
    Analyze {
        session_id: String,
        verbose: bool,
        reply: oneshot::Sender<DebugResult<AnalyzeResponse>>,
    },
    GetStackTrace {
        session_id: String,
        thread_id: Option<u32>,
        max_frames: u32,
        reply: oneshot::Sender<DebugResult<GetStackTraceResponse>>,
    },
    ListThreads {
        session_id: String,
        reply: oneshot::Sender<DebugResult<ListThreadsResponse>>,
    },
    SwitchThread {
        session_id: String,
        thread_id: u32,
        reply: oneshot::Sender<DebugResult<SwitchThreadResponse>>,
    },
    ReadMemory {
        session_id: String,
        address: String,
        length: u32,
        format: MemoryFormat,
        reply: oneshot::Sender<DebugResult<ReadMemoryResponse>>,
    },
    WriteMemory {
        session_id: String,
        address: String,
        data: String,
        reply: oneshot::Sender<DebugResult<WriteMemoryResponse>>,
    },
    SearchMemory {
        session_id: String,
        start_address: String,
        length: u64,
        pattern: String,
        max_results: u32,
        reply: oneshot::Sender<DebugResult<SearchMemoryResponse>>,
    },
    GetRegisters {
        session_id: String,
        registers: Vec<String>,
        reply: oneshot::Sender<DebugResult<GetRegistersResponse>>,
    },
    Disassemble {
        session_id: String,
        address: String,
        count: u32,
        reply: oneshot::Sender<DebugResult<DisassembleResponse>>,
    },
    ListModules {
        session_id: String,
        reply: oneshot::Sender<DebugResult<ListModulesResponse>>,
    },
    ResolveSymbol {
        session_id: String,
        symbol: Option<String>,
        address: Option<String>,
        reply: oneshot::Sender<DebugResult<ResolveSymbolResponse>>,
    },
    GetTypeInfo {
        session_id: String,
        module: String,
        type_name: String,
        reply: oneshot::Sender<DebugResult<GetTypeInfoResponse>>,
    },

    // Execution control
    SetBreakpoint {
        session_id: String,
        address: String,
        condition: Option<String>,
        reply: oneshot::Sender<DebugResult<SetBreakpointResponse>>,
    },
    RemoveBreakpoint {
        session_id: String,
        breakpoint_id: u32,
        reply: oneshot::Sender<DebugResult<RemoveBreakpointResponse>>,
    },
    Go {
        session_id: String,
        reply: oneshot::Sender<DebugResult<ExecutionControlResponse>>,
    },
    Step {
        session_id: String,
        step_type: StepType,
        reply: oneshot::Sender<DebugResult<StepResponse>>,
    },
    BreakExecution {
        session_id: String,
        reply: oneshot::Sender<DebugResult<ExecutionControlResponse>>,
    },

    // Shutdown
    Shutdown,
}

/// Handle to communicate with the debugger thread.
#[derive(Clone)]
pub struct DebuggerThread {
    sender: mpsc::Sender<DebugCommand>,
}

impl DebuggerThread {
    /// Spawn the debugger thread and return a handle to it.
    pub fn spawn(safety_config: SafetyConfig) -> (Self, JoinHandle<()>) {
        let (sender, receiver) = mpsc::channel::<DebugCommand>();

        let handle = thread::spawn(move || {
            debugger_thread_main(receiver, safety_config);
        });

        (Self { sender }, handle)
    }

    /// Send a command and wait for the result.
    fn send(&self, cmd: DebugCommand) {
        let _ = self.sender.send(cmd);
    }

    // Session management

    pub async fn open_dump(
        &self,
        path: PathBuf,
        symbol_path: Option<String>,
    ) -> DebugResult<SessionInfo> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::OpenDump {
            path,
            symbol_path,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn attach_process(&self, pid: u32, non_invasive: bool) -> DebugResult<SessionInfo> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::AttachProcess {
            pid,
            non_invasive,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn connect_remote(&self, connection_string: String) -> DebugResult<SessionInfo> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::ConnectRemote {
            connection_string,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn detach(&self, session_id: String) -> DebugResult<()> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::Detach {
            session_id,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn list_sessions(&self) -> Vec<SessionInfo> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::ListSessions { reply: tx });
        rx.await.unwrap_or_default()
    }

    // Debug operations

    pub async fn execute(
        &self,
        session_id: String,
        command: String,
    ) -> DebugResult<ExecuteCommandResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::Execute {
            session_id,
            command,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn analyze(&self, session_id: String, verbose: bool) -> DebugResult<AnalyzeResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::Analyze {
            session_id,
            verbose,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn get_stack_trace(
        &self,
        session_id: String,
        thread_id: Option<u32>,
        max_frames: u32,
    ) -> DebugResult<GetStackTraceResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::GetStackTrace {
            session_id,
            thread_id,
            max_frames,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn list_threads(&self, session_id: String) -> DebugResult<ListThreadsResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::ListThreads {
            session_id,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn switch_thread(
        &self,
        session_id: String,
        thread_id: u32,
    ) -> DebugResult<SwitchThreadResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::SwitchThread {
            session_id,
            thread_id,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn read_memory(
        &self,
        session_id: String,
        address: String,
        length: u32,
        format: MemoryFormat,
    ) -> DebugResult<ReadMemoryResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::ReadMemory {
            session_id,
            address,
            length,
            format,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn write_memory(
        &self,
        session_id: String,
        address: String,
        data: String,
    ) -> DebugResult<WriteMemoryResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::WriteMemory {
            session_id,
            address,
            data,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn search_memory(
        &self,
        session_id: String,
        start_address: String,
        length: u64,
        pattern: String,
        max_results: u32,
    ) -> DebugResult<SearchMemoryResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::SearchMemory {
            session_id,
            start_address,
            length,
            pattern,
            max_results,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn get_registers(
        &self,
        session_id: String,
        registers: Vec<String>,
    ) -> DebugResult<GetRegistersResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::GetRegisters {
            session_id,
            registers,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn disassemble(
        &self,
        session_id: String,
        address: String,
        count: u32,
    ) -> DebugResult<DisassembleResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::Disassemble {
            session_id,
            address,
            count,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn list_modules(&self, session_id: String) -> DebugResult<ListModulesResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::ListModules {
            session_id,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn resolve_symbol(
        &self,
        session_id: String,
        symbol: Option<String>,
        address: Option<String>,
    ) -> DebugResult<ResolveSymbolResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::ResolveSymbol {
            session_id,
            symbol,
            address,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn get_type_info(
        &self,
        session_id: String,
        module: String,
        type_name: String,
    ) -> DebugResult<GetTypeInfoResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::GetTypeInfo {
            session_id,
            module,
            type_name,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    // Execution control

    pub async fn set_breakpoint(
        &self,
        session_id: String,
        address: String,
        condition: Option<String>,
    ) -> DebugResult<SetBreakpointResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::SetBreakpoint {
            session_id,
            address,
            condition,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn remove_breakpoint(
        &self,
        session_id: String,
        breakpoint_id: u32,
    ) -> DebugResult<RemoveBreakpointResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::RemoveBreakpoint {
            session_id,
            breakpoint_id,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn go(&self, session_id: String) -> DebugResult<ExecutionControlResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::Go {
            session_id,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn step(&self, session_id: String, step_type: StepType) -> DebugResult<StepResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::Step {
            session_id,
            step_type,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub async fn break_execution(
        &self,
        session_id: String,
    ) -> DebugResult<ExecutionControlResponse> {
        let (tx, rx) = oneshot::channel();
        self.send(DebugCommand::BreakExecution {
            session_id,
            reply: tx,
        });
        rx.await.unwrap_or_else(|_| {
            Err(super::client::DebugError::DbgEng(
                "Debugger thread died".to_string(),
            ))
        })
    }

    pub fn shutdown(&self) {
        let _ = self.sender.send(DebugCommand::Shutdown);
    }
}

/// Main loop for the debugger thread.
fn debugger_thread_main(receiver: mpsc::Receiver<DebugCommand>, safety_config: SafetyConfig) {
    use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx};

    // Initialize COM on this thread
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }

    let manager = SessionManager::new(safety_config);

    tracing::info!("Debugger thread started");

    while let Ok(cmd) = receiver.recv() {
        match cmd {
            DebugCommand::OpenDump {
                path,
                symbol_path,
                reply,
            } => {
                let result = manager.open_dump(path, symbol_path);
                let _ = reply.send(result);
            }

            DebugCommand::AttachProcess {
                pid,
                non_invasive,
                reply,
            } => {
                let result = manager.attach_process(pid, non_invasive);
                let _ = reply.send(result);
            }

            DebugCommand::ConnectRemote {
                connection_string,
                reply,
            } => {
                let result = manager.connect_remote(&connection_string);
                let _ = reply.send(result);
            }

            DebugCommand::Detach { session_id, reply } => {
                let result = manager.close_session(&session_id);
                let _ = reply.send(result);
            }

            DebugCommand::ListSessions { reply } => {
                let result = manager.list_sessions();
                let _ = reply.send(result);
            }

            DebugCommand::Execute {
                session_id,
                command,
                reply,
            } => {
                let result = manager.with_session(&session_id, |s| s.execute_command(&command));
                let _ = reply.send(result);
            }

            DebugCommand::Analyze {
                session_id,
                verbose,
                reply,
            } => {
                let result = manager.with_session(&session_id, |s| s.analyze(verbose));
                let _ = reply.send(result);
            }

            DebugCommand::GetStackTrace {
                session_id,
                thread_id,
                max_frames,
                reply,
            } => {
                let result =
                    manager.with_session(&session_id, |s| s.get_stack_trace(thread_id, max_frames));
                let _ = reply.send(result);
            }

            DebugCommand::ListThreads { session_id, reply } => {
                let result = manager.with_session(&session_id, |s| s.get_threads());
                let _ = reply.send(result);
            }

            DebugCommand::SwitchThread {
                session_id,
                thread_id,
                reply,
            } => {
                let result = manager.with_session(&session_id, |s| s.switch_thread(thread_id));
                let _ = reply.send(result);
            }

            DebugCommand::ReadMemory {
                session_id,
                address,
                length,
                format,
                reply,
            } => {
                let result =
                    manager.with_session(&session_id, |s| s.read_memory(&address, length, format));
                let _ = reply.send(result);
            }

            DebugCommand::WriteMemory {
                session_id,
                address,
                data,
                reply,
            } => {
                let result = manager.with_session(&session_id, |s| s.write_memory(&address, &data));
                let _ = reply.send(result);
            }

            DebugCommand::SearchMemory {
                session_id,
                start_address,
                length,
                pattern,
                max_results,
                reply,
            } => {
                let result = manager.with_session(&session_id, |s| {
                    s.search_memory(&start_address, length, &pattern, max_results)
                });
                let _ = reply.send(result);
            }

            DebugCommand::GetRegisters {
                session_id,
                registers,
                reply,
            } => {
                let result = manager.with_session(&session_id, |s| s.get_registers(&registers));
                let _ = reply.send(result);
            }

            DebugCommand::Disassemble {
                session_id,
                address,
                count,
                reply,
            } => {
                let result = manager.with_session(&session_id, |s| s.disassemble(&address, count));
                let _ = reply.send(result);
            }

            DebugCommand::ListModules { session_id, reply } => {
                let result = manager.with_session(&session_id, |s| s.get_modules());
                let _ = reply.send(result);
            }

            DebugCommand::ResolveSymbol {
                session_id,
                symbol,
                address,
                reply,
            } => {
                let result = manager.with_session(&session_id, |s| {
                    let query = symbol.as_deref().or(address.as_deref()).unwrap_or("");
                    s.resolve_symbol(query)
                });
                let _ = reply.send(result);
            }

            DebugCommand::GetTypeInfo {
                session_id,
                module,
                type_name,
                reply,
            } => {
                let result =
                    manager.with_session(&session_id, |s| s.get_type_info(&module, &type_name));
                let _ = reply.send(result);
            }

            DebugCommand::SetBreakpoint {
                session_id,
                address,
                condition,
                reply,
            } => {
                let result = manager.with_session(&session_id, |s| {
                    s.set_breakpoint(&address, condition.as_deref())
                });
                let _ = reply.send(result);
            }

            DebugCommand::RemoveBreakpoint {
                session_id,
                breakpoint_id,
                reply,
            } => {
                let result =
                    manager.with_session(&session_id, |s| s.remove_breakpoint(breakpoint_id));
                let _ = reply.send(result);
            }

            DebugCommand::Go { session_id, reply } => {
                let result = manager.with_session(&session_id, |s| s.go());
                let _ = reply.send(result);
            }

            DebugCommand::Step {
                session_id,
                step_type,
                reply,
            } => {
                let result = manager.with_session(&session_id, |s| s.step(step_type));
                let _ = reply.send(result);
            }

            DebugCommand::BreakExecution { session_id, reply } => {
                let result = manager.with_session(&session_id, |s| s.break_execution());
                let _ = reply.send(result);
            }

            DebugCommand::Shutdown => {
                tracing::info!("Debugger thread shutting down");
                break;
            }
        }
    }
}
