//! Safety configuration for the WinDbg MCP server.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Safety configuration controlling dangerous operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyConfig {
    /// Allow memory write operations
    #[serde(default)]
    pub allow_memory_write: bool,

    /// Allow register write operations
    #[serde(default)]
    pub allow_register_write: bool,

    /// Allow execution control (go, step, break)
    #[serde(default)]
    pub allow_execution_control: bool,

    /// Allow live process attach
    #[serde(default = "default_true")]
    pub allow_live_attach: bool,

    /// Allow command execution
    #[serde(default = "default_true")]
    pub allow_command_execution: bool,

    /// List of blocked commands (case-insensitive)
    #[serde(default = "default_blocked_commands")]
    pub blocked_commands: HashSet<String>,

    /// Maximum memory read size in bytes
    #[serde(default = "default_max_memory_read")]
    pub max_memory_read_size: u64,

    /// Maximum search memory range in bytes
    #[serde(default = "default_max_search_range")]
    pub max_search_range: u64,
}

fn default_true() -> bool {
    true
}

fn default_blocked_commands() -> HashSet<String> {
    let commands = [
        ".writemem",
        ".crash",
        ".reboot",
        ".kill",
        ".detach",
        "wrmsr",
        ".dump",
        ".write_cmd_hist",
        ".create",
        ".restart",
        ".ttime",
        "!process 0 0",
    ];
    commands.iter().map(|s| s.to_lowercase()).collect()
}

fn default_max_memory_read() -> u64 {
    16 * 1024 * 1024 // 16 MB
}

fn default_max_search_range() -> u64 {
    1024 * 1024 * 1024 // 1 GB
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            allow_memory_write: false,
            allow_register_write: false,
            allow_execution_control: false,
            allow_live_attach: true,
            allow_command_execution: true,
            blocked_commands: default_blocked_commands(),
            max_memory_read_size: default_max_memory_read(),
            max_search_range: default_max_search_range(),
        }
    }
}

impl SafetyConfig {
    /// Create a safety config that allows all operations (for advanced users).
    pub fn permissive() -> Self {
        Self {
            allow_memory_write: true,
            allow_register_write: true,
            allow_execution_control: true,
            allow_live_attach: true,
            allow_command_execution: true,
            blocked_commands: HashSet::new(),
            max_memory_read_size: u64::MAX,
            max_search_range: u64::MAX,
        }
    }

    /// Check if a command is allowed.
    pub fn is_command_allowed(&self, command: &str) -> Result<(), SafetyError> {
        if !self.allow_command_execution {
            return Err(SafetyError::CommandExecutionDisabled);
        }

        let command_lower = command.to_lowercase();
        let command_trimmed = command_lower.trim();

        // Check for blocked commands
        for blocked in &self.blocked_commands {
            if command_trimmed.starts_with(blocked) {
                return Err(SafetyError::BlockedCommand(blocked.clone()));
            }
        }

        // Additional safety checks for dangerous patterns
        if !self.allow_memory_write
            && command_trimmed.starts_with("e")
            && (command_trimmed.starts_with("eb ")
                || command_trimmed.starts_with("ew ")
                || command_trimmed.starts_with("ed ")
                || command_trimmed.starts_with("eq ")
                || command_trimmed.starts_with("ea ")
                || command_trimmed.starts_with("eu ")
                || command_trimmed.starts_with("eza ")
                || command_trimmed.starts_with("ezu "))
        {
            return Err(SafetyError::MemoryWriteDisabled);
        }

        if !self.allow_register_write
            && command_trimmed.starts_with("r ")
            && command_trimmed.contains('=')
        {
            return Err(SafetyError::RegisterWriteDisabled);
        }

        if !self.allow_execution_control {
            let exec_commands = ["g", "t", "p", "gu", "pc", "tc", "wt"];
            for exec_cmd in exec_commands {
                if command_trimmed == exec_cmd
                    || command_trimmed.starts_with(&format!("{} ", exec_cmd))
                {
                    return Err(SafetyError::ExecutionControlDisabled);
                }
            }
        }

        Ok(())
    }

    /// Check if memory write is allowed.
    pub fn check_memory_write(&self) -> Result<(), SafetyError> {
        if !self.allow_memory_write {
            return Err(SafetyError::MemoryWriteDisabled);
        }
        Ok(())
    }

    /// Check if memory read size is within limits.
    pub fn check_memory_read_size(&self, size: u64) -> Result<(), SafetyError> {
        if size > self.max_memory_read_size {
            return Err(SafetyError::MemoryReadTooLarge {
                requested: size,
                max: self.max_memory_read_size,
            });
        }
        Ok(())
    }

    /// Check if search range is within limits.
    pub fn check_search_range(&self, range: u64) -> Result<(), SafetyError> {
        if range > self.max_search_range {
            return Err(SafetyError::SearchRangeTooLarge {
                requested: range,
                max: self.max_search_range,
            });
        }
        Ok(())
    }

    /// Check if execution control is allowed.
    pub fn check_execution_control(&self) -> Result<(), SafetyError> {
        if !self.allow_execution_control {
            return Err(SafetyError::ExecutionControlDisabled);
        }
        Ok(())
    }

    /// Check if live attach is allowed.
    pub fn check_live_attach(&self) -> Result<(), SafetyError> {
        if !self.allow_live_attach {
            return Err(SafetyError::LiveAttachDisabled);
        }
        Ok(())
    }
}

/// Safety-related errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SafetyError {
    #[error("Command execution is disabled")]
    CommandExecutionDisabled,

    #[error("Command '{0}' is blocked by safety policy")]
    BlockedCommand(String),

    #[error("Memory write operations are disabled")]
    MemoryWriteDisabled,

    #[error("Register write operations are disabled")]
    RegisterWriteDisabled,

    #[error("Execution control is disabled")]
    ExecutionControlDisabled,

    #[error("Live process attach is disabled")]
    LiveAttachDisabled,

    #[error("Memory read size {requested} exceeds maximum {max}")]
    MemoryReadTooLarge { requested: u64, max: u64 },

    #[error("Search range {requested} exceeds maximum {max}")]
    SearchRangeTooLarge { requested: u64, max: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SafetyConfig::default();
        assert!(!config.allow_memory_write);
        assert!(!config.allow_register_write);
        assert!(!config.allow_execution_control);
        assert!(config.allow_live_attach);
        assert!(config.allow_command_execution);
    }

    #[test]
    fn test_blocked_commands() {
        let config = SafetyConfig::default();
        assert!(config.is_command_allowed(".writemem foo").is_err());
        assert!(config.is_command_allowed(".crash").is_err());
        assert!(config.is_command_allowed("k").is_ok());
        assert!(config.is_command_allowed("lm").is_ok());
    }

    #[test]
    fn test_memory_write_commands() {
        let config = SafetyConfig::default();
        assert!(config.is_command_allowed("eb 12345 90").is_err());
        assert!(config.is_command_allowed("ed 12345 0").is_err());

        let permissive = SafetyConfig::permissive();
        assert!(permissive.is_command_allowed("eb 12345 90").is_ok());
    }

    #[test]
    fn test_execution_control() {
        let config = SafetyConfig::default();
        assert!(config.is_command_allowed("g").is_err());
        assert!(config.is_command_allowed("t").is_err());
        assert!(config.is_command_allowed("p").is_err());

        let permissive = SafetyConfig::permissive();
        assert!(permissive.is_command_allowed("g").is_ok());
    }
}
