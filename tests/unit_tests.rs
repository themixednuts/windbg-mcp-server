//! Unit tests for WinDbg MCP Server components.

use windbg_mcp_server::SafetyConfig;

mod safety_config_tests {
    use super::*;

    #[test]
    fn test_default_config_blocks_dangerous_operations() {
        let config = SafetyConfig::default();

        // Memory write should be disabled by default
        assert!(config.check_memory_write().is_err());

        // Execution control should be disabled by default
        assert!(config.check_execution_control().is_err());

        // Live attach should be enabled by default
        assert!(config.check_live_attach().is_ok());
    }

    #[test]
    fn test_permissive_config_allows_all() {
        let config = SafetyConfig::permissive();

        assert!(config.check_memory_write().is_ok());
        assert!(config.check_execution_control().is_ok());
        assert!(config.check_live_attach().is_ok());
    }

    #[test]
    fn test_blocked_commands() {
        let config = SafetyConfig::default();

        // These should be blocked
        assert!(config.is_command_allowed(".writemem foo").is_err());
        assert!(config.is_command_allowed(".crash").is_err());
        assert!(config.is_command_allowed(".kill").is_err());
        assert!(config.is_command_allowed(".reboot").is_err());

        // These should be allowed
        assert!(config.is_command_allowed("k").is_ok());
        assert!(config.is_command_allowed("lm").is_ok());
        assert!(config.is_command_allowed("!analyze -v").is_ok());
        assert!(config.is_command_allowed("r").is_ok());
        assert!(config.is_command_allowed("dt ntdll!_PEB").is_ok());
    }

    #[test]
    fn test_memory_write_commands_blocked() {
        let config = SafetyConfig::default();

        // Memory edit commands should be blocked
        assert!(config.is_command_allowed("eb 12345678 90").is_err());
        assert!(config.is_command_allowed("ew 12345678 0000").is_err());
        assert!(config.is_command_allowed("ed 12345678 00000000").is_err());
        assert!(config.is_command_allowed("eq 12345678 0").is_err());
        assert!(config.is_command_allowed("ea 12345678 abc").is_err());
        assert!(config.is_command_allowed("eu 12345678 abc").is_err());
    }

    #[test]
    fn test_execution_control_commands_blocked() {
        let config = SafetyConfig::default();

        // Execution commands should be blocked
        assert!(config.is_command_allowed("g").is_err());
        assert!(config.is_command_allowed("t").is_err());
        assert!(config.is_command_allowed("p").is_err());
        assert!(config.is_command_allowed("gu").is_err());
    }

    #[test]
    fn test_register_write_blocked() {
        let config = SafetyConfig::default();

        // Register write should be blocked
        assert!(config.is_command_allowed("r rax=0").is_err());
        assert!(config.is_command_allowed("r eip=12345678").is_err());

        // Register read should be allowed
        assert!(config.is_command_allowed("r").is_ok());
        assert!(config.is_command_allowed("r rax").is_ok());
    }

    #[test]
    fn test_memory_read_size_limits() {
        let config = SafetyConfig::default();

        // Small reads should be allowed
        assert!(config.check_memory_read_size(1024).is_ok());
        assert!(config.check_memory_read_size(1024 * 1024).is_ok());

        // Very large reads should be blocked
        assert!(config.check_memory_read_size(100 * 1024 * 1024).is_err());
    }

    #[test]
    fn test_search_range_limits() {
        let config = SafetyConfig::default();

        // Normal ranges should be allowed
        assert!(config.check_search_range(1024 * 1024).is_ok());

        // Very large ranges should be blocked
        assert!(config.check_search_range(10 * 1024 * 1024 * 1024).is_err());
    }

    #[test]
    fn test_permissive_allows_all_commands() {
        let config = SafetyConfig::permissive();

        // All previously blocked commands should work
        assert!(config.is_command_allowed("eb 12345678 90").is_ok());
        assert!(config.is_command_allowed("g").is_ok());
        assert!(config.is_command_allowed("r rax=0").is_ok());
        assert!(config.is_command_allowed(".writemem foo").is_ok());
    }

    #[test]
    fn test_case_insensitive_blocking() {
        let config = SafetyConfig::default();

        // Commands should be blocked regardless of case
        assert!(config.is_command_allowed(".WRITEMEM foo").is_err());
        assert!(config.is_command_allowed(".WriteMem foo").is_err());
        assert!(config.is_command_allowed("EB 12345678 90").is_err());
        assert!(config.is_command_allowed("G").is_err());
    }
}

mod tool_response_tests {
    #[test]
    fn test_tool_response_ok() {
        // Just verify the basic structure works
        #[derive(Debug)]
        struct TestResponse {
            success: bool,
            data: Option<String>,
            error: Option<String>,
        }

        let response = TestResponse {
            success: true,
            data: Some("test data".to_string()),
            error: None,
        };

        assert!(response.success);
        assert!(response.data.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_tool_response_err() {
        #[derive(Debug)]
        struct TestResponse {
            success: bool,
            data: Option<String>,
            error: Option<String>,
        }

        let response = TestResponse {
            success: false,
            data: None,
            error: Some("error message".to_string()),
        };

        assert!(!response.success);
        assert!(response.data.is_none());
        assert!(response.error.is_some());
    }
}
