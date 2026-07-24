//! Stdio process lifetime guards.
//!
//! MCP hosts sometimes drop the child `Process` handle without closing stdio or
//! calling TerminateProcess. A reconnect then spawns another server while the
//! previous one keeps running. These helpers reclaim same-parent siblings on
//! startup and exit when the parent process dies.

#[cfg(windows)]
mod windows_impl {
    use std::path::{Path, PathBuf};
    use tracing::{info, warn};
    use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        CreateMutexW, GetCurrentProcessId, OpenMutexW, OpenProcess, QueryFullProcessImageNameW,
        ReleaseMutex, TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, PROCESS_TERMINATE, SYNCHRONIZATION_SYNCHRONIZE,
    };
    use windows::core::{PCWSTR, PWSTR};

    #[derive(Debug, Clone)]
    struct ProcessRow {
        pid: u32,
        parent_pid: u32,
    }

    fn snapshot_processes() -> Vec<ProcessRow> {
        let mut rows = Vec::new();
        let snap = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
            Ok(h) => h,
            Err(_) => return rows,
        };

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        unsafe {
            if Process32FirstW(snap, &mut entry).is_ok() {
                loop {
                    rows.push(ProcessRow {
                        pid: entry.th32ProcessID,
                        parent_pid: entry.th32ParentProcessID,
                    });
                    if Process32NextW(snap, &mut entry).is_err() {
                        break;
                    }
                }
            }
            let _ = CloseHandle(snap);
        }

        rows
    }

    pub fn parent_pid() -> Option<u32> {
        let me = unsafe { GetCurrentProcessId() };
        snapshot_processes()
            .into_iter()
            .find(|row| row.pid == me)
            .map(|row| row.parent_pid)
    }

    fn process_image_path(pid: u32) -> Option<PathBuf> {
        let access = PROCESS_QUERY_LIMITED_INFORMATION;
        let handle = unsafe { OpenProcess(access, false, pid).ok()? };
        let path = (|| {
            let mut buf = vec![0u16; 1024];
            let mut size = buf.len() as u32;
            unsafe {
                QueryFullProcessImageNameW(handle, Default::default(), PWSTR(buf.as_mut_ptr()), &mut size)
                    .ok()?;
            }
            let path = String::from_utf16_lossy(&buf[..size as usize]);
            Some(PathBuf::from(path))
        })();
        unsafe {
            let _ = CloseHandle(handle);
        }
        path
    }

    fn paths_equal(a: &Path, b: &Path) -> bool {
        match (a.canonicalize(), b.canonicalize()) {
            (Ok(a), Ok(b)) => a == b,
            _ => {
                let a = a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy());
                a
            }
        }
    }

    fn terminate_pid(pid: u32) -> bool {
        let access = PROCESS_TERMINATE | PROCESS_SYNCHRONIZE;
        let handle = match unsafe { OpenProcess(access, false, pid) } {
            Ok(h) => h,
            Err(_) => return false,
        };
        let ok = unsafe { TerminateProcess(handle, 1).is_ok() };
        unsafe {
            let _ = CloseHandle(handle);
        }
        ok
    }

    fn transport_mutex_name(kind: &str, pid: u32) -> Vec<u16> {
        let name = format!("Local\\windbg-mcp-transport-{kind}-{pid}");
        let mut wide: Vec<u16> = name.encode_utf16().collect();
        wide.push(0);
        wide
    }

    fn transport_mutex_exists(kind: &str, pid: u32) -> bool {
        let wide = transport_mutex_name(kind, pid);
        match unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, false, PCWSTR(wide.as_ptr())) } {
            Ok(handle) => {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                true
            }
            Err(_) => false,
        }
    }

    /// Hold a per-pid transport marker so sibling reclaim can skip HTTP servers.
    pub struct TransportMarker {
        handle: HANDLE,
    }

    impl TransportMarker {
        pub fn acquire(kind: &str) -> Option<Self> {
            let pid = unsafe { GetCurrentProcessId() };
            let wide = transport_mutex_name(kind, pid);
            let handle =
                unsafe { CreateMutexW(None, true, PCWSTR(wide.as_ptr())).ok()? };
            Some(Self { handle })
        }
    }

    impl Drop for TransportMarker {
        fn drop(&mut self) {
            unsafe {
                let _ = ReleaseMutex(self.handle);
                let _ = CloseHandle(self.handle);
            }
        }
    }

    /// Kill older stdio instances spawned by the same parent (typical MCP reconnect leak).
    pub fn reclaim_stale_stdio_siblings() {
        let me = unsafe { GetCurrentProcessId() };
        let Some(parent) = parent_pid() else {
            return;
        };
        let Some(my_exe) = process_image_path(me) else {
            return;
        };

        let mut reclaimed = 0u32;
        for row in snapshot_processes() {
            if row.pid == me || row.parent_pid != parent {
                continue;
            }
            let Some(exe) = process_image_path(row.pid) else {
                continue;
            };
            if !paths_equal(&exe, &my_exe) {
                continue;
            }
            // Never reclaim an HTTP sibling sharing the same parent shell.
            if transport_mutex_exists("http", row.pid) {
                continue;
            }
            if terminate_pid(row.pid) {
                reclaimed += 1;
                info!(
                    pid = row.pid,
                    parent,
                    "Reclaimed stale windbg-mcp-server sibling from same parent"
                );
            } else {
                warn!(pid = row.pid, "Failed to reclaim stale windbg-mcp-server sibling");
            }
        }

        if reclaimed > 0 {
            info!(reclaimed, "Stdio sibling reclaim complete");
        }
    }

    /// Resolves when the parent process exits (or is already gone).
    pub async fn wait_for_parent_exit() {
        let Some(parent) = parent_pid() else {
            return;
        };

        let handle = match unsafe {
            OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, false, parent)
        } {
            Ok(h) => h,
            Err(_) => {
                // Parent already gone — treat as exit signal.
                return;
            }
        };

        // HANDLE isn't Send; move the raw value across the thread boundary.
        let handle_bits = handle.0 as usize;
        let wait_result = tokio::task::spawn_blocking(move || {
            let handle = windows::Win32::Foundation::HANDLE(handle_bits as *mut core::ffi::c_void);
            let result = unsafe { WaitForSingleObject(handle, u32::MAX) };
            unsafe {
                let _ = CloseHandle(handle);
            }
            result
        })
        .await;

        match wait_result {
            Ok(WAIT_OBJECT_0) => {}
            Ok(other) => warn!(?other, parent, "Unexpected WaitForSingleObject result for parent"),
            Err(err) => warn!(%err, parent, "Parent-wait task failed"),
        }
    }
}

#[cfg(windows)]
pub use windows_impl::{
    TransportMarker, parent_pid, reclaim_stale_stdio_siblings, wait_for_parent_exit,
};

#[cfg(not(windows))]
pub struct TransportMarker;

#[cfg(not(windows))]
impl TransportMarker {
    pub fn acquire(_kind: &str) -> Option<Self> {
        Some(Self)
    }
}

#[cfg(not(windows))]
pub fn reclaim_stale_stdio_siblings() {}

#[cfg(not(windows))]
pub async fn wait_for_parent_exit() {
    std::future::pending::<()>().await;
}
