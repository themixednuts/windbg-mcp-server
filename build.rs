use std::path::Path;

fn main() {
    // Link against the Windows SDK debugger libraries instead of the system ones.
    // This ensures we use the full-featured dbgeng.dll that supports remote debugging,
    // not the stripped-down System32 version.

    let sdk_lib_paths = [
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\lib\x64",
        r"C:\Program Files\Windows Kits\10\Debuggers\lib\x64",
    ];

    let sdk_dll_paths = [
        r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64",
        r"C:\Program Files\Windows Kits\10\Debuggers\x64",
    ];

    // Set link search path
    for path in &sdk_lib_paths {
        if Path::new(path).exists() {
            println!("cargo:rustc-link-search={}", path);
            println!("cargo:warning=Using debugger libs from: {}", path);
            break;
        }
    }

    // Copy DLLs to output directory
    let out_dir = std::env::var("OUT_DIR").unwrap_or_default();
    // OUT_DIR is like target/release/build/xxx/out, we need target/release
    let target_dir = Path::new(&out_dir)
        .ancestors()
        .nth(3)
        .unwrap_or(Path::new("."));

    let dlls = [
        "dbgeng.dll",
        "dbghelp.dll",
        "dbgcore.dll",
        "dbgmodel.dll",
        "dbgsrv.exe",
    ];

    for sdk_path in &sdk_dll_paths {
        let sdk_dir = Path::new(sdk_path);
        if sdk_dir.exists() {
            for dll in &dlls {
                let src = sdk_dir.join(dll);
                let dst = target_dir.join(dll);
                if src.exists() && !dst.exists() {
                    if let Err(e) = std::fs::copy(&src, &dst) {
                        println!("cargo:warning=Failed to copy {}: {}", dll, e);
                    } else {
                        println!("cargo:warning=Copied {} to {}", dll, dst.display());
                    }
                }
            }
            break;
        }
    }
}
