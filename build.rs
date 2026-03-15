fn main() {
    // Only build on Windows
    #[cfg(not(windows))]
    compile_error!("This crate only supports Windows");

    #[cfg(windows)]
    {
        // Find Windows SDK debugger library path
        let lib_paths = [
            r"C:\Program Files (x86)\Windows Kits\10\Debuggers\lib\x64",
            r"C:\Program Files\Windows Kits\10\Debuggers\lib\x64",
        ];

        for path in &lib_paths {
            if std::path::Path::new(path).exists() {
                println!("cargo:rustc-link-search={}", path);
                break;
            }
        }

        // Re-run if these change
        println!("cargo:rerun-if-env-changed=WindowsSdkDir");
    }
}
