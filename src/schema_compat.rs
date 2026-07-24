//! JSON Schema compatibility helpers for MCP clients (OpenCode / AJV).
//!
//! schemars emits non-standard `format` values (`uint32`, `uint64`, …) for Rust
//! integer types. AJV warns on those as "unknown format". Strip them while
//! keeping `type` / `minimum` / `maximum`.

use schemars::Schema;
use schemars::transform::transform_subschemas;

/// Recursive schemars transform: remove OpenCode-incompatible integer formats.
pub fn strip_nonstandard_formats(schema: &mut Schema) {
    if let Some(obj) = schema.as_object_mut() {
        let drop_format = obj
            .get("format")
            .and_then(|v| v.as_str())
            .is_some_and(|fmt| {
                matches!(
                    fmt,
                    "uint" | "uint8"
                        | "uint16"
                        | "uint32"
                        | "uint64"
                        | "int8"
                        | "int16"
                        | "int32"
                        | "int64"
                )
            });
        if drop_format {
            obj.remove("format");
        }
    }

    transform_subschemas(&mut strip_nonstandard_formats, schema);
}
