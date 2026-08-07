//! Compiles `proto/rutilus/center/v1/center.proto` with the `protoc` binary
//! that `protoc-bin-vendored` ships inside the crate, so the build needs no
//! system `protoc` and no C++ toolchain (design §8).
//!
//! `prost-build` 0.14 locates the compiler through
//! `Config::protoc_executable`; no environment variable is set, because
//! `std::env::set_var` is unsafe in edition 2024 and this workspace forbids
//! `unsafe_code`.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    // Every generated message and enum derives serde, so a `center-protocol`
    // envelope is a §9.4 typed JSON payload: the outbox and inbox payload
    // columns store `serde_json` of the real wire type, never hand-written
    // JSON (the `TypedPayloadJson` rule of design §17, D4).
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    config.compile_protos(&["proto/rutilus/center/v1/center.proto"], &["proto"])?;
    Ok(())
}
