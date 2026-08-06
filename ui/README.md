# Rutilus browser UI

This crate is the Leptos CSR application embedded by `rutilus-web`. The final
product does not load UI code from a CDN or require a separate Web server.

The checked-in `web/assets/rutilus_ui.js` and
`web/assets/rutilus_ui_bg.wasm` files are generated artifacts. Do not edit
them by hand. Regenerate them from the repository root with the same Rust
toolchain selected by `rust-toolchain.toml`:

```text
rustup target add wasm32-unknown-unknown
cargo build --locked -p rutilus-ui --target wasm32-unknown-unknown --release
cargo install wasm-bindgen-cli --version 0.2.126 --locked --root target/rutilus-tools
```

On Windows, generate the Web bindings with:

```text
target\rutilus-tools\bin\wasm-bindgen.exe --target web --no-typescript --out-dir web\assets --out-name rutilus_ui target\wasm32-unknown-unknown\release\rutilus_ui.wasm
```

On macOS or Linux, use the equivalent path separators:

```text
target/rutilus-tools/bin/wasm-bindgen --target web --no-typescript --out-dir web/assets --out-name rutilus_ui target/wasm32-unknown-unknown/release/rutilus_ui.wasm
```

The `wasm-bindgen-cli` version must remain identical to the workspace
`wasm-bindgen` version. After regeneration, run the complete workspace quality
gate and verify that a second generation produces byte-identical JavaScript
and WebAssembly files.
