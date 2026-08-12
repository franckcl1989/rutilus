use std::process::Command;

/// The build git commit the binary embeds (§5.4), derived the same way the
/// binary itself derives it: `RUTILUS_GIT_COMMIT` when CI injected it, the
/// `dev` fallback otherwise. The binary and this test compile in the same
/// build under the same environment, so their embedded values always agree
/// and the assertion below holds on both paths.
const EMBEDDED_GIT_COMMIT: &str = match option_env!("RUTILUS_GIT_COMMIT") {
    Some(commit) => commit,
    None => "dev",
};

#[test]
fn version_reports_product_and_upstream_baseline() -> std::io::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_rutilus"))
        .arg("version")
        .output()?;

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    // All three lines derive from their single sources instead of
    // hardcoded strings: the product version from the workspace
    // `[workspace.package] version` (§7.2-A unified versioning), the
    // upstream baseline from the infra-redfish constant, and the build git
    // commit from the compile-time `RUTILUS_GIT_COMMIT` — a release bump
    // needs no test edit.
    assert_eq!(
        output.stdout,
        format!(
            "rutilus {}\nnv-redfish development baseline {}\ngit commit {}\n",
            env!("CARGO_PKG_VERSION"),
            rutilus_infra_redfish::NV_REDFISH_DEVELOPMENT_BASELINE,
            EMBEDDED_GIT_COMMIT
        )
        .into_bytes()
    );

    Ok(())
}
