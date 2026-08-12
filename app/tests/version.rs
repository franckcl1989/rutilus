use std::process::Command;

#[test]
fn version_reports_product_and_upstream_baseline() -> std::io::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_rutilus"))
        .arg("version")
        .output()?;

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    // Both lines derive from their single sources instead of hardcoded
    // strings: the product version from the workspace
    // `[workspace.package] version` (§7.2-A unified versioning) and the
    // upstream baseline from the infra-redfish constant — a release bump
    // needs no test edit.
    assert_eq!(
        output.stdout,
        format!(
            "rutilus {}\nnv-redfish development baseline {}\n",
            env!("CARGO_PKG_VERSION"),
            rutilus_infra_redfish::NV_REDFISH_DEVELOPMENT_BASELINE
        )
        .into_bytes()
    );

    Ok(())
}
