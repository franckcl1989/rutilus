use std::process::Command;

/// The `--log-format` flag is a global CLI option: it is accepted in any
/// position, and the JSON layer only changes the stderr diagnostics — the
/// user-facing stdout output of a command stays byte-identical (the version
/// command emits no diagnostics, so stderr stays empty either way).
#[test]
fn json_log_format_is_accepted_and_keeps_user_visible_output() -> std::io::Result<()> {
    // Derived from the same single sources as the binary: the workspace
    // `[workspace.package] version` and the infra-redfish upstream-baseline
    // constant (§7.2-A unified versioning), so a version bump needs no
    // test edit.
    let expected_stdout = format!(
        "rutilus {}\nnv-redfish development baseline {}\n",
        env!("CARGO_PKG_VERSION"),
        rutilus_infra_redfish::NV_REDFISH_DEVELOPMENT_BASELINE
    );
    for argv in [
        vec!["--log-format", "json", "version"],
        vec!["version", "--log-format", "json"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rutilus"))
            .args(argv)
            .output()?;
        assert!(output.status.success());
        assert_eq!(output.stdout, expected_stdout.as_bytes());
        assert!(output.stderr.is_empty());
    }

    Ok(())
}

/// An unknown format is rejected at parse time, before any command runs.
#[test]
fn unknown_log_formats_are_rejected() -> std::io::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_rutilus"))
        .args(["--log-format", "yaml", "version"])
        .output()?;
    assert!(!output.status.success());

    Ok(())
}
