use std::process::Command;

/// The `--log-format` flag is a global CLI option: it is accepted in any
/// position, and the JSON layer only changes the stderr diagnostics — the
/// user-facing stdout output of a command stays byte-identical (the version
/// command emits no diagnostics, so stderr stays empty either way).
#[test]
fn json_log_format_is_accepted_and_keeps_user_visible_output() -> std::io::Result<()> {
    for argv in [
        vec!["--log-format", "json", "version"],
        vec!["version", "--log-format", "json"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rutilus"))
            .args(argv)
            .output()?;
        assert!(output.status.success());
        assert_eq!(
            output.stdout,
            b"rutilus 0.1.0\nnv-redfish development baseline 0.13.0\n"
        );
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
