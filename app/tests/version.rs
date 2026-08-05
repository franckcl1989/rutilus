use std::process::Command;

#[test]
fn version_reports_product_and_upstream_baseline() -> std::io::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_rutilus"))
        .arg("version")
        .output()?;

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        output.stdout,
        b"rutilus 0.1.0\nnv-redfish development baseline 0.13.0\n"
    );

    Ok(())
}
