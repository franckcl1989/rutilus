//! The third-party license inventory printed by `rutilus licenses` (§18.1).
//!
//! The inventory is embedded static data — one entry per third-party crate
//! in the workspace's direct dependency set — extracted from `Cargo.lock`
//! (resolved versions) and the crates' published license metadata, and
//! cross-checked against the `deny.toml` license allow list. Embedding keeps
//! the subcommand dependency-free and the output stable across builds; the
//! test suite re-checks every entry against the workspace `Cargo.lock` (so a
//! version bump without an inventory update fails CI) and against the
//! dependency tables of every workspace member manifest (so a new direct
//! dependency without an inventory entry fails CI too).

/// One third-party crate of the product.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThirdPartyLicense {
    /// The crates.io package name.
    pub name: &'static str,
    /// The resolved version recorded in `Cargo.lock`.
    pub version: &'static str,
    /// The published SPDX license expression of the crate.
    pub license: &'static str,
}

/// The direct third-party dependency inventory, sorted by crate name.
pub const THIRD_PARTY_LICENSES: &[ThirdPartyLicense] = &[
    ThirdPartyLicense {
        name: "argon2",
        version: "0.5.3",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "axum",
        version: "0.8.9",
        license: "MIT",
    },
    ThirdPartyLicense {
        name: "base32",
        version: "0.5.1",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "base64",
        version: "0.22.1",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "chacha20poly1305",
        version: "0.11.0",
        license: "Apache-2.0 OR MIT",
    },
    ThirdPartyLicense {
        name: "clap",
        version: "4.6.5",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "console",
        version: "0.16.4",
        license: "MIT",
    },
    ThirdPartyLicense {
        name: "csv",
        version: "1.4.0",
        license: "Unlicense/MIT",
    },
    ThirdPartyLicense {
        name: "fs4",
        version: "1.1.0",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "futures",
        version: "0.3.33",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "futures-util",
        version: "0.3.33",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "getrandom",
        version: "0.4.3",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "gloo-net",
        version: "0.6.0",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "hmac",
        version: "0.13.0",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "http-body-util",
        version: "0.1.4",
        license: "MIT",
    },
    ThirdPartyLicense {
        name: "leptos",
        version: "0.8.20",
        license: "MIT",
    },
    ThirdPartyLicense {
        name: "nv-redfish",
        version: "0.13.0",
        license: "Apache-2.0",
    },
    ThirdPartyLicense {
        name: "prost",
        version: "0.14.4",
        license: "Apache-2.0",
    },
    ThirdPartyLicense {
        name: "prost-build",
        version: "0.14.4",
        license: "Apache-2.0",
    },
    ThirdPartyLicense {
        name: "protoc-bin-vendored",
        version: "3.2.0",
        license: "MIT",
    },
    ThirdPartyLicense {
        name: "rcgen",
        version: "0.14.8",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "reqwest",
        version: "0.12.28",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "rust-embed",
        version: "8.11.0",
        license: "MIT",
    },
    ThirdPartyLicense {
        name: "rustls",
        version: "0.23.43",
        license: "Apache-2.0 OR ISC OR MIT",
    },
    ThirdPartyLicense {
        name: "rustls-native-certs",
        version: "0.8.4",
        license: "Apache-2.0 OR ISC OR MIT",
    },
    ThirdPartyLicense {
        name: "rustls-webpki",
        version: "0.103.13",
        license: "ISC",
    },
    ThirdPartyLicense {
        name: "sea-orm",
        version: "2.0.1",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "sea-orm-migration",
        version: "2.0.1",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "secrecy",
        version: "0.10.3",
        license: "Apache-2.0 OR MIT",
    },
    ThirdPartyLicense {
        name: "serde",
        version: "1.0.229",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "serde_json",
        version: "1.0.151",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "sha1",
        version: "0.11.0",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "sha2",
        version: "0.11.0",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "tempfile",
        version: "3.27.0",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "thiserror",
        version: "2.0.19",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "time",
        version: "0.3.55",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "tokio",
        version: "1.53.1",
        license: "MIT",
    },
    ThirdPartyLicense {
        name: "tokio-rustls",
        version: "0.26.4",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "tokio-tungstenite",
        version: "0.24.0",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "tokio-util",
        version: "0.7.19",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "tower",
        version: "0.5.3",
        license: "MIT",
    },
    ThirdPartyLicense {
        name: "tower-http",
        version: "0.6.11",
        license: "MIT",
    },
    ThirdPartyLicense {
        name: "url",
        version: "2.5.8",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "uuid",
        version: "1.24.0",
        license: "Apache-2.0 OR MIT",
    },
    ThirdPartyLicense {
        name: "wasm-bindgen",
        version: "0.2.126",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "wasm-bindgen-futures",
        version: "0.4.76",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "webbrowser",
        version: "1.2.4",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "windows-sys",
        version: "0.61.2",
        license: "MIT OR Apache-2.0",
    },
    ThirdPartyLicense {
        name: "zeroize",
        version: "1.9.0",
        license: "Apache-2.0 OR MIT",
    },
];

/// Prints every third-party license entry, one crate per line.
#[must_use]
pub fn licenses_text() -> String {
    let mut text = String::with_capacity(THIRD_PARTY_LICENSES.len() * 48);
    for entry in THIRD_PARTY_LICENSES {
        text.push_str(entry.name);
        text.push(' ');
        text.push_str(entry.version);
        text.push_str(" (");
        text.push_str(entry.license);
        text.push_str(")\n");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The workspace `Cargo.lock` at test time: the inventory must stay in
    /// lockstep with the resolved versions.
    const WORKSPACE_CARGO_LOCK: &str = include_str!("../../Cargo.lock");

    #[test]
    fn inventory_is_sorted_unique_and_complete() {
        let mut previous: Option<&str> = None;
        for entry in THIRD_PARTY_LICENSES {
            assert!(!entry.name.is_empty());
            assert!(!entry.version.is_empty());
            assert!(!entry.license.is_empty());
            if let Some(previous) = previous {
                assert!(entry.name > previous, "inventory must stay sorted");
                assert_ne!(entry.name, previous, "inventory must be unique");
            }
            previous = Some(entry.name);
        }
    }

    #[test]
    fn every_inventory_version_matches_the_workspace_lock() -> Result<(), String> {
        for entry in THIRD_PARTY_LICENSES {
            let locked = locked_version(entry.name).ok_or_else(|| {
                format!("inventory crate {} is missing from Cargo.lock", entry.name)
            })?;
            assert!(
                locked.iter().any(|version| version == entry.version),
                "inventory version {} for {} does not match Cargo.lock ({locked:?})",
                entry.version,
                entry.name
            );
        }
        Ok(())
    }

    #[test]
    fn licenses_output_lists_every_crate_on_its_own_line() {
        let text = licenses_text();
        for entry in THIRD_PARTY_LICENSES {
            assert!(
                text.contains(&format!(
                    "{} {} ({}",
                    entry.name, entry.version, entry.license
                )),
                "licenses output misses {}",
                entry.name
            );
        }
        assert_eq!(text.lines().count(), THIRD_PARTY_LICENSES.len());
    }

    /// Every workspace member manifest at test time, embedded so the direct
    /// dependency inventory can be cross-checked without a TOML parser. The
    /// workspace root `Cargo.toml` is deliberately excluded: its
    /// `[workspace.dependencies]` table declares versions, not the direct
    /// dependencies of any crate.
    const WORKSPACE_MEMBER_MANIFESTS: &[&str] = &[
        include_str!("../../api/Cargo.toml"),
        include_str!("../../app/Cargo.toml"),
        include_str!("../../application/Cargo.toml"),
        include_str!("../../center-protocol/Cargo.toml"),
        include_str!("../../domain/Cargo.toml"),
        include_str!("../../entity/Cargo.toml"),
        include_str!("../../infra-redfish/Cargo.toml"),
        include_str!("../../migration/Cargo.toml"),
        include_str!("../../operation-engine/Cargo.toml"),
        include_str!("../../persistence/Cargo.toml"),
        include_str!("../../platform/Cargo.toml"),
        include_str!("../../security/Cargo.toml"),
        include_str!("../../test-support/Cargo.toml"),
        include_str!("../../ui/Cargo.toml"),
        include_str!("../../web/Cargo.toml"),
    ];

    #[test]
    fn inventory_covers_exactly_the_direct_third_party_dependencies() {
        let inventory_names = THIRD_PARTY_LICENSES
            .iter()
            .map(|entry| entry.name)
            .collect::<std::collections::HashSet<_>>();
        let mut direct_names = Vec::new();
        for manifest in WORKSPACE_MEMBER_MANIFESTS {
            for name in direct_dependency_names(manifest) {
                if !name.starts_with("rutilus-") {
                    direct_names.push(name);
                }
            }
        }

        let mut missing = direct_names
            .iter()
            .copied()
            .filter(|name| !inventory_names.contains(name))
            .collect::<Vec<_>>();
        missing.sort_unstable();
        missing.dedup();
        assert!(
            missing.is_empty(),
            "the licenses inventory misses direct third-party dependencies: {missing:?}"
        );

        let mut orphaned = inventory_names
            .iter()
            .copied()
            .filter(|name| !direct_names.contains(name))
            .collect::<Vec<_>>();
        orphaned.sort_unstable();
        assert!(
            orphaned.is_empty(),
            "the licenses inventory names crates that are no longer direct dependencies: {orphaned:?}"
        );
    }

    /// The crate names declared in one manifest's dependency tables:
    /// `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]`, and
    /// the target-gated `[target.'cfg(...)'.dependencies]` variants. A
    /// single-line text scan suffices because the workspace writes every
    /// dependency on one line; a future wrapped entry fails the completeness
    /// test loudly, which is exactly the guard's purpose.
    fn direct_dependency_names(manifest: &str) -> Vec<&str> {
        let mut names = Vec::new();
        let mut in_dependency_table = false;
        for line in manifest.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_dependency_table = line.contains("dependencies");
                continue;
            }
            if !in_dependency_table {
                continue;
            }
            let Some(name) = line
                .split_once('=')
                .map(|(key, _)| key.trim())
                .map(|key| key.strip_suffix(".workspace").unwrap_or(key))
                .filter(|name| {
                    !name.is_empty()
                        && name.chars().all(|character| {
                            character.is_ascii_alphanumeric() || matches!(character, '_' | '-')
                        })
                })
            else {
                continue;
            };
            names.push(name);
        }
        names
    }

    /// All `version = "..."` values of one package in the lock file.
    fn locked_version(name: &str) -> Option<Vec<String>> {
        let mut versions = Vec::new();
        for block in WORKSPACE_CARGO_LOCK.split("[[package]]") {
            let block = block.trim();
            if !block.starts_with(&format!("name = \"{name}\"")) {
                continue;
            }
            for line in block.lines() {
                if let Some(value) = line
                    .trim()
                    .strip_prefix("version = \"")
                    .and_then(|value| value.strip_suffix('"'))
                {
                    versions.push(value.to_owned());
                }
            }
        }
        if versions.is_empty() {
            None
        } else {
            Some(versions)
        }
    }
}
