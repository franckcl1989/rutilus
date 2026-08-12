//! UI string catalog (i18n foundation, design §5.1).
//!
//! This iteration ships the complete English catalog as typed fields of a
//! single [`Strings`] struct, the [`Lang`] skeleton, and the console-wide
//! [`L`] instance. The copy no longer lives as scattered literals inside
//! `view!` templates: every extracted string is one named field, so the
//! compiler checks every reference and a future language only has to
//! provide the same field list (the exhaustive constructor refuses to
//! compile otherwise).
//!
//! Design decisions for this iteration:
//!
//! * Copy is static per build — nothing in the console changes a string at
//!   runtime — so the catalog is a `const` instance (`L`) read directly in
//!   view templates as `{L.nav_overview}` instead of a reactive signal or
//!   context. The future language selector only has to switch which
//!   `Strings` value the views read; the templates themselves stay as they
//!   are.
//! * The [`Lang`] skeleton keeps the selection entry point (`Lang::strings`)
//!   without a UI selector yet. A `Translations` trait adds nothing while
//!   only one language exists, so it is deliberately deferred.
//!
//! The `strings_catalog!` macro below is the single source of truth: it
//! declares the struct fields, the English constructor, and the
//! `(key, value)` table the well-formedness test enumerates, so adding a
//! key can never leave the completeness test behind.

/// Declares the [`Strings`] struct from one key/value list.
///
/// Every entry becomes a `pub(crate)` field of `&'static str` with its doc
/// comment, an arm of the English constructor, and a `(field name, value)`
/// row of [`EN_ENTRIES`]. Keeping the three in one place means the catalog
/// completeness test always covers exactly the fields the views can read.
macro_rules! strings_catalog {
    (
        $(
            $(#[$field_meta:meta])*
            $field:ident: $value:literal
        ),+ $(,)?
    ) => {
        /// The UI string catalog: one field per copy key.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(crate) struct Strings {
            $( $(#[$field_meta])* pub(crate) $field: &'static str ),+
        }

        impl Strings {
            /// The complete English catalog.
            pub const fn en() -> Self {
                Self {
                    $($field: $value),+
                }
            }
        }

        /// Every catalog key with its English value, for the
        /// well-formedness tests. Test-only: the wasm build never reads it.
        #[cfg(test)]
        pub(crate) const EN_ENTRIES: &[(&str, &str)] = &[
            $((stringify!($field), $value)),+
        ];
    };
}

strings_catalog! {
    /// The Overview console section (§12.1).
    nav_overview: "Overview",
    /// The Groups console section (§12.1).
    nav_groups: "Groups",
    /// The Credentials console section (§12.1).
    nav_credentials: "Credentials",
    /// The Add endpoint console section (§12.1).
    nav_add_endpoint: "Add endpoint",
    /// The Import console section (§12.1).
    nav_import: "Import",
    /// The Audit console section (§12.1).
    nav_audit: "Audit",
    /// The Capabilities console section (§12.1).
    nav_capabilities: "Capabilities",
    /// The Operations console section (§12.1).
    nav_operations: "Operations",
    /// The Events console section (§12.1).
    nav_events: "Events",
    /// The Artifacts console section (§12.1).
    nav_artifacts: "Artifacts",
    /// The Telemetry console section (§12.1).
    nav_telemetry: "Telemetry",
    /// The Diagnostics console section (§12.1).
    nav_diagnostics: "Diagnostics",
    /// The Users console section (§12.1).
    nav_users: "Users",
    /// The Sessions console section (§12.1).
    nav_sessions: "Sessions",
    /// The Center sites console section (§12.1).
    nav_center_sites: "Center sites",
    /// The Center operations console section (§12.1).
    nav_center_operations: "Center operations",
    /// The Center bindings console section (§12.1).
    nav_center_bindings: "Center bindings",

    /// The §16.1 Administrator role.
    role_administrator: "Administrator",
    /// The §16.1 Operator role.
    role_operator: "Operator",
    /// The §16.1 Viewer role.
    role_viewer: "Viewer",

    /// The product eyebrow of the auth screens and the console header.
    header_eyebrow: "Local Redfish management",
    /// The console scope status of the Center posture.
    header_center_console: "Center aggregation console",
    /// The navigation bar's accessibility label.
    header_nav_aria: "Console sections",
    /// The console status while the initial data load runs.
    header_status_loading: "Starting the local management console...",
    /// The console status of a fully loaded local inventory.
    header_status_ready: "Authenticated local inventory",
    /// The console status when the product metadata could not be verified.
    header_status_failed_metadata: "The local console could not verify product metadata.",
    /// The console status when the endpoint inventory is unavailable.
    header_status_failed_inventory: "The endpoint inventory is temporarily unavailable.",
    /// The console status when the core resource details are unavailable.
    header_status_failed_resources: "Core resource details are temporarily unavailable.",

    /// The sign-in screen heading and submit button.
    auth_sign_in: "Sign in",
    /// The sign-in TOTP field label.
    auth_totp_code: "TOTP code (if enrolled)",
    /// The sign-in TOTP input placeholder.
    auth_totp_placeholder: "6 digits",

    /// The refresh action button.
    action_refresh: "Refresh",
    /// The enable action button.
    action_enable: "Enable",
    /// The disable action button.
    action_disable: "Disable",
    /// The delete action button.
    action_delete: "Delete",
    /// The cancel action button.
    action_cancel: "Cancel",
    /// The back action button.
    action_back: "Back",
    /// The sign-out button of the console header.
    action_sign_out: "Sign out",

    /// The queued operation phase badge.
    state_queued: "Queued",
    /// The validating operation phase badge.
    state_validating: "Validating",
    /// The running operation phase badge.
    state_running: "Running",
    /// The waiting-for-BMC operation phase badge.
    state_waiting_bmc: "Waiting for BMC",
    /// The verifying operation phase badge.
    state_verifying: "Verifying",
    /// The succeeded operation phase badge.
    state_succeeded: "Succeeded",
    /// The failed operation phase badge.
    state_failed: "Failed",
    /// The unknown operation phase badge.
    state_unknown: "Unknown",
    /// The cancelled operation phase badge.
    state_cancelled: "Cancelled",
    /// The supported capability state badge.
    state_supported: "Supported",
    /// The read-only capability state badge.
    state_read_only: "Read only",
    /// The unauthorized capability state badge.
    state_unauthorized: "Unauthorized",
    /// The temporarily unavailable capability state badge.
    state_temporarily_unavailable: "Temporarily unavailable",
    /// The schema-incompatible capability state badge.
    state_schema_incompatible: "Schema incompatible",
    /// The not-advertised capability state badge.
    state_not_advertised: "Not advertised",
    /// The not-compiled capability state badge.
    state_not_compiled: "Not compiled",
    /// The unsupported batch outcome chip.
    state_unsupported: "Unsupported",

    /// The generic message for a response that could not be read.
    error_server_unreadable: "The server response could not be read.",
    /// The generic message for a response that could not be parsed.
    error_server_unparsable: "The server response could not be parsed.",
    /// The message for an empty file selection.
    error_file_empty: "The selected file is empty.",
    /// The message for an unreadable file selection.
    error_file_unreadable: "The selected file could not be read.",
    /// The message for a submission that could not be prepared.
    error_submission_unprepared: "The submission could not be prepared.",
    /// The message for a resource that no longer exists.
    error_resource_missing: "This resource no longer exists in the product.",
    /// The message for a display name that exceeds the maximum length.
    error_display_name_too_long: "The display name cannot exceed 128 characters.",
    /// The message for a missing password.
    error_password_required: "A password is required.",
    /// The message for mismatching password confirmations.
    error_passwords_mismatch: "the passwords do not match",
    /// The message for a password that is too short.
    error_password_too_short: "the password must contain at least 12 characters",

    /// The username field label (sign-in and credential forms).
    field_username: "Username",
    /// The password field label (sign-in, credential, and operation forms).
    field_password: "Password",
    /// The account ID field label.
    field_account_id: "Account ID",
    /// The user name field label.
    field_user_name: "User name",
    /// The role ID field label.
    field_role_id: "Role ID",
    /// The display name field label.
    field_display_name: "Display name",
    /// The address field label.
    field_address: "Address",
    /// The host name field label.
    field_host_name: "Host name",
    /// The destination field label.
    field_destination: "Destination",
    /// The protocol field label.
    field_protocol: "Protocol",
    /// The event types field label.
    field_event_types: "Event types",
    /// The role field label.
    field_role: "Role",
    /// The action field label.
    field_action: "Action",
    /// The created timestamp label.
    field_created: "Created",
    /// The action selector placeholder without an ellipsis.
    field_choose_action: "Choose an action",
    /// The action selector placeholder with an ellipsis.
    field_choose_action_ellipsis: "Choose an action...",
}

/// The language of the UI, as selectable in a later iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Lang {
    /// English, the default and currently the only language.
    En,
}

impl Lang {
    /// The string catalog of this language.
    pub const fn strings(self) -> Strings {
        match self {
            Self::En => Strings::en(),
        }
    }
}

/// The catalog the console renders with.
///
/// Copy is static per build in this iteration, so the views read it
/// directly (`{L.nav_overview}`) without a signal or context. The value
/// comes from the language selection entry point [`Lang::strings`], which
/// is the single place a future language selector swaps the whole console.
pub(crate) const L: Strings = Lang::En.strings();

#[cfg(test)]
mod tests {
    use super::{EN_ENTRIES, L, Lang, Strings};

    /// The catalog must never ship an empty string or a leftover format
    /// placeholder: these fields render verbatim, so any `{`/`}`/`%` would
    /// be a broken copy key, not a format argument.
    #[test]
    fn en_catalog_has_no_empty_strings_or_placeholders() {
        for (key, value) in EN_ENTRIES {
            assert!(!value.is_empty(), "catalog entry `{key}` must not be empty");
            for forbidden in ['{', '}', '%'] {
                assert!(
                    !value.contains(forbidden),
                    "catalog entry `{key}` ({value:?}) must not contain `{forbidden}`"
                );
            }
        }
    }

    /// The language selection entry point must exist and map the only
    /// current language to the complete English catalog.
    #[test]
    fn lang_selection_returns_the_en_catalog() {
        assert_eq!(Lang::En.strings(), Strings::en());
        assert_eq!(L, Strings::en());
    }

    /// The console navigation must read exactly the catalog entries: every
    /// view label and the navigation aria-label come from `L`, so a future
    /// language flips the whole navigation with the rest of the console.
    #[test]
    fn catalog_powers_the_console_navigation() {
        use crate::ConsoleView;

        for view in ConsoleView::ALL {
            let label = view.label();
            assert!(
                !label.is_empty(),
                "view {view:?} must not expose an empty navigation label"
            );
            assert!(
                EN_ENTRIES.iter().any(|(_, value)| *value == label),
                "navigation label {label:?} of {view:?} must come from the catalog"
            );
        }
        assert_eq!(L.header_nav_aria, "Console sections");
    }
}
