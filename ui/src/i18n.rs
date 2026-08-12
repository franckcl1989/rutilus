//! UI string catalog (i18n, design §5.1).
//!
//! This iteration ships the complete bilingual catalog as typed fields of a
//! single [`Strings`] struct, the [`Lang`] selection with English and
//! Simplified Chinese, and the console-wide [`L()`] accessor. The copy no
//! longer lives as scattered literals inside `view!` templates: every
//! extracted string is one named field, so the compiler checks every
//! reference and a language only has to provide the same field list (the
//! exhaustive constructors refuse to compile otherwise).
//!
//! Design decisions for this iteration:
//!
//! * Language is a per-thread runtime selection (`thread_local!`), not a
//!   compile-time constant, so a language selector can switch the whole
//!   console. Views read the active catalog through [`L()`], which resolves
//!   the current [`Lang`] to the matching `'static` catalog. The selector
//!   writes the choice, persists it, and reloads the page: a full reload is
//!   the only honest re-render, because the templates read `L()` as plain
//!   expressions and Leptos reactivity cannot re-evaluate them without a
//!   signal at every site. Test threads get their own language state, so a
//!   test can switch languages without leaking into parallel tests.
//! * Formatting copy lives in the catalog too, with `{}` placeholders and
//!   named arguments (`{count}`, `{total}`, ...) preserved verbatim. The
//!   well-formedness test allows `{}` only in the keys listed in
//!   [`FORMAT_KEYS`], so a verbatim key can never accidentally carry a
//!   stray placeholder.
//! * The catalog is a `const`-constructed value (`Strings::en` / `Strings::zh`)
//!   read through [`L()`] instead of a reactive signal or context; the
//!   templates themselves stay as they are across languages.
//!
//! The `strings_catalog!` macro below is the single source of truth: it
//! declares the struct fields, both language constructors, and the
//! `(key, value)` tables the well-formedness tests enumerate, so adding a
//! key can never leave a completeness test behind.

/// Declares the [`Strings`] struct from one bilingual key/value list.
///
/// Every entry becomes a `pub(crate)` field of `&'static str` with its doc
/// comment, an arm of the English and Simplified Chinese constructors, and a
/// `(field name, value)` row of [`EN_ENTRIES`] / [`ZH_ENTRIES`]. Keeping all
/// four in one place means the catalog completeness test always covers
/// exactly the fields the views can read, in both languages.
macro_rules! strings_catalog {
    (
        $(
            $(#[$field_meta:meta])*
            $field:ident: $en:literal, zh: $zh:literal
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
                    $($field: $en),+
                }
            }

            /// The complete Simplified Chinese catalog.
            pub const fn zh() -> Self {
                Self {
                    $($field: $zh),+
                }
            }
        }

        /// Every catalog key with its English value, for the
        /// well-formedness tests. Test-only: the wasm build never reads it.
        #[cfg(test)]
        pub(crate) const EN_ENTRIES: &[(&str, &str)] = &[
            $((stringify!($field), $en)),+
        ];

        /// Every catalog key with its Simplified Chinese value, for the
        /// well-formedness tests. Test-only: the wasm build never reads it.
        #[cfg(test)]
        pub(crate) const ZH_ENTRIES: &[(&str, &str)] = &[
            $((stringify!($field), $zh)),+
        ];
    };
}

/// Catalog keys that legitimately carry `{}` placeholders (or named
/// `{argument}` slots): the views pass them to `format!`, never verbatim.
/// Test-only: the well-formedness test cross-checks this list against the
/// catalogs so a verbatim key can never accidentally contain a placeholder.
#[cfg(test)]
const FORMAT_KEYS: &[&str] = &[
    "fmt_generation_observed",
    "fmt_generation_snapshots",
    "fmt_endpoints_shown_one",
    "fmt_endpoints_shown_many",
    "fmt_endpoints_selected_one",
    "fmt_endpoints_selected_many",
    "fmt_center_operations_one",
    "fmt_center_operations_many",
    "fmt_aggregated_endpoints_one",
    "fmt_aggregated_endpoints_many",
    "fmt_capabilities_count",
    "fmt_rows_enrolled",
    "fmt_endpoints_refreshed",
    "fmt_coverage_supported",
    "fmt_members_versions",
    "fmt_percent",
    "fmt_binding_code",
    "fmt_account_create_payload",
    "fmt_change_role_payload",
    "fmt_change_password_payload",
    "fmt_rename_payload",
    "fmt_delete_payload",
    "fmt_event_create_payload",
    "fmt_reset_keys_payload",
    "fmt_start_push_payload",
    "fmt_start_multipart_payload",
    "fmt_token_generate_payload",
    "fmt_token_erase_payload",
    "fmt_power_activate_payload",
    "fmt_metric_definition_create",
    "fmt_metric_definition_update",
    "fmt_metric_definition_delete",
    "fmt_report_definition_create",
    "fmt_report_definition_update",
    "fmt_report_definition_delete",
    "fmt_targets_one",
    "fmt_targets_many",
    "fmt_selected_file",
    "fmt_selected_artifact",
    "fmt_resume_note",
    "fmt_upload_progress",
    "fmt_uploading_chunk",
    "fmt_last_refresh",
    "error_refresh_rejected",
    "error_import_rejected",
    "error_artifact_create_rejected",
    "error_artifact_chunk_rejected",
    "error_artifact_finalize_rejected",
    "fmt_reset_to_defaults_payload",
    "fmt_power_supply_reset_payload",
    "fmt_clear_payload",
    "fmt_set_point_payload",
    "fmt_set_enabled_payload",
    "fmt_patch_payload",
    "count_endpoints_many",
    "count_credentials_many",
    "count_audit_events_many",
    "count_events_many",
    "count_events_latest_many",
    "count_series_many",
    "count_operations_many",
    "count_artifacts_many",
    "count_batches_many",
    "count_groups_many",
    "count_members_many",
    "count_tag_endpoints_many",
    "count_registered_sites_many",
];

strings_catalog! {
    /// The Overview console section (§12.1).
    nav_overview: "Overview", zh: "总览",
    /// The Groups console section (§12.1).
    nav_groups: "Groups", zh: "分组",
    /// The Credentials console section (§12.1).
    nav_credentials: "Credentials", zh: "凭据",
    /// The Add endpoint console section (§12.1).
    nav_add_endpoint: "Add endpoint", zh: "添加端点",
    /// The Import console section (§12.1).
    nav_import: "Import", zh: "导入",
    /// The Audit console section (§12.1).
    nav_audit: "Audit", zh: "审计",
    /// The Capabilities console section (§12.1).
    nav_capabilities: "Capabilities", zh: "能力",
    /// The Operations console section (§12.1).
    nav_operations: "Operations", zh: "操作",
    /// The Events console section (§12.1).
    nav_events: "Events", zh: "事件",
    /// The Artifacts console section (§12.1).
    nav_artifacts: "Artifacts", zh: "固件包",
    /// The Telemetry console section (§12.1).
    nav_telemetry: "Telemetry", zh: "遥测",
    /// The Diagnostics console section (§12.1).
    nav_diagnostics: "Diagnostics", zh: "诊断",
    /// The Users console section (§12.1).
    nav_users: "Users", zh: "用户",
    /// The Sessions console section (§12.1).
    nav_sessions: "Sessions", zh: "会话",
    /// The Center sites console section (§12.1).
    nav_center_sites: "Center sites", zh: "中心站点",
    /// The Center operations console section (§12.1).
    nav_center_operations: "Center operations", zh: "中心操作",
    /// The Center bindings console section (§12.1).
    nav_center_bindings: "Center bindings", zh: "中心绑定",

    /// The §16.1 Administrator role.
    role_administrator: "Administrator", zh: "管理员",
    /// The §16.1 Operator role.
    role_operator: "Operator", zh: "操作员",
    /// The §16.1 Viewer role.
    role_viewer: "Viewer", zh: "查看者",

    /// The product eyebrow of the auth screens and the console header.
    header_eyebrow: "Local Redfish management", zh: "本地 Redfish 管理",
    /// The console scope status of the Center posture.
    header_center_console: "Center aggregation console", zh: "中心聚合控制台",
    /// The navigation bar's accessibility label.
    header_nav_aria: "Console sections", zh: "控制台分区",
    /// The console status while the initial data load runs.
    header_status_loading: "Starting the local management console...", zh: "正在启动本地管理控制台……",
    /// The console status of a fully loaded local inventory.
    header_status_ready: "Authenticated local inventory", zh: "已认证的本地清单",
    /// The console status when the product metadata could not be verified.
    header_status_failed_metadata: "The local console could not verify product metadata.", zh: "本地控制台无法验证产品元数据。",
    /// The console status when the endpoint inventory is unavailable.
    header_status_failed_inventory: "The endpoint inventory is temporarily unavailable.", zh: "端点清单暂时不可用。",
    /// The console status when the core resource details are unavailable.
    header_status_failed_resources: "Core resource details are temporarily unavailable.", zh: "核心资源详情暂时不可用。",

    /// The sign-in screen heading and submit button.
    auth_sign_in: "Sign in", zh: "登录",
    /// The sign-in TOTP field label.
    auth_totp_code: "TOTP code (if enrolled)", zh: "TOTP 验证码（如已启用）",
    /// The sign-in TOTP input placeholder.
    auth_totp_placeholder: "6 digits", zh: "6 位数字",

    /// The refresh action button.
    action_refresh: "Refresh", zh: "刷新",
    /// The enable action button.
    action_enable: "Enable", zh: "启用",
    /// The disable action button.
    action_disable: "Disable", zh: "禁用",
    /// The delete action button.
    action_delete: "Delete", zh: "删除",
    /// The cancel action button.
    action_cancel: "Cancel", zh: "取消",
    /// The back action button.
    action_back: "Back", zh: "返回",
    /// The sign-out button of the console header.
    action_sign_out: "Sign out", zh: "退出登录",

    /// The queued operation phase badge.
    state_queued: "Queued", zh: "已排队",
    /// The validating operation phase badge.
    state_validating: "Validating", zh: "校验中",
    /// The running operation phase badge.
    state_running: "Running", zh: "执行中",
    /// The waiting-for-BMC operation phase badge.
    state_waiting_bmc: "Waiting for BMC", zh: "等待 BMC",
    /// The verifying operation phase badge.
    state_verifying: "Verifying", zh: "验证中",
    /// The succeeded operation phase badge.
    state_succeeded: "Succeeded", zh: "成功",
    /// The failed operation phase badge.
    state_failed: "Failed", zh: "失败",
    /// The unknown operation phase badge.
    state_unknown: "Unknown", zh: "未知",
    /// The cancelled operation phase badge.
    state_cancelled: "Cancelled", zh: "已取消",
    /// The supported capability state badge.
    state_supported: "Supported", zh: "支持",
    /// The read-only capability state badge.
    state_read_only: "Read only", zh: "只读",
    /// The unauthorized capability state badge.
    state_unauthorized: "Unauthorized", zh: "未授权",
    /// The temporarily unavailable capability state badge.
    state_temporarily_unavailable: "Temporarily unavailable", zh: "暂时不可用",
    /// The schema-incompatible capability state badge.
    state_schema_incompatible: "Schema incompatible", zh: "Schema 不兼容",
    /// The not-advertised capability state badge.
    state_not_advertised: "Not advertised", zh: "未通告",
    /// The not-compiled capability state badge.
    state_not_compiled: "Not compiled", zh: "未编译",
    /// The unsupported batch outcome chip.
    state_unsupported: "Unsupported", zh: "不支持",

    /// The generic message for a response that could not be read.
    error_server_unreadable: "The server response could not be read.", zh: "无法读取服务器响应。",
    /// The generic message for a response that could not be parsed.
    error_server_unparsable: "The server response could not be parsed.", zh: "无法解析服务器响应。",
    /// The message for an empty file selection.
    error_file_empty: "The selected file is empty.", zh: "所选文件为空。",
    /// The message for an unreadable file selection.
    error_file_unreadable: "The selected file could not be read.", zh: "无法读取所选文件。",
    /// The message for a submission that could not be prepared.
    error_submission_unprepared: "The submission could not be prepared.", zh: "无法准备提交。",
    /// The message for a resource that no longer exists.
    error_resource_missing: "This resource no longer exists in the product.", zh: "该资源已不存在于产品中。",
    /// The message for a display name that exceeds the maximum length.
    error_display_name_too_long: "The display name cannot exceed 128 characters.", zh: "显示名称不能超过 128 个字符。",
    /// The message for a missing password.
    error_password_required: "A password is required.", zh: "必须提供密码。",
    /// The message for mismatching password confirmations.
    error_passwords_mismatch: "the passwords do not match", zh: "两次输入的密码不一致",
    /// The message for a password that is too short.
    error_password_too_short: "the password must contain at least 12 characters", zh: "密码至少需要包含 12 个字符",

    /// The username field label (sign-in and credential forms).
    field_username: "Username", zh: "用户名",
    /// The password field label (sign-in, credential, and operation forms).
    field_password: "Password", zh: "密码",
    /// The account ID field label.
    field_account_id: "Account ID", zh: "账户 ID",
    /// The user name field label.
    field_user_name: "User name", zh: "用户名",
    /// The role ID field label.
    field_role_id: "Role ID", zh: "角色 ID",
    /// The display name field label.
    field_display_name: "Display name", zh: "显示名称",
    /// The address field label.
    field_address: "Address", zh: "地址",
    /// The host name field label.
    field_host_name: "Host name", zh: "主机名",
    /// The destination field label.
    field_destination: "Destination", zh: "目标地址",
    /// The protocol field label.
    field_protocol: "Protocol", zh: "协议",
    /// The event types field label.
    field_event_types: "Event types", zh: "事件类型",
    /// The role field label.
    field_role: "Role", zh: "角色",
    /// The action field label.
    field_action: "Action", zh: "操作",
    /// The created timestamp label.
    field_created: "Created", zh: "创建时间",
    /// The action selector placeholder without an ellipsis.
    field_choose_action: "Choose an action", zh: "选择操作",
    /// The action selector placeholder with an ellipsis.
    field_choose_action_ellipsis: "Choose an action...", zh: "选择操作……",

    /// The §12.2 capability-group page title of the Overview page.
    page_systems: "Systems", zh: "系统",
    /// The §12.2 capability-group page title of the Chassis page.
    page_chassis: "Chassis", zh: "机箱",
    /// The §12.2 capability-group page title of the Managers page.
    page_managers: "Managers", zh: "管理器",
    /// The §12.2 capability-group page title of the Assembly page.
    page_assembly: "Assembly", zh: "装配件",
    /// The §12.2 capability-group page title of the Processors page.
    page_processors: "Processors", zh: "处理器",
    /// The §12.2 capability-group page title of the Memory page.
    page_memory: "Memory", zh: "内存",
    /// The §12.2 capability-group page title of the `PCIe` page.
    page_pcie: "PCIe", zh: "PCIe",
    /// The §12.2 capability-group page title of the Network page.
    page_network: "Network", zh: "网络",
    /// The §12.2 capability-group page title of the Power page.
    page_power: "Power", zh: "电源",
    /// The §12.2 capability-group page title of the Thermal page.
    page_thermal: "Thermal", zh: "散热",
    /// The §12.2 capability-group page title of the Sensors page.
    page_sensors: "Sensors", zh: "传感器",
    /// The §12.2 capability-group page title of the BIOS page.
    page_bios: "BIOS", zh: "BIOS",
    /// The §12.2 capability-group page title of the Boot page.
    page_boot: "Boot", zh: "启动",
    /// The §12.2 capability-group page title of the Secure Boot page.
    page_secure_boot: "Secure Boot", zh: "安全启动",
    /// The §12.2 capability-group page title of the Storage page.
    page_storage: "Storage", zh: "存储",
    /// The §12.2 capability-group page title of the Accounts page.
    page_accounts: "Accounts", zh: "账户",
    /// The §12.2 capability-group page title of the Logs page.
    page_logs: "Logs", zh: "日志",
    /// The §12.2 capability-group page title of the Update page.
    page_update: "Update", zh: "更新",
    /// The §12.2 capability-group page title of the Tasks page.
    page_tasks: "Tasks", zh: "任务",
    /// The §12.2 capability-group page title of the OEM page.
    page_oem: "OEM", zh: "OEM",
    /// The §12.2 capability-group page title of the Infrastructure page.
    page_infrastructure: "Infrastructure", zh: "基础设施",

    /// The resource-card title of the Service Root family.
    type_service_root: "Service Root", zh: "服务根",
    /// The resource-card title of the System family.
    type_system: "System", zh: "系统",
    /// The resource-card title of the Manager family.
    type_manager: "Manager", zh: "管理器",
    /// The resource-card title of the Processor family.
    type_processor: "Processor", zh: "处理器",
    /// The resource-card title of the Storage family.
    type_storage: "Storage", zh: "存储",
    /// The resource-card title of the Network Adapter family.
    type_network_adapter: "Network adapter", zh: "网卡",
    /// The resource-card title of the Network Device Function family.
    type_network_device_function: "Network device function", zh: "网络设备功能",
    /// The resource-card title of the Power Equipment family.
    type_power_equipment: "Power equipment", zh: "电源设备",
    /// The resource-card title of the Power Supply family.
    type_power_supply: "Power supply", zh: "电源模块",
    /// The resource-card title of the Environment Metrics family.
    type_environment_metrics: "Environment metrics", zh: "环境指标",
    /// The resource-card title of the Ethernet Interface family.
    type_ethernet_interface: "Ethernet interface", zh: "以太网接口",
    /// The resource-card title of the Account family.
    type_account: "Account", zh: "账户",
    /// The resource-card title of the Boot Option family.
    type_boot_option: "Boot option", zh: "启动项",
    /// The resource-card title of the Sensor family.
    type_sensor: "Sensor", zh: "传感器",
    /// The resource-card title of the Control family.
    type_control: "Control", zh: "控制",
    /// The resource-card title of the Log Service family.
    type_log_service: "Log Service", zh: "日志服务",
    /// The resource-card title of the Manager Network Protocol family.
    type_manager_network_protocol: "Manager Network Protocol", zh: "管理器网络协议",
    /// The resource-card title of the Host Interface family.
    type_host_interface: "Host Interface", zh: "主机接口",
    /// The resource-card title of the `PCIe` Device family.
    type_pcie_device: "PCIe device", zh: "PCIe 设备",
    /// The resource-card title of the Software Inventory family.
    type_software_inventory: "Software inventory", zh: "软件清单",
    /// The resource-card title of the Event Service family.
    type_event_service: "Event Service", zh: "事件服务",
    /// The resource-card title of the Event Subscription family.
    type_event_subscription: "Event subscription", zh: "事件订阅",
    /// The resource-card title of the Telemetry Service family.
    type_telemetry_service: "Telemetry Service", zh: "遥测服务",
    /// The resource-card title of the Metric Definition family.
    type_metric_definition: "Metric definition", zh: "指标定义",
    /// The resource-card title of the Metric Report family.
    type_metric_report: "Metric report", zh: "指标报告",
    /// The resource-card title of the Task Service family.
    type_task_service: "Task Service", zh: "任务服务",
    /// The resource-card title of the Task family.
    type_task: "Task", zh: "任务",
    /// The resource-card title of the Dell OEM family.
    type_dell_oem: "Dell OEM", zh: "Dell OEM",
    /// The resource-card title of the Supermicro `SysLockdown` family.
    type_smc_sys_lockdown: "Supermicro SysLockdown", zh: "Supermicro SysLockdown",
    /// The resource-card title of the Supermicro `KCS Interface` family.
    type_smc_kcs_interface: "Supermicro KCS Interface", zh: "Supermicro KCS 接口",
    /// The resource-card title of the NVIDIA System Config Profile family.
    type_nvidia_system_config_profile: "NVIDIA System Config Profile", zh: "NVIDIA 系统配置配置文件",
    /// The resource-card title of the NVIDIA Profile Status family.
    type_nvidia_profile_status: "NVIDIA Profile Status", zh: "NVIDIA 配置文件状态",
    /// The resource-card title of the NVIDIA System Profile family.
    type_nvidia_system_profile: "NVIDIA System Profile", zh: "NVIDIA 系统配置文件",
    /// The resource-card title of the NVIDIA Profile File family.
    type_nvidia_profile_file: "NVIDIA Profile File", zh: "NVIDIA 配置文件",
    /// The resource-card title of the NVIDIA Power Compliance family.
    type_nvidia_power_compliance: "NVIDIA Power Compliance", zh: "NVIDIA 电源合规",
    /// The resource-card title of the NVIDIA Power Domain family.
    type_nvidia_power_domain: "NVIDIA Power Domain", zh: "NVIDIA 电源域",
    /// The resource-card title of the NVIDIA Power Policy family.
    type_nvidia_power_policy: "NVIDIA Power Policy", zh: "NVIDIA 电源策略",
    /// The resource-card title of the NVIDIA Managed Entity Group family.
    type_nvidia_managed_entity_group: "NVIDIA Managed Entity Group", zh: "NVIDIA 受管实体组",
    /// The resource-card title of the NVIDIA Power State Group family.
    type_nvidia_power_state_group: "NVIDIA Power State Group", zh: "NVIDIA 电源状态组",
    /// The resource-card title of the NVIDIA PSC State family.
    type_nvidia_psc_state: "NVIDIA PSC State", zh: "NVIDIA PSC 状态",
    /// The resource-card title of the NVIDIA PSU State family.
    type_nvidia_psu_state: "NVIDIA PSU State", zh: "NVIDIA PSU 状态",
    /// The resource-card title of the NVIDIA PSU Redundancy family.
    type_nvidia_psu_redundancy: "NVIDIA PSU Redundancy", zh: "NVIDIA PSU 冗余",
    /// The resource-card title of the NVIDIA Managed Entity family.
    type_nvidia_managed_entity: "NVIDIA Managed Entity", zh: "NVIDIA 受管实体",
    /// The resource-card title of the Lenovo Security Service family.
    type_lenovo_security_service: "Lenovo Security Service", zh: "Lenovo 安全服务",
    /// The resource-card title of the AMI Service Root family.
    type_ami_service_root: "AMI Service Root", zh: "AMI 服务根",
    /// The resource-card title of the AMI Config BMC family.
    type_ami_config_bmc: "AMI Config BMC", zh: "AMI 配置 BMC",
    /// The resource-card title of the HPE iLO Service Extension family.
    type_hpe_ilo_service_ext: "HPE iLO Service Extension", zh: "HPE iLO 服务扩展",
    /// The resource-card title of the HPE iLO Manager family.
    type_hpe_ilo_manager: "HPE iLO Manager", zh: "HPE iLO 管理器",
    /// The resource-card title of the `LiteOn` Power Supply family.
    type_liteon_power_supply: "LiteOn Power Supply", zh: "LiteOn 电源模块",
    /// The resource-card title of the Delta Power Supply family.
    type_delta_power_supply: "Delta Power Supply", zh: "Delta 电源模块",

    /// The Service Root "Vendor" fact label.
    fact_vendor: "Vendor", zh: "厂商",
    /// The Service Root "Product" fact label.
    fact_product: "Product", zh: "产品",
    /// The Service Root "Redfish version" fact label.
    fact_redfish_version: "Redfish version", zh: "Redfish 版本",
    /// The System "System type" fact label.
    fact_system_type: "System type", zh: "系统类型",
    /// The hardware "Manufacturer" fact label.
    fact_manufacturer: "Manufacturer", zh: "制造商",
    /// The hardware "Model" fact label.
    fact_model: "Model", zh: "型号",
    /// The hardware "Part number" fact label.
    fact_part_number: "Part number", zh: "部件号",
    /// The hardware "Serial number" fact label.
    fact_serial_number: "Serial number", zh: "序列号",
    /// The "SKU" fact label (Redfish field name, kept verbatim).
    fact_sku: "SKU", zh: "SKU",
    /// The "UUID" fact label (Redfish field name, kept verbatim).
    fact_uuid: "UUID", zh: "UUID",
    /// The System "BIOS version" fact label.
    fact_bios_version: "BIOS version", zh: "BIOS 版本",
    /// The "Power state" fact label.
    fact_power_state: "Power state", zh: "电源状态",
    /// The status "State" fact label.
    fact_state: "State", zh: "状态",
    /// The status "Health" fact label.
    fact_health: "Health", zh: "健康状态",
    /// The status "Health rollup" fact label.
    fact_health_rollup: "Health rollup", zh: "健康汇总",
    /// The Chassis "Chassis type" fact label.
    fact_chassis_type: "Chassis type", zh: "机箱类型",
    /// The Chassis "Asset tag" fact label.
    fact_asset_tag: "Asset tag", zh: "资产标签",
    /// The Manager "Manager type" fact label.
    fact_manager_type: "Manager type", zh: "管理器类型",
    /// The "Firmware version" fact label.
    fact_firmware_version: "Firmware version", zh: "固件版本",
    /// The "Version" fact label.
    fact_version: "Version", zh: "版本",
    /// The Processor "Processor type" fact label.
    fact_processor_type: "Processor type", zh: "处理器类型",
    /// The Processor "Socket" fact label.
    fact_socket: "Socket", zh: "插槽",
    /// The Processor "Total cores" fact label.
    fact_total_cores: "Total cores", zh: "核心总数",
    /// The Memory "Memory device type" fact label.
    fact_memory_device_type: "Memory device type", zh: "内存设备类型",
    /// The Memory "Capacity (MiB)" fact label.
    fact_capacity_mib: "Capacity (MiB)", zh: "容量（MiB）",
    /// The Storage "Controller count" fact label.
    fact_controller_count: "Controller count", zh: "控制器数量",
    /// The Storage "Drive count" fact label.
    fact_drive_count: "Drive count", zh: "驱动器数量",
    /// The "Device enabled" fact label.
    fact_device_enabled: "Device enabled", zh: "设备已启用",
    /// The "Interface enabled" fact label.
    fact_interface_enabled: "Interface enabled", zh: "接口已启用",
    /// The "Enabled" fact label.
    fact_enabled: "Enabled", zh: "已启用",
    /// The "Locked" fact label.
    fact_locked: "Locked", zh: "已锁定",
    /// The BIOS "Attribute registry" fact label.
    fact_attribute_registry: "Attribute registry", zh: "属性注册表",
    /// The "Secure boot enabled" fact label.
    fact_secure_boot_enabled: "Secure boot enabled", zh: "安全启动已启用",
    /// The Network Device Function "Function type" fact label.
    fact_function_type: "Function type", zh: "功能类型",
    /// The Ethernet Interface "MAC address" fact label.
    fact_mac_address: "MAC address", zh: "MAC 地址",
    /// The Ethernet Interface "Speed (Mbps)" fact label.
    fact_speed_mbps: "Speed (Mbps)", zh: "速度（Mbps）",
    /// The Boot Option "UEFI device path" fact label.
    fact_uefi_device_path: "UEFI device path", zh: "UEFI 设备路径",
    /// The Secure Boot "Secure boot mode" fact label.
    fact_secure_boot_mode: "Secure boot mode", zh: "安全启动模式",
    /// The Power Equipment "Equipment type" fact label.
    fact_equipment_type: "Equipment type", zh: "设备类型",
    /// The Power Supply "Supply type" fact label.
    fact_supply_type: "Supply type", zh: "电源类型",
    /// The Power Supply "Capacity (W)" fact label.
    fact_capacity_w: "Capacity (W)", zh: "容量（W）",
    /// The Thermal "Fan readings" fact label.
    fact_fan_readings: "Fan readings", zh: "风扇读数",
    /// The Thermal "Ambient temperature (C)" fact label.
    fact_ambient_temperature: "Ambient temperature (C)", zh: "环境温度（℃）",
    /// The Sensor "Reading type" fact label.
    fact_reading_type: "Reading type", zh: "读数类型",
    /// The Sensor "Reading" fact label.
    fact_reading: "Reading", zh: "读数",
    /// The Sensor "Reading units" fact label.
    fact_reading_units: "Reading units", zh: "读数单位",
    /// The Control "Control type" fact label.
    fact_control_type: "Control type", zh: "控制类型",
    /// The Control "Set point" fact label.
    fact_set_point: "Set point", zh: "设定值",
    /// The Log Service "Service enabled" fact label.
    fact_service_enabled: "Service enabled", zh: "服务已启用",
    /// The Log Service "Max records" fact label.
    fact_max_records: "Max records", zh: "最大记录数",
    /// The Manager Network Protocol "FQDN" fact label (Redfish field name).
    fact_fqdn: "FQDN", zh: "FQDN",
    /// The `PCIe` Device "Device type" fact label.
    fact_device_type: "Device type", zh: "设备类型",
    /// The Assembly "Producer" fact label.
    fact_producer: "Producer", zh: "生产商",
    /// The Assembly "Release date" fact label.
    fact_release_date: "Release date", zh: "发布日期",
    /// The Software Inventory "Software ID" fact label.
    fact_software_id: "Software ID", zh: "软件 ID",
    /// The Event Subscription "Context" fact label.
    fact_context: "Context", zh: "上下文",
    /// The Event Subscription "Latest value" fact label.
    fact_latest_value: "Latest value", zh: "最新值",
    /// The Metric Definition "Units" fact label.
    fact_units: "Units", zh: "单位",
    /// The Metric Definition "Metric type" fact label.
    fact_metric_type: "Metric type", zh: "指标类型",
    /// The Metric Report "Metric values" fact label.
    fact_metric_values: "Metric values", zh: "指标值",
    /// The Task Service "Service enabled" fact label (reuses the service label).
    fact_completed_task_policy: "Completed task policy", zh: "完成任务策略",
    /// The Task "Start time" fact label.
    fact_start_time: "Start time", zh: "开始时间",
    /// The Task "End time" fact label.
    fact_end_time: "End time", zh: "结束时间",
    /// The Task "Task state" fact label.
    fact_task_state: "Task state", zh: "任务状态",
    /// The Task "Task status" fact label.
    fact_task_status: "Task status", zh: "任务状态",
    /// The Task "Percent complete" fact label.
    fact_percent_complete: "Percent complete", zh: "完成百分比",
    /// The Dell "BMC MAC address" fact label.
    fact_bmc_mac_address: "BMC MAC address", zh: "BMC MAC 地址",
    /// The Dell "Service tag" fact label.
    fact_service_tag: "Service tag", zh: "服务标签",
    /// The Dell "Server name" fact label.
    fact_server_name: "Server name", zh: "服务器名称",
    /// The Supermicro KCS "Privilege" fact label.
    fact_privilege: "Privilege", zh: "权限",
    /// The NVIDIA "`SysLockdown` enabled" fact label.
    fact_sys_lockdown_enabled: "SysLockdown enabled", zh: "SysLockdown 已启用",
    /// The NVIDIA "NVIDIA certificates" fact label.
    fact_nvidia_certificates: "NVIDIA certificates", zh: "NVIDIA 证书",
    /// The NVIDIA "OEM certificates" fact label.
    fact_oem_certificates: "OEM certificates", zh: "OEM 证书",
    /// The NVIDIA "Pending activation" fact label.
    fact_pending_activation: "Pending activation", zh: "待激活",
    /// The NVIDIA "Factory reset status" fact label.
    fact_factory_reset_status: "Factory reset status", zh: "出厂重置状态",
    /// The NVIDIA "Active profile index" fact label.
    fact_active_profile_index: "Active profile index", zh: "活动配置文件索引",
    /// The NVIDIA "BMC profile version" fact label.
    fact_bmc_profile_version: "BMC profile version", zh: "BMC 配置文件版本",
    /// The NVIDIA "Default profile index" fact label.
    fact_default_profile_index: "Default profile index", zh: "默认配置文件索引",
    /// The NVIDIA profile "Default" fact label.
    fact_default: "Default", zh: "默认",
    /// The NVIDIA profile "Owner" fact label.
    fact_owner: "Owner", zh: "所有者",
    /// The NVIDIA profile "Profile name" fact label.
    fact_profile_name: "Profile name", zh: "配置文件名称",
    /// The NVIDIA profile file "Activate" fact label.
    fact_activate: "Activate", zh: "激活",
    /// The NVIDIA profile file "More profiles" fact label.
    fact_more_profiles: "More profiles", zh: "更多配置文件",
    /// The NVIDIA profile file "Project name" fact label.
    fact_project_name: "Project name", zh: "项目名称",
    /// The NVIDIA profile file "Profile" fact label.
    fact_profile: "Profile", zh: "配置文件",
    /// The NVIDIA power domain "Value" fact label.
    fact_value: "Value", zh: "值",
    /// The NVIDIA power domain "Type" fact label.
    fact_type: "Type", zh: "类型",
    /// The NVIDIA power domain "Unit" fact label.
    fact_unit: "Unit", zh: "单位",
    /// The NVIDIA power domain "Sensor implementation" fact label.
    fact_sensor_implementation: "Sensor implementation", zh: "传感器实现",
    /// The NVIDIA power policy "Min" fact label.
    fact_min: "Min", zh: "最小值",
    /// The NVIDIA power policy "Max" fact label.
    fact_max: "Max", zh: "最大值",
    /// The NVIDIA power policy "Policy actions" fact label.
    fact_policy_actions: "Policy actions", zh: "策略动作",
    /// The NVIDIA "Origin profile UUID" fact label.
    fact_origin_profile_uuid: "Origin profile UUID", zh: "源配置文件 UUID",
    /// The NVIDIA power state group "PSC ID" fact label.
    fact_psc_id: "PSC ID", zh: "PSC ID",
    /// The NVIDIA power state group "Generated watts" fact label.
    fact_generated_watts: "Generated watts", zh: "发电功率（瓦）",
    /// The NVIDIA power state group "Number of PSCs" fact label.
    fact_number_of_pscs: "Number of PSCs", zh: "PSC 数量",
    /// The NVIDIA power state group "Number of local PSUs" fact label.
    fact_number_of_local_psus: "Number of local PSUs", zh: "本地 PSU 数量",
    /// The NVIDIA PSC state "Operational PSUs" fact label.
    fact_operational_psus: "Operational PSUs", zh: "运行中 PSU 数量",
    /// The NVIDIA PSC state "Power brake assert" fact label.
    fact_power_brake_assert: "Power brake assert", zh: "电源刹车断言",
    /// The NVIDIA PSC state "Status" fact label.
    fact_status: "Status", zh: "状态",
    /// The NVIDIA PSU state "PSU ID" fact label.
    fact_psu_id: "PSU ID", zh: "PSU ID",
    /// The NVIDIA PSU state "Presence" fact label.
    fact_presence: "Presence", zh: "在位",
    /// The NVIDIA PSU state "Input 1 active" fact label.
    fact_input_1_active: "Input 1 active", zh: "输入 1 活动",
    /// The NVIDIA PSU state "Input 2 active" fact label.
    fact_input_2_active: "Input 2 active", zh: "输入 2 活动",
    /// The NVIDIA PSU redundancy "Redundancy setting" fact label.
    fact_redundancy_setting: "Redundancy setting", zh: "冗余设置",
    /// The NVIDIA PSU redundancy "Min PSUs needed" fact label.
    fact_min_psus_needed: "Min PSUs needed", zh: "所需最少 PSU 数量",
    /// The NVIDIA managed entity "Current managed entity" fact label.
    fact_current_managed_entity: "Current managed entity", zh: "当前受管实体",
    /// The NVIDIA managed entity "Milliseconds since last heartbeat" fact label.
    fact_ms_since_last_heartbeat: "Milliseconds since last heartbeat", zh: "距上次心跳的毫秒数",
    /// The NVIDIA managed entity "IPv4 address" fact label.
    fact_ipv4_address: "IPv4 address", zh: "IPv4 地址",
    /// The NVIDIA managed entity "IPv6 address" fact label.
    fact_ipv6_address: "IPv6 address", zh: "IPv6 地址",
    /// The NVIDIA managed entity "Port" fact label.
    fact_port: "Port", zh: "端口",
    /// The Lenovo "Firmware rollback" fact label.
    fact_firmware_rollback: "Firmware rollback", zh: "固件回滚",
    /// The Max PSUs "Max PSUs supported" fact label.
    fact_max_psus_supported: "Max PSUs supported", zh: "支持的最大 PSU 数量",
    /// The Transport "Transport protocol" fact label.
    fact_transport_protocol: "Transport protocol", zh: "传输协议",
    /// The "Redfish Technology Pack version" fact label.
    fact_redfish_tech_pack_version: "Redfish Technology Pack version", zh: "Redfish Technology Pack 版本",
    /// The "Host control lockout" fact label.
    fact_host_control_lockout: "Host control lockout", zh: "主机控制锁定",
    /// The "BIOS variable write lockout" fact label.
    fact_bios_variable_write_lockout: "BIOS variable write lockout", zh: "BIOS 变量写入锁定",
    /// The "BIOS settings-change lockdown" fact label.
    fact_bios_settings_change_lockdown: "BIOS settings-change lockdown", zh: "BIOS 设置变更锁定",
    /// The "BIOS upgrade/downgrade lockdown" fact label.
    fact_bios_upgrade_downgrade_lockdown: "BIOS upgrade/downgrade lockdown", zh: "BIOS 升级/降级锁定",
    /// The "Manager firmware version" fact label.
    fact_manager_firmware_version: "Manager firmware version", zh: "管理器固件版本",
    /// The "Power supply type" fact label.
    fact_power_supply_type: "Power supply type", zh: "电源类型",
    /// The "Sensor reading type" fact label.
    fact_sensor_reading_type: "Sensor reading type", zh: "传感器读数类型",
    /// The "Redfish ID" fact label.
    fact_redfish_id: "Redfish ID", zh: "Redfish ID",
    /// The "Temperature (C)" environment fact label.
    fact_temperature_c: "Temperature (C)", zh: "温度（℃）",
    /// The "Humidity (%)" environment fact label.
    fact_humidity_percent: "Humidity (%)", zh: "湿度（%）",
    /// The "Power (W)" environment fact label.
    fact_power_w: "Power (W)", zh: "功率（W）",
    /// The "Energy (kWh)" environment fact label.
    fact_energy_kwh: "Energy (kWh)", zh: "能量（kWh）",
    /// The "Power load (%)" environment fact label.
    fact_power_load_percent: "Power load (%)", zh: "功率负载（%）",
    /// The "Power limit (W)" environment fact label.
    fact_power_limit_w: "Power limit (W)", zh: "功率上限（W）",
    /// The "Dew point (C)" environment fact label.
    fact_dew_point_c: "Dew point (C)", zh: "露点（℃）",
    /// The "Absolute humidity" environment fact label.
    fact_absolute_humidity: "Absolute humidity", zh: "绝对湿度",
    /// The "Energy (J)" environment fact label.
    fact_energy_j: "Energy (J)", zh: "能量（J）",
    /// The "Voltage (V)" environment fact label.
    fact_voltage_v: "Voltage (V)", zh: "电压（V）",
    /// The "Current (A)" environment fact label.
    fact_current_a: "Current (A)", zh: "电流（A）",
    /// The "Virtual NIC enabled" HPE fact label.
    fact_virtual_nic_enabled: "Virtual NIC enabled", zh: "虚拟网卡已启用",
    /// The "Power capacity (watts)" `LiteOn` fact label.
    fact_power_capacity_watts: "Power capacity (watts)", zh: "功率容量（瓦）",
    /// The "Fan speed target" Delta fact label.
    fact_fan_speed_target: "Fan speed target", zh: "风扇转速目标",
    /// The "Power" Delta fact label.
    fact_power_flag: "Power", zh: "电源",
    /// The "Auto deassert power brake" fact label.
    fact_auto_deassert_power_brake: "Auto deassert power brake", zh: "自动解除电源刹车",

    /// The §7.5 command family label of the account family.
    family_account: "Account", zh: "账户",
    /// The §7.5 command family label of the system reset family.
    family_system_reset: "System reset", zh: "系统重置",
    /// The §7.5 command family label of the manager reset family.
    family_manager_reset: "Manager reset", zh: "管理器重置",
    /// The §7.5 command family label of the chassis reset family.
    family_chassis_reset: "Chassis reset", zh: "机箱重置",
    /// The §7.5 command family label of the boot source override family.
    family_boot_override: "Boot source override", zh: "启动源覆盖",
    /// The §7.5 command family label of the Secure Boot family.
    family_secure_boot: "Secure Boot", zh: "安全启动",
    /// The §7.5 command family label of the event subscription family.
    family_event_subscription: "Event subscription", zh: "事件订阅",
    /// The §7.5 command family label of the telemetry family.
    family_telemetry: "Telemetry", zh: "遥测",
    /// The §7.5 command family label of the firmware update family.
    family_firmware_update: "Firmware update", zh: "固件更新",
    /// The §7.5 command family label of the OEM family.
    family_oem: "OEM (NVIDIA)", zh: "OEM（NVIDIA）",
    /// The command family label of the log-service family.
    family_log_service: "Log service", zh: "日志服务",
    /// The command family label of the control family.
    family_control: "Control", zh: "控制",

    /// The NVIDIA OEM face label of the system config profile face.
    face_system_config_profile: "System config profile", zh: "系统配置配置文件",
    /// The NVIDIA OEM face label of the debug token face.
    face_debug_token: "Debug token", zh: "调试令牌",
    /// The NVIDIA OEM face label of the power smoothing face.
    face_power_smoothing: "Power smoothing", zh: "电源平滑",

    /// The account action label for creating an account.
    action_create_account: "Create account", zh: "创建账户",
    /// The account action label for changing a role.
    action_change_role: "Change role", zh: "更改角色",
    /// The account action label for changing a password.
    action_change_password: "Change password", zh: "更改密码",
    /// The account action label for renaming an account.
    action_rename_account: "Rename account", zh: "重命名账户",
    /// The account action label for deleting an account.
    action_delete_account: "Delete account", zh: "删除账户",
    /// The Secure Boot action label for resetting keys.
    action_reset_keys: "Reset keys", zh: "重置密钥",
    /// The event action label for creating a subscription.
    action_create_subscription: "Create subscription", zh: "创建订阅",
    /// The event action label for deleting a subscription.
    action_delete_subscription: "Delete subscription", zh: "删除订阅",
    /// The OEM action label for updating a profile.
    action_update_profile: "Update profile", zh: "更新配置文件",
    /// The OEM action label for a factory reset.
    action_factory_reset: "Factory reset", zh: "出厂重置",
    /// The OEM action label for activating a profile.
    action_activate_profile: "Activate profile", zh: "激活配置文件",
    /// The OEM action label for generating a token.
    action_generate_token: "Generate token", zh: "生成令牌",
    /// The OEM action label for installing a token.
    action_install_token: "Install token", zh: "安装令牌",
    /// The OEM action label for disabling a token.
    action_disable_token: "Disable token", zh: "禁用令牌",
    /// The OEM action label for erasing tokens.
    action_erase_tokens: "Erase tokens", zh: "擦除令牌",
    /// The OEM action label for activating a preset profile.
    action_activate_preset: "Activate preset profile", zh: "激活预设配置文件",
    /// The OEM action label for applying admin overrides.
    action_apply_admin_overrides: "Apply admin overrides", zh: "应用管理员覆盖",

    /// The unified §12.3 health label of a healthy resource.
    health_ok: "OK", zh: "正常",
    /// The unified §12.3 health label of a warning resource.
    health_warning: "Warning", zh: "警告",
    /// The unified §12.3 health label of a critical resource.
    health_critical: "Critical", zh: "严重",

    /// The §14.2 freshness label of a never-refreshed snapshot.
    freshness_never: "Never refreshed", zh: "从未刷新",
    /// The §14.2 freshness label of a snapshot within the last hour.
    freshness_hour: "Within 1 hour", zh: "1 小时内",
    /// The §14.2 freshness label of a snapshot within the last day.
    freshness_day: "Within 1 day", zh: "1 天内",
    /// The §14.2 freshness label of a snapshot within the last week.
    freshness_week: "Within 7 days", zh: "7 天内",
    /// The §14.2 freshness label of a snapshot older than a week.
    freshness_older: "Older than 7 days", zh: "超过 7 天",

    /// The CSV import row outcome label of an enrolled row.
    status_enrolled: "Enrolled", zh: "已注册",
    /// The CSV import row outcome label of a failed TLS probe.
    status_tls_probe_failed: "TLS probe failed", zh: "TLS 探测失败",
    /// The CSV import row outcome label of a rejected trust decision.
    status_trust_rejected: "Trust rejected", zh: "信任被拒绝",
    /// The CSV import row outcome label of a failed enrollment.
    status_enrollment_failed: "Enrollment failed", zh: "注册失败",
    /// The refresh row outcome label of a refreshed endpoint.
    status_refreshed: "Refreshed", zh: "已刷新",
    /// The refresh row outcome label of a missing endpoint.
    status_not_found: "Not found", zh: "未找到",
    /// The artifact badge label of the uploading state.
    status_uploading: "Uploading", zh: "上传中",
    /// The artifact badge label of the ready state.
    status_ready: "Ready", zh: "就绪",

    /// The "Pinned certificate" trust-mode label.
    notice_pinned_certificate: "Pinned certificate", zh: "固定证书",
    /// The "System CA" trust-mode label.
    notice_system_ca: "System CA", zh: "系统 CA",
    /// The §11.5 honest notice when the nv-redfish baseline has no
    /// strong-typed OEM surface for the endpoint's vendor. Pinned so the
    /// `UnsupportedByNvRedfishBaseline` rendering cannot drift from the
    /// §11.5 contract wording.
    notice_oem_unsupported: "OEM data is not available in the nv-redfish baseline for this vendor", zh: "此厂商的 nv-redfish 基线不提供 OEM 数据",
    /// The §12.4 placeholder shown when a BMC did not publish an optional
    /// diagnostics field.
    notice_diagnostics_absent: "Not published", zh: "未发布",
    /// The §12.4 footnote disclosing that the payload is the persisted
    /// decoded snapshot of the latest complete refresh.
    notice_diagnostics_footer: "Diagnostics show the decoded snapshot of the latest complete refresh; decode-error paths and ExtendedInfo are shown when the refresh recorded them.", zh: "诊断显示最近一次完整刷新的已解码快照；当刷新记录到解码错误路径和 ExtendedInfo 时才会显示。",
    /// The capability state label of a capability that has never been
    /// observed on this endpoint.
    notice_not_observed: "Not yet observed", zh: "尚未观测",
    /// The trust challenge state label of a system-CA-verified identity.
    notice_verified_by_system_ca: "Verified by system CA roots", zh: "已通过系统 CA 根验证",
    /// The trust challenge state label of an identity that requires an
    /// explicit pin.
    notice_explicit_pin_required: "Not trusted by system CA roots; an explicit pin is required", zh: "未受系统 CA 根信任；需要显式固定",

    /// The endpoint-card snapshot label of a first-refresh snapshot.
    notice_awaiting_first_refresh: "Awaiting first refresh", zh: "等待首次刷新",

    /// The header "Product" build label.
    label_product: "Product", zh: "产品",
    /// The Overview "Inventory" section label.
    label_inventory: "Inventory", zh: "清单",
    /// The Overview heading describing the latest complete generations.
    label_latest_generations: "Latest complete Redfish resource generations", zh: "最新的完整 Redfish 资源代际",
    /// The "Endpoints" overview stat tile label.
    label_endpoints: "Endpoints", zh: "端点",
    /// The "With current snapshot" overview stat tile label.
    label_with_current_snapshot: "With current snapshot", zh: "具有当前快照",
    /// The "Running operations" overview stat tile label.
    label_running_operations: "Running operations", zh: "执行中的操作",
    /// The "Firmware members" overview stat tile label.
    label_firmware_members: "Firmware members", zh: "固件成员",
    /// The "Capability coverage" overview stat tile label.
    label_capability_coverage: "Capability coverage", zh: "能力覆盖率",
    /// The "No capability observations yet" overview stat tile note.
    label_no_capability_observations: "No capability observations yet", zh: "尚无能力观测",
    /// The "Vendors" overview block label.
    label_vendors: "Vendors", zh: "厂商",
    /// The "Data freshness" overview block label.
    label_data_freshness: "Data freshness", zh: "数据新鲜度",
    /// The "Recent events" overview block label.
    label_recent_events: "Recent events", zh: "最近事件",
    /// The overview search placeholder.
    label_name_or_address: "Name or address", zh: "名称或地址",
    /// The "Search" overview field label.
    label_search: "Search", zh: "搜索",
    /// The "Source" resource fact label.
    label_source: "Source", zh: "来源",
    /// The "Updated" facts timestamp label.
    label_updated: "Updated", zh: "更新时间",
    /// The "Name" form field label.
    label_name: "Name", zh: "名称",
    /// The "Site" form field label.
    label_site: "Site", zh: "站点",
    /// The "Standalone" operation origin label.
    label_standalone: "Standalone", zh: "独立",
    /// The "Center" operation origin label.
    label_center: "Center", zh: "中心",
    /// The "Endpoint" form and table label.
    label_endpoint: "Endpoint", zh: "端点",
    /// The "Target" form field label.
    label_target: "Target", zh: "目标",
    /// The "Command family" form field label.
    label_command_family: "Command family", zh: "命令族",
    /// The "Reset type" form field label.
    label_reset_type: "Reset type", zh: "重置类型",
    /// The "Boot source" form field label.
    label_boot_source: "Boot source", zh: "启动源",
    /// The "Enabled" boot-override form label.
    label_enabled: "Enabled", zh: "启用",
    /// The "Applies" boot-override form label.
    label_applies: "Applies", zh: "应用范围",
    /// The "Mode" form field label.
    label_mode: "Mode", zh: "模式",
    /// The "Key set" form field label.
    label_key_set: "Key set", zh: "密钥集",
    /// The "Destination URL" form field label.
    label_destination_url: "Destination URL", zh: "目标 URL",
    /// The "Subscription ID" form field label.
    label_subscription_id: "Subscription ID", zh: "订阅 ID",
    /// The "Account action" form field label.
    label_account_action: "Account action", zh: "账户操作",
    /// The "Center URL the site connects to" form field label.
    label_center_url: "Center URL the site connects to", zh: "站点连接的中心 URL",
    /// The "CSV file" form field label.
    label_csv_file: "CSV file", zh: "CSV 文件",
    /// The "Group name" form field label.
    label_group_name: "Group name", zh: "分组名称",
    /// The "Tag name" form field label.
    label_tag_name: "Tag name", zh: "标签名称",
    /// The "Endpoint address" form field label.
    label_endpoint_address: "Endpoint address", zh: "端点地址",
    /// The "Preset profile id" form field label.
    label_preset_profile_id: "Preset profile id", zh: "预设配置文件 ID",
    /// The "Token type" form field label.
    label_token_type: "Token type", zh: "令牌类型",
    /// The "Erase scope" form field label.
    label_erase_scope: "Erase scope", zh: "擦除范围",
    /// The "Token data (Base64)" form field label.
    label_token_data: "Token data (Base64)", zh: "令牌数据（Base64）",
    /// The "Profile file (JSON)" form field label.
    label_profile_file: "Profile file (JSON)", zh: "配置文件（JSON）",
    /// The "Push URI (optional)" form field label.
    label_push_uri: "Push URI (optional)", zh: "推送 URI（可选）",
    /// The "Firmware artifact" form field label.
    label_firmware_artifact: "Firmware artifact", zh: "固件包",
    /// The "Firmware file" form field label.
    label_firmware_file: "Firmware file", zh: "固件文件",
    /// The "New password" form field label.
    label_new_password: "New password", zh: "新密码",
    /// The "New user name" form field label.
    label_new_user_name: "New user name", zh: "新用户名",
    /// The "Bootstrap code" first-run form label.
    label_bootstrap_code: "Bootstrap code", zh: "引导码",
    /// The "Confirm password" first-run form label.
    label_confirm_password: "Confirm password", zh: "确认密码",
    /// The "Set up TOTP now (optional)" first-run option label.
    label_totp_optional: "Set up TOTP now (optional)", zh: "立即设置 TOTP（可选）",
    /// The "Secret from your authenticator app" TOTP hint.
    label_totp_secret: "Secret from your authenticator app", zh: "认证器应用中的密钥",
    /// The "Activation code" TOTP field label.
    label_activation_code: "Activation code", zh: "激活码",
    /// The "New user role" aria-label of the user admin role selector.
    label_new_user_role: "New user role", zh: "新用户角色",
    /// The "Observed at" facts timestamp label.
    label_observed_at: "Observed at", zh: "观察时间",
    /// The "SHA-256 fingerprint" onboarding panel label.
    label_sha256_fingerprint: "SHA-256 fingerprint", zh: "SHA-256 指纹",
    /// The "Generation" facts label.
    label_generation: "Generation", zh: "代际",
    /// The "Target ID" audit facts label.
    label_target_id: "Target ID", zh: "目标 ID",
    /// The "Outcome" audit facts label.
    label_outcome: "Outcome", zh: "结果",
    /// The "Sequence" audit facts label.
    label_sequence: "Sequence", zh: "序号",
    /// The "Operation" audit facts label.
    label_operation: "Operation", zh: "操作",
    /// The "Event time" event facts label.
    label_event_time: "Event time", zh: "事件时间",
    /// The "Source endpoint" event facts label.
    label_source_endpoint: "Source endpoint", zh: "来源端点",
    /// The "Event id" event facts label.
    label_event_id: "Event id", zh: "事件 ID",
    /// The "Current value" telemetry facts label.
    label_current_value: "Current value", zh: "当前值",
    /// The "Latest observed at" telemetry facts label.
    label_latest_observed_at: "Latest observed at", zh: "最近观察时间",
    /// The "Samples retained" telemetry facts label.
    label_samples_retained: "Samples retained", zh: "保留的采样数",
    /// The "Upstream feature" capability facts label.
    label_upstream_feature: "Upstream feature", zh: "上游功能",
    /// The "Endpoint ID" enrollment facts label.
    label_endpoint_id: "Endpoint ID", zh: "端点 ID",
    /// The "Initial generation" enrollment facts label.
    label_initial_generation: "Initial generation", zh: "初始代际",
    /// The "`MessageId`" diagnostics facts label.
    label_message_id: "MessageId", zh: "MessageId",
    /// The "Severity" diagnostics facts label.
    label_severity: "Severity", zh: "严重级别",
    /// The "Message" diagnostics facts label.
    label_message: "Message", zh: "消息",
    /// The "Resolution" diagnostics facts label.
    label_resolution: "Resolution", zh: "解决方案",
    /// The "`OData URI`" diagnostics facts label.
    label_odata_uri: "OData URI", zh: "OData URI",
    /// The "`OData Type`" diagnostics facts label.
    label_odata_type: "OData Type", zh: "OData 类型",
    /// The "nv-redfish feature" diagnostics facts label.
    label_nv_redfish_feature: "nv-redfish feature", zh: "nv-redfish 功能",
    /// The "OEM Namespace" diagnostics facts label.
    label_oem_namespace: "OEM Namespace", zh: "OEM 命名空间",
    /// The "Decode error" diagnostics facts label.
    label_decode_error: "Decode error", zh: "解码错误",
    /// The `ETag` diagnostics facts label.
    label_etag: "ETag", zh: "ETag",
    /// The `ExtendedInfo` diagnostics section label.
    label_extended_info: "ExtendedInfo", zh: "ExtendedInfo",
    /// The "Decode failures in this refresh" diagnostics section label.
    label_decode_failures: "Decode failures in this refresh", zh: "本次刷新中的解码失败",
    /// The "Decoded typed payload" diagnostics section label.
    label_decoded_payload: "Decoded typed payload", zh: "已解码的类型化载荷",
    /// The "Health" results-table header.
    table_health: "Health", zh: "健康状态",
    /// The "Result" results-table header.
    table_result: "Result", zh: "结果",
    /// The "Detail" results-table header.
    table_detail: "Detail", zh: "详情",
    /// The "Row" import-table header.
    table_row: "Row", zh: "行",
    /// The "Size" artifact facts label.
    label_size: "Size", zh: "大小",
    /// The "SHA-256" artifact facts label.
    label_sha256: "SHA-256", zh: "SHA-256",

    /// The "Center connection" center-section label.
    section_center_connection: "Center connection", zh: "中心连接",
    /// The "Site detail" center-section label.
    section_site_detail: "Site detail", zh: "站点详情",
    /// The "Administration" user-admin heading.
    section_administration: "Administration", zh: "管理",
    /// The "Create group" section label and submit button.
    section_create_group: "Create group", zh: "创建分组",
    /// The "Tags" section label.
    section_tags: "Tags", zh: "标签",
    /// The "Members" section label.
    section_members: "Members", zh: "成员",
    /// The "Add members" section label.
    section_add_members: "Add members", zh: "添加成员",
    /// The "Group detail" section label.
    section_group_detail: "Group detail", zh: "分组详情",
    /// The "Group" group-detail facts label.
    section_group: "Group", zh: "分组",
    /// The "Protected BMC access" credentials section label.
    section_protected_bmc_access: "Protected BMC access", zh: "受保护的 BMC 访问",
    /// The "Create credential" section label.
    section_create_credential: "Create credential", zh: "创建凭据",
    /// The "Onboarding" section label.
    section_onboarding: "Onboarding", zh: "接入引导",
    /// The "TLS identity observed" onboarding panel label.
    section_tls_identity_observed: "TLS identity observed", zh: "已观察到 TLS 身份",
    /// The "Established trust" onboarding panel label.
    section_established_trust: "Established trust", zh: "已建立信任",
    /// The "Credential" onboarding panel label.
    section_credential: "Credential", zh: "凭据",
    /// The "New credential" onboarding panel label.
    section_new_credential: "New credential", zh: "新凭据",
    /// The "Enrollment complete" onboarding panel label.
    section_enrollment_complete: "Enrollment complete", zh: "注册完成",
    /// The "Endpoint enrolled" onboarding panel heading.
    section_endpoint_enrolled: "Endpoint enrolled", zh: "端点已注册",
    /// The "Bulk onboarding" import section label.
    section_bulk_onboarding: "Bulk onboarding", zh: "批量接入",
    /// The "Import endpoints" import section heading.
    section_import_endpoints: "Import endpoints", zh: "导入端点",
    /// The "Import report" results panel label.
    section_import_report: "Import report", zh: "导入报告",
    /// The "Refresh report" results panel label.
    section_refresh_report: "Refresh report", zh: "刷新报告",
    /// The "Compliance" audit section label.
    section_compliance: "Compliance", zh: "合规",
    /// The "Event history" events section label.
    section_event_history: "Event history", zh: "事件历史",
    /// The "Capabilities" drill-down section label.
    section_capabilities: "Capabilities", zh: "能力",
    /// The "Operation tasks" operations section label.
    section_operation_tasks: "Operation tasks", zh: "操作任务",
    /// The "Batch operations" operations section label.
    section_batch_operations: "Batch operations", zh: "批处理操作",
    /// The "Submit operation" form section label.
    section_submit_operation: "Submit operation", zh: "提交操作",
    /// The "Targets" form section label.
    section_targets: "Targets", zh: "目标",
    /// The "Command" form section label.
    section_command: "Command", zh: "命令",
    /// The "Firmware artifacts" artifacts section label.
    section_firmware_artifacts: "Firmware artifacts", zh: "固件包",
    /// The "Latest readings" telemetry section label.
    section_latest_readings: "Latest readings", zh: "最新读数",
    /// The "Core resources" overview section label.
    section_core_resources: "Core resources", zh: "核心资源",
    /// The "Dispatch a center operation" form section label.
    section_dispatch_center_operation: "Dispatch a center operation", zh: "派发中心操作",
    /// The "Register a site" bindings form label.
    section_register_site: "Register a site", zh: "注册站点",
    /// The "One-time binding code" bindings panel label.
    section_one_time_binding_code: "One-time binding code", zh: "一次性绑定码",
    /// The "Active bindings" bindings panel label.
    section_active_bindings: "Active bindings", zh: "活动绑定",

    /// The auth screen loading aria-label.
    aria_loading: "Loading", zh: "正在加载",
    /// The "Rutilus" product name in the console header (brand noun).
    label_rutilus: "Rutilus", zh: "Rutilus",
    /// The "First-run setup" bootstrap screen heading and aria-label.
    label_first_run_setup: "First-run setup", zh: "首次运行设置",
    /// The session-table time prefix "created ".
    label_suffix_created: "created ", zh: "创建于 ",
    /// The session-table time prefix "used ".
    label_suffix_used: "used ", zh: "使用于 ",
    /// The session-table time prefix "expires ".
    label_suffix_expires: "expires ", zh: "过期于 ",
    /// The "OEM face" operation form label.
    label_oem_face: "OEM face", zh: "OEM 界面",
    /// The "Subscription id" center-operation form label (center spelling).
    label_subscription_id_lower: "Subscription id", zh: "订阅 ID",
    /// The " · endpoint " joiner of the event-card source line.
    label_endpoint_joiner: " · endpoint ", zh: " · 端点 ",
    /// The "endpoint " prefix of the telemetry-card series line.
    label_endpoint_joiner_plain: "endpoint ", zh: "端点 ",
    /// The "Unknown endpoint" display name of a group member that left the
    /// inventory.
    label_unknown_endpoint: "Unknown endpoint", zh: "未知端点",
    /// The aria-label of the language selector.
    label_language: "Language", zh: "语言",
    /// The English option label of the language selector.
    lang_en: "English", zh: "英语",
    /// The Chinese option label of the language selector.
    lang_zh: "中文", zh: "中文",
    /// The aria-label of the endpoint selection checkbox.
    aria_select_endpoint: "Select this endpoint for refresh", zh: "选择此端点以刷新",
    /// The title attribute of the unified endpoint health badge.
    title_unified_endpoint_health: "Unified endpoint health", zh: "统一端点健康状态",

    /// The "Checking…" auth loading note.
    loading_auth: "Checking…", zh: "正在检查……",
    /// The "Loading registered sites..." center status.
    loading_center_sites: "Loading registered sites...", zh: "正在加载注册站点……",
    /// The "Loading aggregated endpoints..." center status.
    loading_aggregated_endpoints: "Loading aggregated endpoints...", zh: "正在加载聚合端点……",
    /// The "Loading center operations..." center status.
    loading_center_operations: "Loading center operations...", zh: "正在加载中心操作……",
    /// The "Loading bindings..." center status.
    loading_bindings: "Loading bindings...", zh: "正在加载绑定……",
    /// The "Loading groups..." groups status.
    loading_groups: "Loading groups...", zh: "正在加载分组……",
    /// The "Loading tags..." tags status.
    loading_tags: "Loading tags...", zh: "正在加载标签……",
    /// The "Loading group detail..." group status.
    loading_group_detail: "Loading group detail...", zh: "正在加载分组详情……",
    /// The "Loading capability list..." capability status.
    loading_capabilities: "Loading capability list...", zh: "正在加载能力列表……",
    /// The "Loading diagnostics..." diagnostics status.
    loading_diagnostics: "Loading diagnostics...", zh: "正在加载诊断信息……",
    /// The "Loading operations..." operations status.
    loading_operations: "Loading operations...", zh: "正在加载操作……",
    /// The "Loading batches..." operations status.
    loading_batches: "Loading batches...", zh: "正在加载批处理……",
    /// The "Loading firmware artifacts..." update status.
    loading_firmware_artifacts: "Loading firmware artifacts...", zh: "正在加载固件包……",
    /// The "Loading artifacts..." artifacts status.
    loading_artifacts: "Loading artifacts...", zh: "正在加载固件包……",
    /// The "Creating the credential..." credential status.
    loading_credential_create: "Creating the credential...", zh: "正在创建凭据……",
    /// The "Creating artifact..." artifact status.
    loading_artifact_create: "Creating artifact...", zh: "正在创建固件包……",
    /// The "Verifying the uploaded digest..." artifact status.
    loading_verify_digest: "Verifying the uploaded digest...", zh: "正在验证上传的摘要……",
    /// The "Submitting the operation..." operation status.
    loading_submit: "Submitting the operation...", zh: "正在提交操作……",

    /// The "Group created." success message.
    success_group_created: "Group created.", zh: "分组已创建。",
    /// The "Tag updated." success message.
    success_tag_updated: "Tag updated.", zh: "标签已更新。",
    /// The "Members updated." success message.
    success_members_updated: "Members updated.", zh: "成员已更新。",
    /// The "Credential created." success message.
    success_credential_created: "Credential created.", zh: "凭据已创建。",
    /// The "Credential created and selected." success message.
    success_credential_created_selected: "Credential created and selected.", zh: "凭据已创建并选择。",
    /// The "Artifact uploaded and verified." success message.
    success_artifact_uploaded: "Artifact uploaded and verified.", zh: "固件包已上传并通过验证。",
    /// The "Operation submitted." success message.
    success_operation_submitted: "Operation submitted.", zh: "操作已提交。",
    /// The "The operation was dispatched to the site." success message.
    success_dispatched: "The operation was dispatched to the site.", zh: "操作已派发到站点。",
    /// The "The binding was revoked; the site converges on its next connection." success message.
    success_binding_revoked: "The binding was revoked; the site converges on its next connection.", zh: "绑定已撤销；站点将在下次连接时收敛。",

    /// The registered-site list unavailable message.
    unavailable_center_sites: "The registered-site list is temporarily unavailable.", zh: "注册站点列表暂时不可用。",
    /// The aggregated endpoint list unavailable message.
    unavailable_aggregated_endpoints: "The aggregated endpoint list is temporarily unavailable.", zh: "聚合端点列表暂时不可用。",
    /// The center operation list unavailable message.
    unavailable_center_operations: "The center operation list is temporarily unavailable.", zh: "中心操作列表暂时不可用。",
    /// The binding list unavailable message.
    unavailable_bindings: "The binding list is temporarily unavailable.", zh: "绑定列表暂时不可用。",
    /// The user list unavailable message.
    unavailable_users: "The user list is temporarily unavailable.", zh: "用户列表暂时不可用。",
    /// The session list unavailable message.
    unavailable_sessions: "The session list is temporarily unavailable.", zh: "会话列表暂时不可用。",
    /// The tag list unavailable message.
    unavailable_tags: "The tag list is temporarily unavailable.", zh: "标签列表暂时不可用。",
    /// The credential inventory unavailable message.
    unavailable_credentials: "The credential inventory is temporarily unavailable.", zh: "凭据清单暂时不可用。",
    /// The audit log unavailable message.
    unavailable_audit: "The audit log is temporarily unavailable.", zh: "审计日志暂时不可用。",
    /// The event history unavailable message.
    unavailable_events: "The event history is temporarily unavailable.", zh: "事件历史暂时不可用。",
    /// The telemetry history unavailable message.
    unavailable_telemetry: "The telemetry history is temporarily unavailable.", zh: "遥测历史暂时不可用。",
    /// The capability list unavailable message.
    unavailable_capabilities: "The capability list is temporarily unavailable.", zh: "能力列表暂时不可用。",
    /// The operation list unavailable message.
    unavailable_operations: "The operation list is temporarily unavailable.", zh: "操作列表暂时不可用。",
    /// The batch list unavailable message.
    unavailable_batches: "The batch list is temporarily unavailable.", zh: "批处理列表暂时不可用。",
    /// The firmware artifact list unavailable message.
    unavailable_firmware_artifacts: "The firmware artifact list is temporarily unavailable.", zh: "固件包列表暂时不可用。",
    /// The artifact store unavailable message.
    unavailable_artifacts: "The artifact store is temporarily unavailable.", zh: "固件包存储暂时不可用。",
    /// The overview aggregate unavailable message.
    unavailable_overview: "The overview is temporarily unavailable.", zh: "总览暂时不可用。",
    /// The refresh service unavailable message.
    unavailable_refresh: "The refresh service is temporarily unavailable.", zh: "刷新服务暂时不可用。",
    /// The import service unavailable message.
    unavailable_import: "The import service is temporarily unavailable.", zh: "导入服务暂时不可用。",

    /// The "No sites are registered yet. Register a site on the Center bindings page." empty state.
    empty_center_sites: "No sites are registered yet. Register a site on the Center bindings page.", zh: "尚未注册任何站点。请在中心绑定页面注册一个站点。",
    /// The "This site has not projected any endpoints yet." empty state.
    empty_site_endpoints: "This site has not projected any endpoints yet.", zh: "此站点尚未投影出任何端点。",
    /// The "No center operations have been dispatched yet." empty state.
    empty_center_operations: "No center operations have been dispatched yet.", zh: "尚未派发任何中心操作。",
    /// The "No sites are registered yet." bindings empty state.
    empty_bindings: "No sites are registered yet.", zh: "尚未注册任何站点。",
    /// The "No endpoints are managed yet. Add a trusted BMC endpoint to begin." empty state.
    empty_no_endpoints_managed: "No endpoints are managed yet. Add a trusted BMC endpoint to begin.", zh: "尚未管理任何端点。请先添加受信任的 BMC 端点。",
    /// The "No endpoints match the current filters." empty state.
    empty_no_endpoints_match: "No endpoints match the current filters.", zh: "没有端点匹配当前筛选条件。",
    /// The "No events have been observed yet." overview empty state.
    empty_no_events_observed: "No events have been observed yet.", zh: "尚未观察到任何事件。",
    /// The "No groups have been created yet. Create a group to organize endpoints." empty state.
    empty_groups: "No groups have been created yet. Create a group to organize endpoints.", zh: "尚未创建任何分组。请创建一个分组来组织端点。",
    /// The "No members yet. Add endpoints below." empty state.
    empty_group_members: "No members yet. Add endpoints below.", zh: "暂无成员。请在下方向分组添加端点。",
    /// The "Every managed endpoint is already in this group." empty state.
    empty_group_all_members: "Every managed endpoint is already in this group.", zh: "所有受管端点都已在当前分组中。",
    /// The "No endpoints carry this tag yet." empty state.
    empty_tag_endpoints: "No endpoints carry this tag yet.", zh: "尚无端点带有此标签。",
    /// The "No tags have been applied yet." empty state.
    empty_tags: "No tags have been applied yet.", zh: "尚未应用任何标签。",
    /// The "No credentials are stored yet. Create the first one below." empty state.
    empty_credentials: "No credentials are stored yet. Create the first one below.", zh: "尚未存储任何凭据。请先创建第一条凭据。",
    /// The "No audit events have been recorded yet." empty state.
    empty_audit: "No audit events have been recorded yet.", zh: "尚未记录任何审计事件。",
    /// The "No events have been recorded yet." empty state.
    empty_events: "No events have been recorded yet.", zh: "尚未记录任何事件。",
    /// The "No telemetry series have been sampled yet. Refresh the endpoint inventory to capture readings." empty state.
    empty_telemetry: "No telemetry series have been sampled yet. Refresh the endpoint inventory to capture readings.", zh: "尚未采样任何遥测序列。请刷新端点清单以采集读数。",
    /// The "No capability data is available for this endpoint yet." empty state.
    empty_capabilities: "No capability data is available for this endpoint yet.", zh: "此端点尚无可用能力数据。",
    /// The "No operations have been submitted yet." empty state.
    empty_operations: "No operations have been submitted yet.", zh: "尚未提交任何操作。",
    /// The "No batch operations have been submitted yet." empty state.
    empty_batches: "No batch operations have been submitted yet.", zh: "尚未提交任何批处理操作。",
    /// The "No ready firmware artifacts. Upload and finalize one in the Artifacts view." empty state.
    empty_firmware_artifacts: "No ready firmware artifacts. Upload and finalize one in the Artifacts view.", zh: "没有就绪的固件包。请在固件包视图中上传并完成一个。",
    /// The "No firmware artifacts have been uploaded yet." empty state.
    empty_artifacts: "No firmware artifacts have been uploaded yet.", zh: "尚未上传任何固件包。",
    /// The "No resource counts are published until a complete refresh succeeds." notice.
    notice_no_resource_counts: "No resource counts are published until a complete refresh succeeds.", zh: "在完整刷新成功之前不会发布资源计数。",

    /// The "Choose a site..." center selector placeholder.
    choose_site: "Choose a site...", zh: "选择站点……",
    /// The "Choose an endpoint..." center selector placeholder.
    choose_endpoint: "Choose an endpoint...", zh: "选择端点……",
    /// The "Choose a family..." center selector placeholder.
    choose_family: "Choose a family...", zh: "选择命令族……",
    /// The "Choose a reset type" selector placeholder.
    choose_reset_type: "Choose a reset type", zh: "选择重置类型",
    /// The "Choose a reset type..." center selector placeholder.
    choose_reset_type_ellipsis: "Choose a reset type...", zh: "选择重置类型……",
    /// The "Choose a boot source" selector placeholder.
    choose_boot_source: "Choose a boot source", zh: "选择启动源",
    /// The "Choose a boot source..." center selector placeholder.
    choose_boot_source_ellipsis: "Choose a boot source...", zh: "选择启动源……",
    /// The "Choose" compact selector placeholder.
    choose: "Choose", zh: "选择",
    /// The "Choose..." compact selector placeholder.
    choose_ellipsis: "Choose...", zh: "选择……",
    /// The "Choose a mode..." center selector placeholder.
    choose_mode: "Choose a mode...", zh: "选择模式……",
    /// The "Choose a key set" selector placeholder.
    choose_key_set: "Choose a key set", zh: "选择密钥集",
    /// The "Choose a key set..." center selector placeholder.
    choose_key_set_ellipsis: "Choose a key set...", zh: "选择密钥集……",
    /// The "Choose a protocol" selector placeholder.
    choose_protocol: "Choose a protocol", zh: "选择协议",
    /// The "Choose a protocol..." center selector placeholder.
    choose_protocol_ellipsis: "Choose a protocol...", zh: "选择协议……",
    /// The "Choose an artifact" selector placeholder.
    choose_artifact: "Choose an artifact", zh: "选择固件包",
    /// The "Choose an OEM face" selector placeholder.
    choose_oem_face: "Choose an OEM face", zh: "选择 OEM 界面",
    /// The "Choose a token type" selector placeholder.
    choose_token_type: "Choose a token type", zh: "选择令牌类型",
    /// The "Choose an erase scope" selector placeholder.
    choose_erase_scope: "Choose an erase scope", zh: "选择擦除范围",
    /// The "Select an endpoint..." tag-form selector placeholder.
    select_endpoint: "Select an endpoint...", zh: "选择端点……",

    /// The "0 registered sites" center count text.
    fmt_aggregated_endpoints_one: "1 aggregated endpoint", zh: "1 个聚合端点",
    /// The "{count} aggregated endpoints" center count text.
    fmt_aggregated_endpoints_many: "{count} aggregated endpoints", zh: "{count} 个聚合端点",
    /// The "1 managed endpoint" console count text.
    count_endpoints_one: "1 managed endpoint", zh: "1 个受管端点",
    /// The "2 managed endpoints" console count text (generic form).
    count_endpoints_many: "{count} managed endpoints", zh: "{count} 个受管端点",
    /// The "1 stored credential" credentials count text.
    count_credentials_one: "1 stored credential", zh: "1 条已存凭据",
    /// The "0 stored credentials" credentials count text.
    count_credentials_many: "{count} stored credentials", zh: "{count} 条已存凭据",
    /// The "1 audit event" audit count text.
    count_audit_events_one: "1 audit event", zh: "1 条审计事件",
    /// The "N audit events" audit count text.
    count_audit_events_many: "{count} audit events", zh: "{count} 条审计事件",
    /// The "1 event" events count text.
    count_events_one: "1 event", zh: "1 条事件",
    /// The "N events" events count text.
    count_events_many: "{count} events", zh: "{count} 条事件",
    /// The "Showing the latest 1 event" events bound text.
    count_events_latest_one: "Showing the latest 1 event", zh: "显示最新 1 条事件",
    /// The "Showing the latest N events" events bound text.
    count_events_latest_many: "Showing the latest {count} events", zh: "显示最新 {count} 条事件",
    /// The "1 series" telemetry count text.
    count_series_one: "1 series", zh: "1 个序列",
    /// The "N series" telemetry count text.
    count_series_many: "{count} series", zh: "{count} 个序列",
    /// The "1 operation" operations count text.
    count_operations_one: "1 operation", zh: "1 个操作",
    /// The "N operations" operations count text.
    count_operations_many: "{count} operations", zh: "{count} 个操作",
    /// The "1 artifact" artifacts count text.
    count_artifacts_one: "1 artifact", zh: "1 个固件包",
    /// The "N artifacts" artifacts count text.
    count_artifacts_many: "{count} artifacts", zh: "{count} 个固件包",
    /// The "1 batch" batches count text.
    count_batches_one: "1 batch", zh: "1 个批处理",
    /// The "N batches" batches count text.
    count_batches_many: "{count} batches", zh: "{count} 个批处理",
    /// The "1 group" groups count text.
    count_groups_one: "1 group", zh: "1 个分组",
    /// The "N groups" groups count text.
    count_groups_many: "{count} groups", zh: "{count} 个分组",
    /// The "1 member" group member count text.
    count_members_one: "1 member", zh: "1 个成员",
    /// The "N members" group member count text.
    count_members_many: "{} members", zh: "{} 个成员",
    /// The "1 endpoint" tag endpoint count text.
    count_tag_endpoints_one: "1 endpoint", zh: "1 个端点",
    /// The "N endpoints" tag endpoint count text.
    count_tag_endpoints_many: "{} endpoints", zh: "{} 个端点",
    /// The "0 registered sites" center count text.
    count_registered_sites_zero: "0 registered sites", zh: "0 个注册站点",
    /// The "1 registered site" center count text.
    count_registered_sites_one: "1 registered site", zh: "1 个注册站点",
    /// The "N registered sites" center count text.
    count_registered_sites_many: "{count} registered sites", zh: "{count} 个注册站点",

    /// The operation-form error for an empty endpoint selection.
    error_endpoints_required: "Select at least one endpoint.", zh: "请至少选择一个端点。",
    /// The center-form error for a missing site.
    error_site_required: "A site must be selected.", zh: "必须选择一个站点。",
    /// The center-form error for a missing endpoint.
    error_endpoint_required: "An endpoint must be selected.", zh: "必须选择一个端点。",
    /// The center-form error for a missing Redfish target.
    error_target_required: "A Redfish target is required.", zh: "必须提供 Redfish 目标。",
    /// The sign-in error when the request could not be prepared.
    error_sign_in_unprepared: "the sign-in request could not be prepared", zh: "无法准备登录请求",
    /// The sign-in error when the request could not be sent.
    error_sign_in_unsent: "the sign-in request could not be sent", zh: "无法发送登录请求",
    /// The sign-in error when the server refused the credentials.
    error_sign_in_failed: "sign-in failed", zh: "登录失败",
    /// The sign-in error when the response could not be parsed.
    error_sign_in_unparsable: "the sign-in response could not be parsed", zh: "无法解析登录响应",
    /// The bootstrap error when the request could not be prepared.
    error_bootstrap_unprepared: "the bootstrap request could not be prepared", zh: "无法准备引导请求",
    /// The bootstrap error when the request could not be sent.
    error_bootstrap_unsent: "the bootstrap request could not be sent", zh: "无法发送引导请求",
    /// The bootstrap error when the one-time code was refused.
    error_bootstrap_code: "bootstrap failed — check the one-time code", zh: "引导失败——请检查一次性引导码",
    /// The bootstrap error when the response could not be parsed.
    error_bootstrap_unparsable: "the bootstrap response could not be parsed", zh: "无法解析引导响应",
    /// The operation-form error for a missing command family.
    error_family_required: "Choose a command family.", zh: "请选择命令族。",
    /// The operation-form error for a missing account action.
    error_account_action_required: "Choose an account action.", zh: "请选择账户操作。",
    /// The operation-form error for a missing account id.
    error_account_id_required: "An account ID is required.", zh: "必须提供账户 ID。",
    /// The operation-form error for an invalid account id.
    error_account_id_invalid: "The account ID can only contain letters, digits, '-', and '_'.", zh: "账户 ID 只能包含字母、数字、'-' 和 '_'。",
    /// The operation-form error for a missing account user name.
    error_account_user_name_required: "A user name is required.", zh: "必须提供用户名。",
    /// The operation-form error for an invalid account user name.
    error_account_user_name_invalid: "The user name contains unsupported characters.", zh: "用户名包含不支持的字符。",
    /// The operation-form error for an oversized account password.
    error_account_password_invalid: "The password is too long.", zh: "密码过长。",
    /// The operation-form error for a missing role id.
    error_role_id_required: "A role ID is required.", zh: "必须提供角色 ID。",
    /// The operation-form error for an invalid role id.
    error_role_id_invalid: "The role ID contains unsupported characters.", zh: "角色 ID 包含不支持的字符。",
    /// The operation-form error for a missing reset type.
    error_reset_type_required: "Choose a reset type.", zh: "请选择重置类型。",
    /// The operation-form error for a missing boot source.
    error_boot_source_required: "Choose a boot source.", zh: "请选择启动源。",
    /// The operation-form error for a missing boot override duration.
    error_boot_enabled_required: "Choose how long the override applies.", zh: "请选择覆盖的生效时长。",
    /// The operation-form error for a missing boot mode.
    error_boot_mode_required: "Choose a boot mode.", zh: "请选择启动模式。",
    /// The operation-form error for a missing Secure Boot action.
    error_secure_boot_action_required: "Choose a Secure Boot action.", zh: "请选择安全启动操作。",
    /// The operation-form error for a missing key set.
    error_reset_keys_type_required: "Choose the key set to reset.", zh: "请选择要重置的密钥集。",
    /// The operation-form error for a missing event action.
    error_event_action_required: "Choose an event action.", zh: "请选择事件操作。",
    /// The operation-form error for a missing destination.
    error_destination_required: "A destination URL is required.", zh: "必须提供目标 URL。",
    /// The operation-form error for an invalid destination.
    error_destination_invalid: "The destination must be a URL with a host.", zh: "目标必须是包含主机名的 URL。",
    /// The operation-form error for a missing protocol.
    error_protocol_required: "Choose a delivery protocol.", zh: "请选择投递协议。",
    /// The operation-form error for an empty event type set.
    error_event_types_required: "Select at least one event type.", zh: "请至少选择一种事件类型。",
    /// The operation-form error for a missing subscription id.
    error_subscription_id_required: "A subscription ID is required.", zh: "必须提供订阅 ID。",
    /// The operation-form error for a missing firmware artifact.
    error_artifact_required: "Choose a ready firmware artifact.", zh: "请选择就绪的固件包。",
    /// The operation-form error for an invalid push URI.
    error_push_uri_invalid: "The push URI must be an http(s) URL.", zh: "推送 URI 必须是 http(s) URL。",
    /// The operation-form error for a missing OEM action.
    error_oem_action_required: "Choose an OEM action.", zh: "请选择 OEM 操作。",
    /// The operation-form error for a missing profile file.
    error_profile_file_required: "The profile file JSON is required.", zh: "必须提供配置文件 JSON。",
    /// The operation-form error for a missing token type.
    error_token_type_required: "Choose a token type.", zh: "请选择令牌类型。",
    /// The operation-form error for missing token data.
    error_token_data_required: "The Base64 token data is required.", zh: "必须提供 Base64 令牌数据。",
    /// The operation-form error for a missing erase scope.
    error_erase_type_required: "Choose the erase scope.", zh: "请选择擦除范围。",
    /// The operation-form error for an invalid profile id.
    error_profile_id_invalid: "The profile id must be a whole number.", zh: "配置文件 ID 必须是整数。",
    /// The credential-draft error for a missing credential name.
    error_credential_name_required: "A credential name is required.", zh: "必须提供凭据名称。",
    /// The credential-draft error for control characters in the name.
    error_credential_name_control: "The credential name cannot contain control characters.", zh: "凭据名称不能包含控制字符。",
    /// The credential-draft error for an oversized credential name.
    error_credential_name_too_long: "The credential name cannot exceed 128 characters.", zh: "凭据名称不能超过 128 个字符。",
    /// The credential-draft error for a missing BMC username.
    error_bmc_username_required: "A BMC username is required.", zh: "必须提供 BMC 用户名。",
    /// The credential-draft error for control characters in the username.
    error_bmc_username_control: "The username cannot contain control characters.", zh: "用户名不能包含控制字符。",
    /// The credential-draft error for an oversized username.
    error_bmc_username_too_long: "The username cannot exceed 256 characters.", zh: "用户名不能超过 256 个字符。",
    /// The credential-draft error for an oversized password.
    error_password_too_large: "The password cannot exceed 4 KiB.", zh: "密码不能超过 4 KiB。",
    /// The address-draft error for an empty address.
    error_address_required: "An endpoint address is required.", zh: "必须提供端点地址。",
    /// The address-draft error for a non-HTTPS address.
    error_address_scheme: "The endpoint address must use https://.", zh: "端点地址必须使用 https://。",
    /// The address-draft error for an address without a host.
    error_address_host: "The endpoint address must include a host.", zh: "端点地址必须包含主机名。",
    /// The address-draft error for whitespace in the address.
    error_address_whitespace: "The endpoint address cannot contain whitespace.", zh: "端点地址不能包含空白字符。",
    /// The address-draft error for embedded credentials.
    error_address_credentials: "The endpoint address must not embed credentials.", zh: "端点地址不得内嵌凭据。",
    /// The address-draft error for a query or fragment.
    error_address_query_fragment: "The endpoint address must not contain a query or fragment.", zh: "端点地址不得包含查询串或片段。",
    /// The display-name draft error for an empty name.
    error_display_name_required: "A display name is required.", zh: "必须提供显示名称。",
    /// The display-name draft error for control characters.
    error_display_name_control: "The display name cannot contain control characters.", zh: "显示名称不能包含控制字符。",
    /// The enrollment-draft error for a missing credential.
    error_enrollment_credential_required: "Select or create a credential before enrolling.", zh: "注册前请选择或创建凭据。",
    /// The user-admin draft error for an empty user name.
    error_user_name_required: "the user name is required", zh: "必须提供用户名",
    /// The site-registration error for an empty display name.
    error_site_display_name_required: "A site display name is required.", zh: "必须提供站点显示名称。",
    /// The site-registration error for an empty center URL.
    error_center_url_required: "The center URL is required.", zh: "必须提供中心 URL。",
    /// The group-name draft error for an empty name.
    error_group_name_required: "A group name is required.", zh: "必须提供分组名称。",
    /// The group-name draft error for control characters.
    error_group_name_control: "The group name cannot contain control characters.", zh: "分组名称不能包含控制字符。",
    /// The group-name draft error for an oversized name.
    error_group_name_too_long: "The group name cannot exceed 64 characters.", zh: "分组名称不能超过 64 个字符。",
    /// The tag draft error for a missing endpoint.
    error_tag_endpoint_required: "Select the endpoint to tag.", zh: "请选择要打标签的端点。",
    /// The tag draft error for an empty name.
    error_tag_name_required: "A tag name is required.", zh: "必须提供标签名称。",
    /// The tag draft error for control characters.
    error_tag_name_control: "A tag name cannot contain control characters.", zh: "标签名称不能包含控制字符。",
    /// The tag draft error for an oversized name.
    error_tag_name_too_long: "A tag name cannot exceed 64 characters.", zh: "标签名称不能超过 64 个字符。",
    /// The group-create failure message.
    error_group_create: "The group could not be created.", zh: "无法创建分组。",
    /// The group-member-add failure message.
    error_group_members_add: "One or more endpoints could not be added to the group.", zh: "有一个或多个端点无法添加到分组。",
    /// The group-member-remove failure message.
    error_group_member_remove: "The member could not be removed from the group.", zh: "无法从分组中移除该成员。",
    /// The tag-apply failure message.
    error_tag_apply: "The tag could not be applied.", zh: "无法应用标签。",
    /// The tag-remove failure message.
    error_tag_remove: "The tag could not be removed.", zh: "无法移除标签。",
    /// The credential-create failure message of the onboarding step.
    error_credential_create_rejected: "The credential could not be created.", zh: "无法创建凭据。",
    /// The credential-create failure message of the credential form.
    error_credential_create: "The credential could not be created. Check the fields and try again.", zh: "无法创建凭据。请检查字段后重试。",
    /// The user-create failure message.
    error_user_create: "The user could not be created.", zh: "无法创建用户。",
    /// The TLS observation failure message.
    error_tls_unobservable: "The TLS identity could not be observed. Check that the address is reachable over HTTPS.", zh: "无法观察 TLS 身份。请检查该地址是否可通过 HTTPS 访问。",
    /// The trust-policy verification failure message.
    error_tls_policy_unverified: "The confirmed trust policy could not be verified. The observed certificate may have changed.", zh: "无法验证已确认的信任策略。观察到的证书可能已发生变化。",
    /// The enrollment failure message.
    error_enrollment_failed: "The endpoint could not be enrolled with the selected credential.", zh: "无法使用所选凭据注册该端点。",
    /// The refresh rejection message, with the HTTP status interpolated.
    error_refresh_rejected: "The server rejected the refresh request (HTTP {status}).", zh: "服务器拒绝了刷新请求（HTTP {status}）。",
    /// The import rejection message, with the HTTP status interpolated.
    error_import_rejected: "The server rejected the import request (HTTP {status}).", zh: "服务器拒绝了导入请求（HTTP {status}）。",
    /// The artifact-create rejection message, with the HTTP status interpolated.
    error_artifact_create_rejected: "The server rejected the artifact creation (HTTP {status}).", zh: "服务器拒绝了固件包创建（HTTP {status}）。",
    /// The upload-chunk rejection message, with the HTTP status interpolated.
    error_artifact_chunk_rejected: "The server rejected an upload chunk (HTTP {status}).", zh: "服务器拒绝了一个上传分块（HTTP {status}）。",
    /// The upload-finalize rejection message, with the HTTP status interpolated.
    error_artifact_finalize_rejected: "The server rejected the upload finalize (HTTP {status}).", zh: "服务器拒绝了上传完成操作（HTTP {status}）。",
    /// The SHA-256 verification failure message.
    error_artifact_digest: "The uploaded bytes did not pass SHA-256 verification.", zh: "上传的字节未通过 SHA-256 验证。",
    /// The center-unreachable message.
    error_center_unreachable: "The center did not answer.", zh: "中心未响应。",
    /// The center submission-refused message.
    error_center_submission_refused: "The center refused the submission.", zh: "中心拒绝了提交。",
    /// The centre acknowledgement-unparsable message.
    error_center_ack_unparsable: "The acknowledgement could not be parsed.", zh: "无法解析确认信息。",
    /// The center registration-unprepared message.
    error_center_registration_unprepared: "The registration could not be prepared.", zh: "无法准备注册。",
    /// The center registration-refused message.
    error_center_registration_refused: "The center refused the registration.", zh: "中心拒绝了注册。",
    /// The centre binding-code-unparsable message.
    error_center_binding_code_unparsable: "The binding code could not be parsed.", zh: "无法解析绑定码。",
    /// The revocation-refused message.
    error_revocation_refused: "The revocation was refused; the binding is unchanged.", zh: "撤销被拒绝；绑定保持不变。",
    /// The endpoint-missing capability message.
    error_endpoint_missing: "This endpoint no longer exists.", zh: "该端点已不存在。",

    /// The first-run hint describing the bootstrap code.
    hint_bootstrap_intro: "Enter the one-time bootstrap code printed by the console to set the administrator password.", zh: "输入控制台打印的一次性引导码以设置管理员密码。",
    /// The center-sites section hint.
    hint_center_sites: "The §15.5 registered-site view: bindings, presence, and aggregated endpoints.", zh: "§15.5 注册站点视图：绑定、在线状态与聚合端点。",
    /// The center-operations section hint.
    hint_center_operations: "The §15.6 tracking view and the typed dispatch form.", zh: "§15.6 跟踪视图与类型化派发表单。",
    /// The groups section hint.
    hint_groups: "Static groups for organizing managed endpoints", zh: "用于组织受管端点的静态分组",
    /// The create-group panel hint.
    hint_group_intro: "A static group collects managed endpoints for the Overview filter and bulk actions.", zh: "静态分组为总览筛选和批量操作收集受管端点。",
    /// The operation-submit failure message.
    error_operation_submit: "The operation could not be submitted. Check the fields and try again.", zh: "无法提交操作。请检查字段后重试。",
    /// The group-list unavailable message.
    unavailable_groups: "The group list is temporarily unavailable.", zh: "分组列表暂时不可用。",
    /// The group-detail unavailable message.
    unavailable_group_detail: "The group detail is temporarily unavailable.", zh: "分组详情暂时不可用。",
    /// The tag-inventory unavailable message.
    unavailable_tag_inventory: "The tag inventory is temporarily unavailable.", zh: "标签清单暂时不可用。",
    /// The diagnostics-snapshot unavailable message.
    unavailable_diagnostics: "The diagnostics snapshot is temporarily unavailable.", zh: "诊断快照暂时不可用。",
    /// The tags section hint.
    hint_tags: "Tags label endpoints for the Overview tag filter.", zh: "标签为总览页的标签筛选标记端点。",
    /// The credentials section hint.
    hint_credentials: "Reusable credentials never leave this device unencrypted.", zh: "可复用凭据绝不会以未加密形式离开本设备。",
    /// The onboarding hint that trust comes first.
    hint_onboarding_trust: "Trust is established before any credential is transmitted.", zh: "在传输任何凭据之前先建立信任。",
    /// The onboarding hint that no secret leaves before trust.
    hint_tls_first: "Rutilus first observes the TLS identity without credentials. No secret is sent before trust is confirmed.", zh: "Rutilus 首先在不使用凭据的情况下观察 TLS 身份。在信任确认前不会发送任何机密信息。",
    /// The onboarding hint that no credential was sent yet.
    hint_no_credential_sent: "No credential has been sent to this device. Confirm the identity to record the trust decision before authentication.", zh: "尚未向此设备发送凭据。请确认身份以在认证前记录信任决策。",
    /// The enrollment hint about credential choices.
    hint_enrollment_credential: "Choose an existing credential or create a new one. Credentials are encrypted before they are stored.", zh: "选择现有凭据或创建新凭据。凭据在存储前会进行加密。",
    /// The enrollment success hint about the first refresh.
    hint_enrollment_refresh: "The first complete core-resource refresh succeeded during enrollment.", zh: "注册期间首次完整核心资源刷新已成功。",
    /// The import hint describing the CSV columns.
    hint_import_one_row: "One row per BMC: display_name, address, credential_id, tls_sha256", zh: "每行一个 BMC：display_name, address, credential_id, tls_sha256",
    /// The audit section hint.
    hint_audit: "Immutable secret-free records, newest first", zh: "不可变且不含机密的记录，按最新优先",
    /// The events section hint.
    hint_events: "BMC event records, newest first", zh: "BMC 事件记录，按最新优先",
    /// The telemetry section hint.
    hint_telemetry: "Current values and bounded history, newest first", zh: "当前值与有限历史，按最新优先",
    /// The operations section hint.
    hint_operations: "Every write is a persisted, typed operation before it executes.", zh: "每次写入在执行前都是已持久化的类型化操作。",
    /// The batch operations section hint.
    hint_batches: "A multi-endpoint write is one batch with a per-endpoint outcome report.", zh: "多端点写入是一个批处理，并附有逐端点的结果报告。",
    /// The operation form hint.
    hint_operation_form: "Choose the target endpoints and the typed command. The submission is persisted before it is executed.", zh: "选择目标端点和类型化命令。提交在执行前会先持久化。",
    /// The update form hint that only ready artifacts dispatch.
    hint_update_only_ready: "Only artifacts with a verified complete upload (Ready) can be dispatched.", zh: "只有已通过完整上传验证（就绪）的固件包才能派发。",
    /// The update form hint about the push URI.
    hint_push_uri: "Leave empty to dispatch the locally stored artifact as multipart upload.", zh: "留空将以 multipart 上传方式派发本地存储的固件包。",
    /// The center dispatch hint about site re-checks.
    hint_site_rechecks: "The site re-checks every precondition and only accepts what it can execute (§15.6).", zh: "站点会重新检查每个前置条件，仅接受其可执行的操作（§15.6）。",
    /// The center dispatch hint about firmware artifacts.
    hint_firmware_dispatch: "Firmware updates dispatch from the site console, which holds the artifact.", zh: "固件更新从持有固件包的站点控制台派发。",
    /// The center dispatch hint about OEM profile files.
    hint_oem_profile_dispatch: "OEM profile files dispatch from the site console, which holds the file.", zh: "OEM 配置文件从持有文件的站点控制台派发。",
    /// The center dispatch hint that the telemetry form is later.
    hint_telemetry_later: "The telemetry write form is a later milestone.", zh: "遥测写入表单属于后续里程碑。",
    /// The bindings hint.
    hint_bindings: "Register a site and hand its one-time code to the site operator (design D2).", zh: "注册站点并将其一次性绑定码交给站点操作员（设计 D2）。",
    /// The bindings hint about the one-time code.
    hint_binding_code: "This code is shown exactly once. Hand it to the site operator; it expires at the shown time.", zh: "此绑定码仅显示一次。请将其交给站点操作员；它将在所示时间过期。",
    /// The artifacts section hint.
    hint_artifacts: "Uploaded firmware artifacts for the §14.3 update flow.", zh: "为 §14.3 更新流程上传的固件包。",
    /// The resume hint of the artifact upload form.
    hint_resume_same_file: "Select the same file in the upload form to resume from this point.", zh: "在上传表单中选择同一文件即可从此处继续。",

    /// The "Refresh selected" overview action.
    action_refresh_selected: "Refresh selected", zh: "刷新所选",
    /// The "Refresh inventory" overview action.
    action_refresh_inventory: "Refresh inventory", zh: "刷新清单",
    /// The "Clear filters" overview action.
    action_clear_filters: "Clear filters", zh: "清除筛选",
    /// The "View capabilities" endpoint-card action.
    action_view_capabilities: "View capabilities", zh: "查看能力",
    /// The "Apply tag" tag action.
    action_apply_tag: "Apply tag", zh: "应用标签",
    /// The "Manage members" group action.
    action_manage_members: "Manage members", zh: "管理成员",
    /// The "Back to groups" group action.
    action_back_to_groups: "Back to groups", zh: "返回分组",
    /// The "Remove" member action.
    action_remove: "Remove", zh: "移除",
    /// The "Add selected" group action.
    action_add_selected: "Add selected", zh: "添加所选",
    /// The "Untag" tag action.
    action_untag: "Untag", zh: "移除标签",
    /// The "Observe TLS identity" onboarding action.
    action_observe_tls_identity: "Observe TLS identity", zh: "观察 TLS 身份",
    /// The "Confirm trust and continue" onboarding action.
    action_confirm_trust: "Confirm trust and continue", zh: "确认信任并继续",
    /// The "Create a new credential" onboarding action.
    action_create_new_credential: "Create a new credential", zh: "创建新凭据",
    /// The "Create and select" onboarding action.
    action_create_and_select: "Create and select", zh: "创建并选择",
    /// The "Enroll endpoint" onboarding action.
    action_enroll_endpoint: "Enroll endpoint", zh: "注册端点",
    /// The "Add another endpoint" onboarding action.
    action_add_another_endpoint: "Add another endpoint", zh: "添加另一个端点",
    /// The "Import CSV" import action.
    action_import_csv: "Import CSV", zh: "导入 CSV",
    /// The "Back to overview" drill-down action.
    action_back_to_overview: "Back to overview", zh: "返回总览",
    /// The "Create user" user-admin action.
    action_create_user: "Create user", zh: "创建用户",
    /// The "Revoke" session action.
    action_revoke: "Revoke", zh: "撤销",
    /// The "Close detail" center action.
    action_close_detail: "Close detail", zh: "关闭详情",
    /// The "Dispatch operation" center action.
    action_dispatch_operation: "Dispatch operation", zh: "派发操作",
    /// The "Register site" center action.
    action_register_site: "Register site", zh: "注册站点",
    /// The "Set up" first-run action.
    action_set_up: "Set up", zh: "设置",
    /// The "Submit operation" form action.
    action_submit_operation: "Submit operation", zh: "提交操作",
    /// The "Hide endpoints" batch action.
    action_hide_endpoints: "Hide endpoints", zh: "隐藏端点",
    /// The "Show endpoints" batch action.
    action_show_endpoints: "Show endpoints", zh: "显示端点",
    /// The "Resume upload" artifact action.
    action_resume_upload: "Resume upload", zh: "继续上传",
    /// The "Upload artifact" artifact action.
    action_upload_artifact: "Upload artifact", zh: "上传固件包",

    /// The "enabled" user-state chip.
    chip_enabled: "enabled", zh: "已启用",
    /// The "disabled" user-state chip.
    chip_disabled: "disabled", zh: "已禁用",
    /// The "revoked" session-state chip.
    chip_revoked: "revoked", zh: "已撤销",
    /// The "current" session-state chip.
    chip_current: "current", zh: "当前",
    /// The "active" session-state chip.
    chip_active: "active", zh: "活动",
    /// The "no binding" center-site chip.
    chip_no_binding: "no binding", zh: "未绑定",
    /// The "online" center-site chip.
    chip_online: "online", zh: "在线",
    /// The "offline" center-site chip.
    chip_offline: "offline", zh: "离线",
    /// The "no refresh yet" center-site chip.
    chip_no_refresh_yet: "no refresh yet", zh: "尚未刷新",
    /// The "no target on record" center-operation chip.
    chip_no_target_on_record: "no target on record", zh: "无目标记录",

    /// The "Generation {} · observed {}" endpoint-card snapshot label.
    fmt_generation_observed: "Generation {} · observed {}", zh: "第 {} 代 · 观察于 {}",
    /// The "Generation {} — {} snapshots" refresh-row detail.
    fmt_generation_snapshots: "Generation {} — {} snapshots", zh: "第 {} 代 —— {} 个快照",
    /// The "1 of {total} endpoints shown" overview filter summary.
    fmt_endpoints_shown_one: "1 of {total} endpoints shown", zh: "共 {total} 个端点，已显示 1 个",
    /// The "{shown} of {total} endpoints shown" overview filter summary.
    fmt_endpoints_shown_many: "{shown} of {total} endpoints shown", zh: "已显示 {shown} 个，共 {total} 个端点",
    /// The "1 endpoint selected" overview selection summary.
    fmt_endpoints_selected_one: "1 endpoint selected", zh: "已选择 1 个端点",
    /// The "{count} endpoints selected" overview selection summary.
    fmt_endpoints_selected_many: "{count} endpoints selected", zh: "已选择 {count} 个端点",
    /// The "1 center operation" center count text.
    fmt_center_operations_one: "1 center operation", zh: "1 个中心操作",
    /// The "{count} center operations" center count text.
    fmt_center_operations_many: "{count} center operations", zh: "{count} 个中心操作",
    /// The "{entries} capabilities across {} pages" capability summary.
    fmt_capabilities_count: "{entries} capabilities across {} pages", zh: "{entries} 项能力，共 {} 页",
    /// The "{} of {} rows enrolled; {} failed" import summary.
    fmt_rows_enrolled: "{} of {} rows enrolled; {} failed", zh: "{} / {} 行已注册；{} 行失败",
    /// The "{} of {} endpoints refreshed; {} failed" refresh summary.
    fmt_endpoints_refreshed: "{} of {} endpoints refreshed; {} failed", zh: "已刷新 {} / {} 个端点；{} 个失败",
    /// The "{} of {} ({}) supported" capability coverage text.
    fmt_coverage_supported: "{} of {} ({}) supported", zh: "{} / {}（{}）支持",
    /// The "{} members across {} endpoints, {} distinct versions" firmware summary.
    fmt_members_versions: "{} members across {} endpoints, {} distinct versions", zh: "{} 个成员，分布于 {} 个端点，{} 个不同版本",
    /// The "{}%" progress text.
    fmt_percent: "{}%", zh: "{}%",
    /// The "Site {} · binding {} · expires {}" binding code text.
    fmt_binding_code: "Site {} · binding {} · expires {}", zh: "站点 {} · 绑定 {} · 过期时间 {}",
    /// The "Create · {} · {}" account-command payload summary.
    fmt_account_create_payload: "Create · {} · {}", zh: "创建 · {} · {}",
    /// The "Change role · {} · {}" account-command payload summary.
    fmt_change_role_payload: "Change role · {} · {}", zh: "更改角色 · {} · {}",
    /// The "Change password · {}" account-command payload summary.
    fmt_change_password_payload: "Change password · {}", zh: "更改密码 · {}",
    /// The "Rename · {} · {}" account-command payload summary.
    fmt_rename_payload: "Rename · {} · {}", zh: "重命名 · {} · {}",
    /// The "Delete · {}" account-command payload summary.
    fmt_delete_payload: "Delete · {}", zh: "删除 · {}",
    /// The "Create · {} · {} · {}" event-command payload summary.
    fmt_event_create_payload: "Create · {} · {} · {}", zh: "创建 · {} · {} · {}",
    /// The "Reset keys · {}" Secure Boot payload summary.
    fmt_reset_keys_payload: "Reset keys · {}", zh: "重置密钥 · {}",
    /// The "Start · {} · push {}" update payload summary.
    fmt_start_push_payload: "Start · {} · push {}", zh: "启动 · {} · 推送 {}",
    /// The "Start · {} · `multipart`" update payload summary.
    fmt_start_multipart_payload: "Start · {} · multipart", zh: "启动 · {} · multipart",
    /// The "Token · Generate · {}" OEM payload summary.
    fmt_token_generate_payload: "Token · Generate · {}", zh: "令牌 · 生成 · {}",
    /// The "Token · Erase · {} · {}" OEM payload summary.
    fmt_token_erase_payload: "Token · Erase · {} · {}", zh: "令牌 · 擦除 · {} · {}",
    /// The "`Power smoothing` · Activate preset · {}" OEM payload summary.
    fmt_power_activate_payload: "Power smoothing · Activate preset · {}", zh: "电源平滑 · 激活预设 · {}",
    /// The "Metric definition · Create · {} · {}" wire summary.
    fmt_metric_definition_create: "Metric definition · Create · {} · {}", zh: "指标定义 · 创建 · {} · {}",
    /// The "Metric definition · Update · {} · {} · {}" wire summary.
    fmt_metric_definition_update: "Metric definition · Update · {} · {} · {}", zh: "指标定义 · 更新 · {} · {} · {}",
    /// The "Metric definition · Delete · {}" wire summary.
    fmt_metric_definition_delete: "Metric definition · Delete · {}", zh: "指标定义 · 删除 · {}",
    /// The "Report definition · Create · {} · {}" wire summary.
    fmt_report_definition_create: "Report definition · Create · {} · {}", zh: "报告定义 · 创建 · {} · {}",
    /// The "Report definition · Update · {} · {} · {}" wire summary.
    fmt_report_definition_update: "Report definition · Update · {} · {} · {}", zh: "报告定义 · 更新 · {} · {} · {}",
    /// The "Report definition · Delete · {}" wire summary.
    fmt_report_definition_delete: "Report definition · Delete · {}", zh: "报告定义 · 删除 · {}",
    /// The "Profile · Update" OEM payload summary.
    summary_profile_update: "Profile · Update", zh: "配置文件 · 更新",
    /// The "Profile · Factory reset" OEM payload summary.
    summary_profile_factory_reset: "Profile · Factory reset", zh: "配置文件 · 出厂重置",
    /// The "Profile · Activate" OEM payload summary.
    summary_profile_activate: "Profile · Activate", zh: "配置文件 · 激活",
    /// The "Token · Install" OEM payload summary.
    summary_token_install: "Token · Install", zh: "令牌 · 安装",
    /// The "Token · Disable" OEM payload summary.
    summary_token_disable: "Token · Disable", zh: "令牌 · 禁用",
    /// The "`Power smoothing` · Apply overrides" OEM payload summary.
    summary_power_overrides: "Power smoothing · Apply overrides", zh: "电源平滑 · 应用覆盖",
    /// The "Reset to defaults · {kind}" manager reset payload summary.
    fmt_reset_to_defaults_payload: "Reset to defaults · {}", zh: "重置为默认值 · {}",
    /// The "Power supply reset · {id}" chassis payload summary.
    fmt_power_supply_reset_payload: "Power supply reset · {}", zh: "电源模块重置 · {}",
    /// The "Power supply reset · first member" chassis payload summary.
    summary_power_supply_reset_first: "Power supply reset · first member", zh: "电源模块重置 · 第一个成员",
    /// The "Clear · {id}" log-service payload summary.
    fmt_clear_payload: "Clear · {}", zh: "清除 · {}",
    /// The "Clear · first log service" log-service payload summary.
    summary_clear_first: "Clear · first log service", zh: "清除 · 第一个日志服务",
    /// The "`Set point · {set_point}`" control payload summary.
    fmt_set_point_payload: "Set point · {}", zh: "设定值 · {}",
    /// The "Set point" control payload summary without a value.
    summary_set_point: "Set point", zh: "设定值",
    /// The "Set enabled · {enabled}" telemetry payload summary.
    fmt_set_enabled_payload: "Set enabled · {}", zh: "设置启用 · {}",
    /// The "Patch · {members}" firmware-update payload summary.
    fmt_patch_payload: "Patch · {}", zh: "修补 · {}",
    /// The "no members" firmware-update patch summary.
    summary_patch_no_members: "no members", zh: "无成员",
    /// The "1 target" operation-card count.
    fmt_targets_one: "1 target", zh: "1 个目标",
    /// The "`{target_count} targets`" operation-card count.
    fmt_targets_many: "{target_count} targets", zh: "{target_count} 个目标",
    /// The "Selected: {name}" import file summary.
    fmt_selected_file: "Selected: {name}", zh: "已选择：{name}",
    /// The "Selected: {name} · {}" artifact file summary.
    fmt_selected_artifact: "Selected: {name} · {}", zh: "已选择：{name} · {}",
    /// The "Resumes the interrupted upload of this file from {}%." resume note.
    fmt_resume_note: "Resumes the interrupted upload of this file from {}%.", zh: "将从 {}% 处继续此文件的中断上传。",
    /// The "{} of {} uploaded · {}%" upload progress text.
    fmt_upload_progress: "{} of {} uploaded · {}%", zh: "已上传 {} / {} · {}%",
    /// The "Uploading chunk `{chunk_index} of {total_chunks}` · {percent}%" upload status.
    fmt_uploading_chunk: "Uploading chunk {chunk_index} of {total_chunks} · {percent}%", zh: "正在上传分块 {chunk_index} / {total_chunks} · {percent}%",
    /// The "last refresh {text}" center-site chip.
    fmt_last_refresh: "last refresh {text}", zh: "上次刷新 {text}",
}

/// The language of the UI, as selectable by the console header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Lang {
    /// English, the default.
    En,
    /// Simplified Chinese.
    Zh,
}

impl Lang {
    /// The string catalog of this language. The wasm build resolves the
    /// active catalog through [`L()`] instead, so this accessor is
    /// test-only in practice; the `dead_code` allowance keeps it available
    /// for the completeness tests without a wasm-only warning.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub const fn strings(self) -> Strings {
        match self {
            Self::En => Strings::en(),
            Self::Zh => Strings::zh(),
        }
    }
}

/// The stable storage code of one language, for the browser persistence.
pub(crate) const fn lang_code(lang: Lang) -> &'static str {
    match lang {
        Lang::En => "en",
        Lang::Zh => "zh",
    }
}

/// Parses one stored language code back into a [`Lang`]; an unknown code
/// (including a missing value) falls back to English, the default. Not
/// `const`: matching on `str` needs const `PartialEq`, which is not stable.
pub(crate) fn parse_lang(code: &str) -> Lang {
    match code {
        "zh" => Lang::Zh,
        _ => Lang::En,
    }
}

/// The English catalog, kept in a `'static` slot so [`L()`] can hand out
/// `'static` references without allocating.
static EN_CATALOG: Strings = Strings::en();

/// The Simplified Chinese catalog, kept in a `'static` slot so [`L()`] can
/// hand out `'static` references without allocating.
static ZH_CATALOG: Strings = Strings::zh();

thread_local! {
    /// The language of the current thread. The console selector writes it,
    /// persists it, and reloads the page; tests switch it per thread.
    static CURRENT_LANG: std::cell::Cell<Lang> = const { std::cell::Cell::new(Lang::En) };
}

/// Switches the language of the current thread.
///
/// The console calls this before reloading the page, so the fresh mount
/// renders the chosen language; tests call it to exercise a language. In the
/// single-threaded wasm runtime the thread-local is effectively a global,
/// and in the host test runner each test thread carries its own choice.
pub(crate) fn set_lang(lang: Lang) {
    CURRENT_LANG.with(|cell| cell.set(lang));
}

/// The language currently selected on this thread.
pub(crate) fn current_lang() -> Lang {
    CURRENT_LANG.with(std::cell::Cell::get)
}

/// The catalog the console renders with.
///
/// Views read it directly (`{L().nav_overview}`) without a signal or
/// context; the value comes from the current thread's [`Lang`] selection, so
/// a language switch is a full catalog swap. The returned reference is
/// `'static` because both catalogs are program-lifetime statics. The single
/// uppercase letter is the design's catalog accessor, deliberately kept
/// short for the hundreds of template reads.
#[allow(non_snake_case)]
pub(crate) fn L() -> &'static Strings {
    match current_lang() {
        Lang::En => &EN_CATALOG,
        Lang::Zh => &ZH_CATALOG,
    }
}

/// Formats one catalog template with the given arguments.
///
/// Rust's `format!` only accepts a literal template, so formatting copy that
/// lives in the catalog goes through this runtime substitute. Both `{}`
/// slots and named slots (`{count}`, `{status}`, ...) are filled by the
/// arguments in their order of appearance in the template, matching the way
/// the call sites pass them. A missing argument renders the slot verbatim so
/// a catalog/argument mismatch stays visible on screen instead of silently
/// dropping text.
pub(crate) fn format_catalog(template: &str, args: &[&dyn std::fmt::Display]) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(template.len() + 16);
    let mut rest = template;
    let mut args = args.iter();
    while let Some(start) = rest.find('{') {
        let Some(close_rel) = rest[start..].find('}') else {
            out.push_str(rest);
            return out;
        };
        out.push_str(&rest[..start]);
        match args.next() {
            Some(argument) => {
                let _ = write!(out, "{argument}");
            }
            None => out.push_str(&rest[start..=start + close_rel]),
        }
        rest = &rest[start + close_rel + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::{
        EN_ENTRIES, FORMAT_KEYS, L, Lang, Strings, ZH_ENTRIES, current_lang, lang_code, parse_lang,
        set_lang,
    };

    /// The catalogs must never ship an empty string: every field renders or
    /// formats, so an empty value would be a broken copy key.
    #[test]
    fn catalogs_have_no_empty_strings() {
        for (key, value) in EN_ENTRIES.iter().chain(ZH_ENTRIES) {
            assert!(!value.is_empty(), "catalog entry `{key}` must not be empty");
        }
    }

    /// Verbatim keys must never carry a format placeholder: a `{`/`}` in a
    /// key outside `FORMAT_KEYS` would render literally on screen, and a
    /// printf-style `%` (followed by a letter, digit, or another `%`) is a
    /// leftover of a different format vocabulary. A trailing `%` is the
    /// deliberate percent sign of `{}%`-style progress templates.
    #[test]
    fn catalogs_have_no_stray_placeholders() {
        for (key, value) in EN_ENTRIES.iter().chain(ZH_ENTRIES) {
            let printf_leftover = value.match_indices('%').any(|(index, _)| {
                value[index + 1..]
                    .chars()
                    .next()
                    .is_some_and(|next| next.is_ascii_alphanumeric() || next == '%')
            });
            assert!(
                !printf_leftover,
                "catalog entry `{key}` ({value:?}) must not contain a printf-style `%`"
            );
            let is_format_key = FORMAT_KEYS.contains(key);
            for forbidden in ['{', '}'] {
                assert!(
                    !value.contains(forbidden) || is_format_key,
                    "catalog entry `{key}` ({value:?}) must not contain `{forbidden}` unless listed in FORMAT_KEYS"
                );
            }
        }
    }

    /// Every format key must exist as a catalog key: a stale entry in the
    /// list would silently drop the placeholder discipline.
    #[test]
    fn format_keys_are_all_catalog_keys() {
        for key in FORMAT_KEYS {
            assert!(
                EN_ENTRIES.iter().any(|(entry, _)| entry == key),
                "format key `{key}` must be a catalog key"
            );
        }
    }

    /// The two languages must cover exactly the same key set, in the same
    /// order: a key added to one language and forgotten in the other fails
    /// here before any view can render a missing translation.
    #[test]
    fn zh_covers_exactly_the_en_keys() {
        let en_keys = EN_ENTRIES.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        let zh_keys = ZH_ENTRIES.iter().map(|(key, _)| *key).collect::<Vec<_>>();
        assert_eq!(zh_keys, en_keys);
    }

    /// Every format template must expose its placeholders in the same order
    /// in both languages: `format_catalog` fills the slots by their order of
    /// appearance, so a template that reorders the slots swaps the arguments'
    /// values in that language (e.g. "共 {total} 个端点，已显示 {shown} 个"
    /// renders the shown count into the total position). Any language adding
    /// a reversed template fails here before a view can render swapped
    /// numbers; named and positional slots are compared as they appear.
    #[test]
    fn zh_templates_keep_the_en_placeholder_order() {
        fn slot_sequence(template: &str) -> Vec<&str> {
            let mut slots = Vec::new();
            let mut rest = template;
            while let Some(start) = rest.find('{') {
                let Some(close_rel) = rest[start..].find('}') else {
                    break;
                };
                let name = &rest[start + 1..start + close_rel];
                slots.push(if name.is_empty() { "{}" } else { name });
                rest = &rest[start + close_rel + 1..];
            }
            slots
        }

        // The completeness test pins the two key sets to the same order, so
        // zipping the paired entries is safe here.
        for ((key, en_template), (_, zh_template)) in EN_ENTRIES.iter().zip(ZH_ENTRIES) {
            assert_eq!(
                slot_sequence(zh_template),
                slot_sequence(en_template),
                "catalog entry `{key}` must keep its placeholder order in both languages"
            );
        }
    }

    /// The language selection entry point must map both languages to their
    /// complete catalogs, and the default thread state must be English.
    #[test]
    fn lang_selection_returns_the_complete_catalogs() {
        assert_eq!(Lang::En.strings(), Strings::en());
        assert_eq!(Lang::Zh.strings(), Strings::zh());
        assert_eq!(*L(), Strings::en());
        assert_eq!(current_lang(), Lang::En);
    }

    /// Switching the thread language swaps the catalog `L()` resolves, and
    /// the choice is per-thread (parallel tests cannot observe each other's
    /// language). The test restores English afterwards.
    #[test]
    fn language_switch_swaps_the_active_catalog() {
        set_lang(Lang::Zh);
        assert_eq!(current_lang(), Lang::Zh);
        assert_eq!(*L(), Strings::zh());
        assert_eq!(L().nav_overview, "总览");
        set_lang(Lang::En);
        assert_eq!(current_lang(), Lang::En);
        assert_eq!(*L(), Strings::en());
        assert_eq!(L().nav_overview, "Overview");
    }

    /// The runtime formatter fills positional and named slots in appearance
    /// order, renders mixed argument types, and keeps a missing argument
    /// visible instead of silently dropping text.
    #[test]
    fn format_catalog_interpolates_positional_and_named_slots() {
        use super::format_catalog;

        assert_eq!(
            format_catalog(
                "{} of {} endpoints refreshed; {} failed",
                &[&1u64, &3u64, &2u64]
            ),
            "1 of 3 endpoints refreshed; 2 failed"
        );
        assert_eq!(
            format_catalog(
                "Uploading chunk {chunk_index} of {total_chunks} · {percent}%",
                &[&2u64, &4u64, &40u8]
            ),
            "Uploading chunk 2 of 4 · 40%"
        );
        assert_eq!(
            format_catalog("Selected: {name}", &[&"firmware.bin".to_owned()]),
            "Selected: firmware.bin"
        );
        assert_eq!(
            format_catalog(
                "Start · {} · push {}",
                &[&"abc123", &"https://mirror.example/fw.bin"]
            ),
            "Start · abc123 · push https://mirror.example/fw.bin"
        );
        // A missing argument keeps the slot verbatim so the mismatch is
        // visible on screen instead of dropping text.
        assert_eq!(format_catalog("{} of {}", &[&1u64]), "1 of {}");
        // A template without slots renders unchanged.
        assert_eq!(
            format_catalog("Operation submitted.", &[&1u64]),
            "Operation submitted."
        );
    }

    /// The persistence codes round-trip: every language has a stable code,
    /// and parsing an unknown or missing code falls back to English.
    #[test]
    fn language_codes_round_trip_and_fallback_to_en() {
        assert_eq!(lang_code(Lang::En), "en");
        assert_eq!(lang_code(Lang::Zh), "zh");
        assert_eq!(parse_lang("zh"), Lang::Zh);
        assert_eq!(parse_lang("en"), Lang::En);
        assert_eq!(parse_lang("fr"), Lang::En);
        assert_eq!(parse_lang(""), Lang::En);
    }

    /// The console navigation must read exactly the catalog entries: every
    /// view label and the navigation aria-label come from `L()`, so a
    /// language switch flips the whole navigation with the rest of the
    /// console.
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
        assert_eq!(L().header_nav_aria, "Console sections");
    }

    /// The §11.5 OEM notice stays pinned to its contract wording: the
    /// `UnsupportedByNvRedfishBaseline` rendering cannot drift from the
    /// §11.5 sentence, and the translation keeps the same meaning.
    #[test]
    fn oem_unsupported_notice_stays_pinned() {
        assert_eq!(
            Lang::En.strings().notice_oem_unsupported,
            "OEM data is not available in the nv-redfish baseline for this vendor"
        );
        assert_eq!(
            Lang::Zh.strings().notice_oem_unsupported,
            "此厂商的 nv-redfish 基线不提供 OEM 数据"
        );
    }

    /// The English and Simplified Chinese values of the health vocabulary
    /// stay aligned with the §12.3 unified levels.
    #[test]
    fn health_vocabulary_is_complete_in_both_languages() {
        assert_eq!(Lang::En.strings().health_ok, "OK");
        assert_eq!(Lang::En.strings().health_warning, "Warning");
        assert_eq!(Lang::En.strings().health_critical, "Critical");
        assert_eq!(Lang::Zh.strings().health_ok, "正常");
        assert_eq!(Lang::Zh.strings().health_warning, "警告");
        assert_eq!(Lang::Zh.strings().health_critical, "严重");
    }
}
