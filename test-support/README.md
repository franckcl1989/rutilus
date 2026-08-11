# rutilus-test-support

Deterministic test support for the Rutilus product (design section 8
`test-support`: Mock、Fixture、故障注入): a runnable **HTTPS Mock Redfish
BMC** on loopback, serving a fixed resource tree that the product's
trust-first onboarding, 47-capability probe, and typed core resource read
can exercise without a real BMC.

The crate is split into:

- `src/mock_bmc/` -- the library: the `MockBmc` server, its deterministic
  TLS identity, the fixture tree, the HTTP/1.1 server plumbing, and the
  Session ledger.
- `src/bin/mock-bmc.rs` -- the development/demo binary (not a product CLI;
  the product binary is `rutilus` in `app/`).
- `tests/gateway_mock_bmc.rs` -- integration tests driving the real
  `RedfishGateway` against the Mock BMC through public APIs only.

Why not `nv-redfish-bmc-mock` (design section 19.1)? The upstream mock
implements the `Bmc` trait in-process and is not a network endpoint, so the
product's HTTPS onboarding cannot reach it. This crate serves the
network-shaped fixture the product needs today; the upstream mock becomes
relevant after the `BmcFactory` abstraction lands.

## Quick start: run the demo without a real BMC

### 1. Start the Mock BMC (terminal A)

```text
cargo run -p rutilus-test-support --bin mock-bmc
```

Optional: `--port 8443` to pin a fixed port, and `--profile dell` to serve
the Dell vendor profile instead of the default. The binary prints:

```text
Rutilus Mock Redfish BMC (profile: rutilus) listening at https://127.0.0.1:64153/
SHA-256 fingerprint: E6:E8:CA:7E:A3:6C:B7:C7:0B:E0:D8:C8:D0:8C:47:8B:90:2B:97:30:45:BD:C3:C5:9C:61:AC:7E:5E:02:A6:26
```

The fingerprint is **identical on every run** (fixed RSA-2048 key, fixed
subject, serial, and validity), so it is safe to document and to assert in
tests. `Ctrl-C` stops the server gracefully.

### 2. Start the product (terminal B)

```text
cargo run -p rutilus -- init        # first run only; sets the unlock passphrase
cargo run -p rutilus -- run          # unlocks and opens the Web console
```

### 3. Enroll the mock endpoint in the console

1. In the UI, open **添加端点** (add endpoint) and enter the URL printed by
   the Mock BMC (`https://127.0.0.1:{port}/`).
2. The product observes the TLS leaf without credentials. Because the mock
   serves a self-signed certificate, system CA roots reject it and the UI
   shows the observed SHA-256 fingerprint -- confirm it matches the value
   printed by `mock-bmc` (it will) and accept the Pin.
3. Select or create a credential (`admin` / `password` works; the mock
   accepts any user name) and run the enrollment.
4. The resource page shows the typed core tree (ServiceRoot; System 1 with
   its Bios singleton, the PXE-1 boot option, Secure Boot, CPU1/CPU2, DIMM1,
   and the GPU1 PCIe device; Chassis 1 with its Power and Thermal singletons
   plus one Sensor, one Control member, and the Fan Assembly member; Manager
   1 with its event LogService, Network Protocol metadata, and Host
   Interface; the built-in `admin` account; the System BIOS software
   inventory under the UpdateService; the EventService with its webhook
   subscription, the TelemetryService with its power-consumption metric
   definition and power report, and the TaskService with its running
   firmware-update task); the capability page shows the 47-capability probe
   result (33 standard features followed by the 14 OEM features):
   SessionService/Systems/Chassis/Managers/Processors/Memory/Accounts/Bios/
   BootOptions/SecureBoot/Power/Thermal/Sensors/Controls/HostInterfaces/
   LogServices/ManagerNetworkProtocol/PcieDevices/Assembly/UpdateService/
   EventService/TelemetryService/TaskService `Supported`, everything the
   fixture does not serve honestly `NotAdvertised`.
5. Refresh the endpoint: the same tree is re-read through a fresh transient
   Session, which the product deletes before returning.

## Resource tree served by the Mock BMC

| Method | Path | Response |
|---|---|---|
| GET | `/redfish/v1` | Service Root (Vendor "Rutilus Test", Product "Mock BMC", RedfishVersion "1.20.0", `Links.Sessions`, typed links to SessionService/Systems/Chassis/Managers/AccountService/UpdateService/EventService/TelemetryService/TaskService) |
| GET | `/redfish/v1/SessionService` | Session Service, `ServiceEnabled: true` |
| GET | `/redfish/v1/SessionService/Sessions` | Session collection listing the active ledger |
| POST | `/redfish/v1/SessionService/Sessions` | `201` + `X-Auth-Token: test-session-token` + `Location` + Session document (echoes `UserName`) |
| DELETE | `/redfish/v1/SessionService/Sessions/{id}` | `204`, or `404` for an unknown/expired Session |
| GET | `/redfish/v1/AccountService` | Account Service advertising its Accounts collection |
| GET | `/redfish/v1/AccountService/Accounts` | ManagerAccount collection (admin) |
| GET | `/redfish/v1/AccountService/Accounts/admin` | Built-in administrator account (RoleId "Administrator", AccountTypes Redfish/IPMI) |
| GET | `/redfish/v1/Systems` | System collection, one member |
| GET | `/redfish/v1/Systems/1` | ComputerSystem with Bios/BootOptions/SecureBoot/Processors/Memory/PCIeDevices links |
| GET | `/redfish/v1/Systems/1/Bios` | BIOS configuration singleton (AttributeRegistry, no raw Attributes bag in the snapshot) |
| GET | `/redfish/v1/Systems/1/BootOptions` | Boot option collection (PXE-1) |
| GET | `/redfish/v1/Systems/1/BootOptions/PXE-1` | Boot option (UEFI PXE, alias "Pxe") |
| GET | `/redfish/v1/Systems/1/SecureBoot` | Secure Boot singleton (enabled, UserMode) |
| GET | `/redfish/v1/Systems/1/Processors` | Processor collection (CPU1, CPU2) |
| GET | `/redfish/v1/Systems/1/Processors/CPU1` | Processor (64 cores, LGA4189) |
| GET | `/redfish/v1/Systems/1/Processors/CPU2` | Processor (32 cores) |
| GET | `/redfish/v1/Systems/1/Memory` | Memory collection (DIMM1) |
| GET | `/redfish/v1/Systems/1/Memory/DIMM1` | Memory module (DDR4, 32768 MiB) |
| GET | `/redfish/v1/Systems/1/PCIeDevices/GPU1` | PCIe device (SingleFunction, GPU accelerator) |
| GET | `/redfish/v1/Chassis` | Chassis collection, one member |
| GET | `/redfish/v1/Chassis/1` | RackMount chassis with Power/Thermal/Sensors/Controls/Assembly links |
| GET | `/redfish/v1/Chassis/1/Power` | Power singleton (PowerControl: 320 W consumed, 800 W capacity) |
| GET | `/redfish/v1/Chassis/1/Thermal` | Thermal singleton (inlet 27.5 C, Status) |
| GET | `/redfish/v1/Chassis/1/Sensors` | Sensor collection (InletTemp) |
| GET | `/redfish/v1/Chassis/1/Sensors/InletTemp` | Temperature sensor (27.5 Cel, ReadingType Temperature) |
| GET | `/redfish/v1/Chassis/1/Controls` | Control collection (FanDuty) |
| GET | `/redfish/v1/Chassis/1/Controls/FanDuty` | Fan duty-cycle control (set point 30 Percent) |
| GET | `/redfish/v1/Chassis/1/Assembly` | Assembly document embedding the Assemblies link array |
| GET | `/redfish/v1/Chassis/1/Assembly%23/Assemblies/0` | Fan Assembly member (the JSON-pointer `#` arrives percent-encoded on the wire) |
| GET | `/redfish/v1/Managers` | Manager collection, one member |
| GET | `/redfish/v1/Managers/1` | BMC manager with FirmwareVersion and HostInterfaces/NetworkProtocol/LogServices links (no EthernetInterfaces link) |
| GET | `/redfish/v1/Managers/1/LogServices` | Log service collection (1) |
| GET | `/redfish/v1/Managers/1/LogServices/1` | Event log (ServiceEnabled, MaxNumberOfRecords 1000) |
| GET | `/redfish/v1/Managers/1/NetworkProtocol` | Manager network protocol singleton (HostName "bmc-1", FQDN) |
| GET | `/redfish/v1/Managers/1/HostInterfaces` | Host interface collection (1) |
| GET | `/redfish/v1/Managers/1/HostInterfaces/1` | Host interface (InterfaceEnabled, NetworkHostInterface) |
| GET | `/redfish/v1/UpdateService` | Firmware update service advertising its SoftwareInventory collection |
| GET | `/redfish/v1/UpdateService/SoftwareInventory` | Software inventory collection (BIOS) |
| GET | `/redfish/v1/UpdateService/SoftwareInventory/BIOS` | System BIOS (SoftwareId "BIOS-2026-1", Version "2.7.0", ReleaseDate) |
| GET | `/redfish/v1/EventService` | Event service (ServiceEnabled, Subscriptions link) |
| GET | `/redfish/v1/EventService/Subscriptions` | Event destination collection (subscription 1) |
| GET | `/redfish/v1/EventService/Subscriptions/1` | Webhook subscription (Destination, Protocol Redfish, EventTypes StatusChange/Alert) |
| GET | `/redfish/v1/TelemetryService` | Telemetry service advertising MetricDefinitions/MetricReports links |
| GET | `/redfish/v1/TelemetryService/MetricDefinitions` | Metric definition collection (1) |
| GET | `/redfish/v1/TelemetryService/MetricDefinitions/1` | Power Consumption definition (MetricType Numeric, Units W) |
| GET | `/redfish/v1/TelemetryService/MetricReports` | Metric report collection (1) |
| GET | `/redfish/v1/TelemetryService/MetricReports/1` | Power report (2 metric values; the snapshot carries only the derived count) |
| GET | `/redfish/v1/TaskService` | Task service (ServiceEnabled, CompletedTaskOverWritePolicy Oldest, Tasks link) |
| GET | `/redfish/v1/TaskService/Tasks` | Task collection (1) |
| GET | `/redfish/v1/TaskService/Tasks/1` | Firmware Update Task (Running, 42%, StartTime) |
| any other | | `404` with a Redfish-shaped `error` body (`Base.1.0.ResourceMissingAtURI`) |

Fixture field sets and `@odata.type` spellings mirror the documents
`rutilus-infra-redfish`'s own tests already decode, so the mock cannot drift
from what the product actually parses. Links the tree does not serve are
omitted rather than 404'd, so the capability probe reports `NotAdvertised`
for them instead of classifying a guessed path.

## Vendor profiles

`MockBmc::start()` serves the default Rutilus Test profile;
`MockBmc::start_with_profile(MockProfile::Dell)` (or `mock-bmc
--profile dell`) serves the Dell iDRAC profile:

- Default (`MockProfile::Rutilus`): Vendor "Rutilus Test" / Product "Mock
  BMC", no `Oem` namespace anywhere in the tree, so every §2.1 OEM capability
  probes `NotAdvertised`.
- Dell (`MockProfile::Dell`): Vendor "Dell Inc." / Product "PowerEdge R750";
  `Managers/1` advertises `Oem.Dell` and the mock serves
  `/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1` with the five pinned
  identity attributes (ServerModel, ServerServiceTag, ServerGeneration,
  ServerBmcMacAddress, ServerName), so the gateway's §11.5 Dell Attributes
  read decodes a real document. Every other document of the tree is shared
  with the default profile, and the Dell Attributes route 404s under any
  other profile.
- xFusion (`MockProfile::XFusion`, `--profile xfusion`): Vendor "xFusion" /
  Product "2288H V7", no `Oem` namespace anywhere in the tree, so every
  §2.1 OEM capability probes `NotAdvertised` and the read surface stays the
  default 28-resource tree. This is the 0.5.0 standard-pattern verification
  basis: a vendor that serves no OEM surface must not mis-display any other
  vendor's features. Every document of the tree is shared with the default
  profile except the Service Root identity strings.
- Inspur (`MockProfile::Inspur`, `--profile inspur`): Vendor "Inspur" /
  Product "NF5280M6", no `Oem` namespace anywhere in the tree, the second
  0.5.0 standard-pattern verification basis. Every document of the tree is
  shared with the default profile except the Service Root identity strings.
- The profile enum stays the extension point for further vendors: a vendor
  that serves no OEM surface is a new profile variant that only changes the
  Service Root identity strings, and a vendor with an OEM surface adds its
  namespace plus its gated routes.

## Behavior contract

- **TLS**: loopback HTTPS with a deterministic self-signed RSA-2048 leaf
  (CN "Rutilus Mock BMC", SANs `localhost` and `127.0.0.1`). The SHA-256
  fingerprint is byte-identical on every run and is exposed through
  `MockBmc::fingerprint()` / `fingerprint_text()`.
- **One request per connection**: the product disables connection pooling,
  and the mock mirrors that; each connection serves exactly one request and
  closes with a TLS `close_notify`.
- **Probe connections**: the product's credential-free TLS probe never sends
  HTTP bytes; the mock closes such connections quietly (10-second bounds on
  handshake and request reads).
- **Auth is lenient**: the mock does not validate credentials or tokens. It
  records every request (method, path, headers) so wire-sequence tests can
  assert what the product actually sent, and it tracks the Session ledger so
  tests can prove transient Sessions are cleaned up.

## Using the Mock BMC in integration tests

Integration tests bind their own Mock BMC on an ephemeral port and drive the
real product gateway:

```rust
let mock = MockBmc::start().await?;
let gateway = RedfishGateway::from_system_roots().await?;
let address = mock.endpoint_address();
let observation = gateway.observe_tls(&address).await?; // SystemCaStatus::Rejected
let trust = TlsTrust::PinnedCertificate {
    certificate: observation.certificate().clone(),
    trusted_at: OffsetDateTime::now_utc(),
};
let summary = gateway
    .read_service_root(&address, &trust, &username, &password)
    .await?;
```

See `tests/gateway_mock_bmc.rs` and `src/mock_bmc/tests.rs` for the complete
flow: Service Root read, 47-capability probe, typed core resource read,
Session lifecycle with exact wire-sequence assertions, and refresh.

### Public API

- `MockBmc::start()` / `MockBmc::bind(port)` -- bind and serve the default
  profile in the background; `MockBmc::start_with_profile(profile)` /
  `MockBmc::bind_with_profile(port, profile)` serve a vendor profile
  (`MockProfile::Rutilus` | `MockProfile::Dell` | `MockProfile::Nvidia` |
  `MockProfile::Lenovo` | `MockProfile::XFusion` | `MockProfile::Inspur`);
  `stop()` shuts down and releases the port.
- `MockBmc::endpoint_address()` / `url()` -- the endpoint to enroll.
- `MockBmc::fingerprint()` / `fingerprint_text()` / `certificate_der()` --
  the TLS identity for trust construction and Pin assertions.
- `MockBmc::requests()` -- snapshot of recorded requests (in arrival order);
  `MockBmc::requests_served()` -- request count.
- `MockBmc::active_sessions()` -- the Session ledger size (0 after a
  complete product flow).
- `RequestRecord::method()` / `path()` / `header(name)` -- one recorded
  request; header lookup is case-insensitive.
- `MockTlsIdentity` / `MockTlsIdentityError` -- the deterministic identity
  generator, exposed for direct use.
- `MockBmcError` -- typed failures for bind/serve/stop.

## Verification

```text
cargo check -p rutilus-test-support
cargo test -p rutilus-test-support
cargo clippy -p rutilus-test-support --all-targets --all-features -- -D warnings
cargo check --workspace
```

All crates keep the workspace lints: `unsafe` forbidden, clippy `all` +
`pedantic` denied, and `unwrap`/`panic`/`todo`/`expect` denied.
