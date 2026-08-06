# rutilus-test-support

Deterministic test support for the Rutilus product (design section 8
`test-support`: Mock、Fixture、故障注入): a runnable **HTTPS Mock Redfish
BMC** on loopback, serving a fixed resource tree that the product's
trust-first onboarding, 30-capability probe, and typed core resource read
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

Optional: `--port 8443` to pin a fixed port. The binary prints:

```text
Rutilus Mock Redfish BMC listening at https://127.0.0.1:64153/
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
4. The resource page shows the typed core tree (ServiceRoot, System 1 with
   CPU1/CPU2 and DIMM1, Chassis 1, Manager 1); the capability page shows the
   30-capability probe result: SessionService/Systems/Chassis/Managers/
   Processors/Memory `Supported`, everything the fixture does not serve
   honestly `NotAdvertised`.
5. Refresh the endpoint: the same tree is re-read through a fresh transient
   Session, which the product deletes before returning.

## Resource tree served by the Mock BMC

| Method | Path | Response |
|---|---|---|
| GET | `/redfish/v1` | Service Root (Vendor "Rutilus Test", Product "Mock BMC", RedfishVersion "1.20.0", `Links.Sessions`, typed links to SessionService/Systems/Chassis/Managers) |
| GET | `/redfish/v1/SessionService` | Session Service, `ServiceEnabled: true` |
| GET | `/redfish/v1/SessionService/Sessions` | Session collection listing the active ledger |
| POST | `/redfish/v1/SessionService/Sessions` | `201` + `X-Auth-Token: test-session-token` + `Location` + Session document (echoes `UserName`) |
| DELETE | `/redfish/v1/SessionService/Sessions/{id}` | `204`, or `404` for an unknown/expired Session |
| GET | `/redfish/v1/Systems` | System collection, one member |
| GET | `/redfish/v1/Systems/1` | ComputerSystem with Processors/Memory links |
| GET | `/redfish/v1/Systems/1/Processors` | Processor collection (CPU1, CPU2) |
| GET | `/redfish/v1/Systems/1/Processors/CPU1` | Processor (64 cores, LGA4189) |
| GET | `/redfish/v1/Systems/1/Processors/CPU2` | Processor (32 cores) |
| GET | `/redfish/v1/Systems/1/Memory` | Memory collection (DIMM1) |
| GET | `/redfish/v1/Systems/1/Memory/DIMM1` | Memory module (DDR4, 32768 MiB) |
| GET | `/redfish/v1/Chassis` | Chassis collection, one member |
| GET | `/redfish/v1/Chassis/1` | RackMount chassis (no Power/Thermal links) |
| GET | `/redfish/v1/Managers` | Manager collection, one member |
| GET | `/redfish/v1/Managers/1` | BMC manager with FirmwareVersion (no EthernetInterfaces/HostInterfaces/NetworkProtocol/LogServices links) |
| any other | | `404` with a Redfish-shaped `error` body (`Base.1.0.ResourceMissingAtURI`) |

Fixture field sets and `@odata.type` spellings mirror the documents
`rutilus-infra-redfish`'s own tests already decode, so the mock cannot drift
from what the product actually parses. Links the tree does not serve are
omitted rather than 404'd, so the capability probe reports `NotAdvertised`
for them instead of classifying a guessed path.

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
flow: Service Root read, 30-capability probe, typed core resource read,
Session lifecycle with exact wire-sequence assertions, and refresh.

### Public API

- `MockBmc::start()` / `MockBmc::bind(port)` -- bind and serve in the
  background; `stop()` shuts down and releases the port.
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
