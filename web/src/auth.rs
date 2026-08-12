//! Session authentication and the §16.2 sign-in lifecycle.
//!
//! The module owns every authentication concern of the Web crate:
//!
//! - [`AuthPolicy`] — whether the router enforces sessions at all. `Open`
//!   serves every request without a session (the pre-0.6 behavior, and the
//!   test default); `Guarded` requires a session on every route except the
//!   public sign-in surface; `PendingBootstrap` is the Standalone loopback
//!   lifecycle — open until the first-startup claim succeeds, then guarded.
//! - The session middleware — extracts the `rutilus_session` cookie, looks
//!   the session up by its SHA-256 token hash, checks expiry and
//!   revocation, verifies the CSRF token of mutating requests in constant
//!   time, advances the `last_used_at`, refreshes the cookie `Max-Age`,
//!   and resolves the acting principal into the per-request
//!   [`AuthContext`].
//! - The route authorization table — every route carries a role mask and a
//!   mutation flag, so the §16.1 role model is a declarative table instead
//!   of scattered checks.
//! - The in-process login rate limiter (§16.2 "登录失败限速"): 5 failures
//!   per username and 20 per client address in a 15-minute window, with
//!   periodic pruning of expired buckets so the maps stay memory-bounded
//!   under distributed attacks (security-review N3).
//! - The sign-in, sign-out, bootstrap-claim, password-change, `me`, and
//!   administration handlers.
//!
//! The Web crate never touches persistence or security internals: every
//! store and crypto operation flows through the [`AuthServices`] boundary,
//! implemented by the embedding runtime (the Standalone posture composes
//! its `SqliteStore` and master key behind it).

use std::{
    collections::{HashMap, VecDeque, hash_map::Entry},
    error::Error,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration as StdDuration, Instant},
};

use axum::{
    Json,
    extract::{ConnectInfo, FromRequestParts, OriginalUri, Path as AxumPath, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{COOKIE, SET_COOKIE},
        request::Parts,
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use rutilus_api::{
    AssignRoleRequest, BootstrapCompleteRequest, BootstrapCompleteResponse, CreateUserRequest,
    LoginRequest, LoginResponse, LogoutRequest, MeResponse, PrincipalStateResponse,
    PrincipalSummaryResponse, RevokeSessionRequest, RoleResponse, SessionAdminResponse,
    SessionSummaryResponse, SetPasswordRequest, SetPrincipalStateRequest, UserAdminResponse,
    UserSummaryResponse,
};
use rutilus_application::{AuditEventWriter, BoundaryFuture, Clock};
use rutilus_domain::{
    ARGON2ID_HASH_LENGTH, ARGON2ID_SALT_LENGTH, Argon2IdHash, AuditAction, AuditActor, AuditEvent,
    AuditFailure, AuditFailureVerification, AuditOperationContext, AuditOperationContextError,
    AuditOperationId, AuditParameterSummary, AuditRedfishOperation, AuditSequence, AuditTarget,
    BootstrapCode, BootstrapCodeId, InstanceId, PasswordCredential, Principal, PrincipalId,
    PrincipalName, PrincipalState, ProductPermission, Role, RoleAssignment, Session, SessionId,
    TOTP_SECRET_LENGTH, TotpAuthenticator, TotpAuthenticatorError,
};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use time::{Duration, OffsetDateTime};

use crate::{WebState, json_error, no_store, uncached_status};

/// The name of the session cookie set by every sign-in response (§16.2
/// "Session Cookie 使用 Secure、HttpOnly、SameSite").
pub const SESSION_COOKIE_NAME: &str = "rutilus_session";

/// The product's built-in administrator, created by the initialization
/// runtime and claimed by the first-startup bootstrap flow (§16.2).
pub const BOOTSTRAP_PRINCIPAL_NAME: &str = "admin";

/// The absolute lifetime of one session: eight hours from creation. The
/// session is never extended by activity — [`AuthServices::touch_session`]
/// only advances the persisted `last_used_at` (for the audit trail and the
/// session listing), so the cookie's `Max-Age` counts down on every
/// authenticated response and the session dies eight hours after sign-in
/// regardless of how often it is used.
const SESSION_LIFETIME: Duration = Duration::hours(8);

/// The interval after which a request advances `last_used_at`.
const TOUCH_INTERVAL: Duration = Duration::MINUTE;

/// The minimum password length of the product, in characters (B1).
///
/// The console form enforces the same floor (`ui/src/lib.rs`
/// `BootstrapView` rejects `chars().count() < 12`, with the copy at
/// `ui/src/i18n.rs` `error_password_too_short`); the API repeats it because
/// the form is a convenience, not a control — the API is the actual
/// boundary every client reaches. The count is Unicode scalar values, not
/// bytes, exactly like the form's check, so a multi-byte character is one
/// character (design §16.2 states no default password; this is the product
/// minimum).
pub(crate) const MIN_PASSWORD_CHARS: usize = 12;

/// Rate-limit window (§16.2 "登录失败限速").
const RATE_WINDOW: StdDuration = StdDuration::from_mins(15);
/// Sign-in failures allowed per username in one window.
pub(crate) const USERNAME_FAILURE_LIMIT: usize = 5;
/// Sign-in failures allowed per client address in one window.
const IP_FAILURE_LIMIT: usize = 20;
/// The longest username key the rate limiter records: every valid principal
/// name is at most [`rutilus_domain::MAX_PRINCIPAL_NAME_CHARS`] characters,
/// so a longer presented username is invalid — it must still consume the
/// per-username budget (the invalid-name attempts of one attacker), but it
/// must not grow the in-memory bucket map with an unbounded
/// attacker-controlled string. The key is the first
/// [`MAX_PRINCIPAL_NAME_CHARS`](rutilus_domain::MAX_PRINCIPAL_NAME_CHARS)
/// characters, so truncation can only share buckets between invalid names —
/// never tighten a legitimate principal's budget, because valid names never
/// exceed the bound.
const RATE_LIMIT_USERNAME_CHARS: usize = rutilus_domain::MAX_PRINCIPAL_NAME_CHARS;

/// New-bucket insertions between full sweeps of one rate-limit bucket map
/// (security-review N3).
///
/// A bucket is only reclaimed once every entry has left the window, so
/// without a backstop the maps would accumulate every distinct
/// attacker-controlled key ever presented. Counting only *new* keys keeps
/// the maps bounded by the working set of one window plus this many
/// un-swept buckets: an attacker must keep a bucket alive with a fresh
/// failure every window, so memory now tracks request traffic instead of
/// growing without bound over time. Each sweep applies the same expiry
/// rule as the access path, so it never changes a limit verdict.
const BUCKET_PRUNE_THRESHOLD: usize = 4096;

/// Whether the router enforces session authentication (§16.2).
#[derive(Clone, Debug)]
pub enum AuthPolicy {
    /// Serve every request without a session — the pre-0.6 behavior and the
    /// default of the test routers.
    Open,
    /// Require a session (and the route's role mask) on every route except
    /// the public sign-in surface.
    Guarded,
    /// The Standalone loopback lifecycle: open until the first-startup
    /// bootstrap claim succeeds, then guarded. The gate flips in-process
    /// when the claim completes, so the console does not need a restart to
    /// start enforcing sessions.
    PendingBootstrap(AuthGate),
}

impl AuthPolicy {
    /// Reports whether this policy currently enforces sessions.
    #[must_use]
    pub fn is_guarded(&self) -> bool {
        match self {
            Self::Open => false,
            Self::Guarded => true,
            Self::PendingBootstrap(gate) => gate.is_guarded(),
        }
    }
}

/// A shared, process-wide switch between open and guarded enforcement.
///
/// The gate is consulted on every request, so arming it after the bootstrap
/// claim immediately starts enforcing sessions on the running console.
#[derive(Clone, Debug)]
pub struct AuthGate(Arc<std::sync::atomic::AtomicBool>);

impl AuthGate {
    /// A gate that starts open.
    #[must_use]
    pub fn open() -> Self {
        Self(Arc::new(std::sync::atomic::AtomicBool::new(false)))
    }

    /// A gate that starts guarded.
    #[must_use]
    pub fn guarded() -> Self {
        Self(Arc::new(std::sync::atomic::AtomicBool::new(true)))
    }

    #[must_use]
    pub fn is_guarded(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Flips the gate to guarded.
    pub fn arm(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// The acting identity of one request, resolved by the auth middleware.
///
/// Every handler that records an audit fact reads its actor from this
/// extension: in `Open` mode the actor is the router's injected actor, in
/// guarded mode it is the session's principal (`actor = user` with the
/// principal id), so audit events always name who actually acted (§16.3).
/// The role and its D3 site scope (the `role_assignments.site_id` column)
/// ride along for the §16.1 authorization judgments — the center console
/// routes apply the site scope to every view and write.
#[derive(Clone, Debug)]
pub struct AuthContext {
    actor: AuditActor,
    actor_principal_id: Option<PrincipalId>,
    session_id: Option<SessionId>,
    role: Option<Role>,
    assignment_site_id: Option<InstanceId>,
}

impl AuthContext {
    /// The unauthenticated fallback context carrying the injected actor.
    #[must_use]
    pub fn unauthenticated(actor: AuditActor) -> Self {
        Self {
            actor,
            actor_principal_id: None,
            session_id: None,
            role: None,
            assignment_site_id: None,
        }
    }

    #[must_use]
    pub const fn actor(&self) -> AuditActor {
        self.actor
    }

    #[must_use]
    pub const fn actor_principal_id(&self) -> Option<PrincipalId> {
        self.actor_principal_id
    }

    #[must_use]
    pub const fn session_id(&self) -> Option<SessionId> {
        self.session_id
    }

    #[must_use]
    pub const fn role(&self) -> Option<Role> {
        self.role
    }

    /// The D3 site scope of the acting principal's role assignment (§16.1 —
    /// a center role can be limited to one site). `None` is either an
    /// unscoped (global) assignment or an unauthenticated context.
    #[must_use]
    pub const fn assignment_site_id(&self) -> Option<InstanceId> {
        self.assignment_site_id
    }
}

/// The §16.1/D3 site-scope judgment of the center views: may the acting role
/// (with its assignment scope) see the given site?
///
/// The `Administrator` sees every site. The `Operator` and the `Viewer` see
/// every site under an unscoped assignment and exactly the assigned site
/// under a scoped one (D3: the `role_assignments.site_id` column); an
/// unauthenticated context (the open test routers) is treated as the
/// unscoped `Viewer`.
#[must_use]
pub(crate) fn view_scope_allows(
    role: Option<Role>,
    assignment_site: Option<InstanceId>,
    site: InstanceId,
) -> bool {
    match role {
        Some(Role::Administrator) => true,
        Some(Role::Operator | Role::Viewer) | None => {
            assignment_site.is_none() || assignment_site == Some(site)
        }
    }
}

/// The §16.1/D3 dispatch judgment of the center console: may the acting role
/// dispatch an operation to the given site?
///
/// The judgment mirrors the application's [`rutilus_application::allows_dispatch`]
/// exactly — the `Administrator` is global, the `Operator` global or scoped,
/// and the `Viewer` (and any unauthenticated context) never dispatches. The
/// application dispatch use case re-checks the same rule against the
/// persisted role assignment, so the handler gate and the use case cannot
/// drift apart.
#[must_use]
pub(crate) fn dispatch_scope_allows(
    role: Option<Role>,
    assignment_site: Option<InstanceId>,
    site: InstanceId,
) -> bool {
    role.is_some_and(|role| rutilus_application::allows_dispatch(role, assignment_site, site))
}

/// The authentication boundaries implemented by the embedding runtime.
///
/// The Web crate stays free of persistence and security internals: the
/// runtime composes its store and master key behind these methods exactly
/// like the product-service boundaries.
pub trait AuthServices: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn find_session_by_token_hash<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
    ) -> BoundaryFuture<'a, Result<Option<Session>, Self::Error>>;
    fn create_session<'a>(
        &'a self,
        session: &'a Session,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;
    fn touch_session(
        &self,
        session_id: SessionId,
        at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;
    fn revoke_session(
        &self,
        session_id: SessionId,
        at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;
    fn revoke_sessions_for_principal(
        &self,
        principal_id: PrincipalId,
        at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<u64, Self::Error>>;
    fn list_sessions(
        &self,
        principal_id: PrincipalId,
    ) -> BoundaryFuture<'_, Result<Vec<Session>, Self::Error>>;
    fn find_principal(
        &self,
        principal_id: PrincipalId,
    ) -> BoundaryFuture<'_, Result<Option<Principal>, Self::Error>>;
    fn find_principal_by_name<'a>(
        &'a self,
        name: &'a PrincipalName,
    ) -> BoundaryFuture<'a, Result<Option<Principal>, Self::Error>>;
    fn list_principals(&self) -> BoundaryFuture<'_, Result<Vec<Principal>, Self::Error>>;
    fn create_principal<'a>(
        &'a self,
        principal: &'a Principal,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;
    fn set_principal_state(
        &self,
        principal_id: PrincipalId,
        state: PrincipalState,
        at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;
    fn assign_role<'a>(
        &'a self,
        assignment: &'a RoleAssignment,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;
    fn find_role_assignment(
        &self,
        principal_id: PrincipalId,
    ) -> BoundaryFuture<'_, Result<Option<RoleAssignment>, Self::Error>>;
    fn list_role_assignments(&self)
    -> BoundaryFuture<'_, Result<Vec<RoleAssignment>, Self::Error>>;
    fn find_password_credential(
        &self,
        principal_id: PrincipalId,
    ) -> BoundaryFuture<'_, Result<Option<PasswordCredential>, Self::Error>>;
    fn save_password_credential<'a>(
        &'a self,
        credential: &'a PasswordCredential,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;
    fn list_totp_authenticators(
        &self,
        principal_id: PrincipalId,
    ) -> BoundaryFuture<'_, Result<Vec<TotpAuthenticator>, Self::Error>>;
    fn record_totp_step(
        &self,
        authenticator_id: rutilus_domain::TotpAuthenticatorId,
        step: u64,
    ) -> BoundaryFuture<'_, Result<bool, Self::Error>>;
    fn find_bootstrap_code_by_hash<'a>(
        &'a self,
        code_hash: &'a [u8; 32],
    ) -> BoundaryFuture<'a, Result<Option<BootstrapCode>, Self::Error>>;
    fn has_unconsumed_bootstrap_code(&self) -> BoundaryFuture<'_, Result<bool, Self::Error>>;
    #[allow(clippy::too_many_arguments)]
    fn consume_bootstrap_code<'a>(
        &'a self,
        code_id: BootstrapCodeId,
        used_by: PrincipalId,
        password: &'a PasswordCredential,
        authenticator: Option<&'a TotpAuthenticator>,
        session: &'a Session,
        consumed_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;

    /// Verifies a presented password against a stored `argon2id-1` hash.
    fn verify_password(&self, hash: &Argon2IdHash, password: &SecretString) -> bool;
    /// Verifies a presented TOTP code in the RFC 6238 window.
    ///
    /// # Errors
    ///
    /// Returns [`TotpAuthenticatorError`] exactly as the domain core does.
    fn verify_totp(
        &self,
        secret: &SecretBox<[u8; TOTP_SECRET_LENGTH]>,
        code: &str,
        now: OffsetDateTime,
        last_used_step: Option<u64>,
    ) -> Result<u64, TotpAuthenticatorError>;
    /// Derives a fresh `argon2id-1` hash for a new password.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] when the derivation cannot complete.
    fn hash_password(&self, password: &SecretString) -> Result<Argon2IdHash, Self::Error>;
    /// Normalizes and hashes a presented bootstrap code for lookup.
    fn hash_bootstrap_code(&self, code: &str) -> [u8; 32];
    /// Issues one session-token/CSRF-token pair.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] when the tokens cannot be issued.
    fn issue_tokens(&self) -> Result<IssuedSessionTokens, Self::Error>;
    /// Hashes a presented session or CSRF token for lookup and comparison.
    fn token_hash(&self, wire: &str) -> [u8; 32];
}

/// One freshly issued token pair (§16.2).
///
/// The wire forms go to the client (the cookie and the login response); the
/// hashes go into the `sessions` row, so the database never holds a usable
/// session secret.
#[derive(Clone, Debug)]
pub struct IssuedSessionTokens {
    session_token: String,
    session_token_hash: [u8; 32],
    csrf_token: String,
    csrf_token_hash: [u8; 32],
}

impl IssuedSessionTokens {
    #[must_use]
    pub fn new(
        session_token: String,
        session_token_hash: [u8; 32],
        csrf_token: String,
        csrf_token_hash: [u8; 32],
    ) -> Self {
        Self {
            session_token,
            session_token_hash,
            csrf_token,
            csrf_token_hash,
        }
    }

    #[must_use]
    pub fn session_token(&self) -> &str {
        &self.session_token
    }

    #[must_use]
    pub const fn session_token_hash(&self) -> &[u8; 32] {
        &self.session_token_hash
    }

    #[must_use]
    pub fn csrf_token(&self) -> &str {
        &self.csrf_token
    }

    #[must_use]
    pub const fn csrf_token_hash(&self) -> &[u8; 32] {
        &self.csrf_token_hash
    }
}

/// The §16.1 role mask of one route: which roles may reach it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoleMask(u8);

impl RoleMask {
    const ADMINISTRATOR: u8 = 1;
    const OPERATOR: u8 = 1 << 1;
    const VIEWER: u8 = 1 << 2;

    /// Every role: the read-only product surface (§16.1 Viewer).
    pub const ANY: Self = Self(Self::ADMINISTRATOR | Self::OPERATOR | Self::VIEWER);
    /// Administrator only: credential, trust, import, and administration
    /// surfaces (§16.1 Administrator).
    pub const ADMINISTRATOR_ONLY: Self = Self(Self::ADMINISTRATOR);
    /// Administrator and Operator: operation submission and artifact upload
    /// (§16.1).
    pub const ADMINISTRATOR_OR_OPERATOR: Self = Self(Self::ADMINISTRATOR | Self::OPERATOR);

    #[must_use]
    pub fn allows(self, role: Role) -> bool {
        let bit = match role {
            Role::Administrator => Self::ADMINISTRATOR,
            Role::Operator => Self::OPERATOR,
            Role::Viewer => Self::VIEWER,
        };
        self.0 & bit != 0
    }
}

/// When a route needs its session, and under what role mask.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RouteAccess {
    /// No session needed: the public sign-in surface and static assets.
    Public,
    /// The route requires a session in every mode (sign-out, password
    /// change, administration).
    Always { roles: RoleMask, mutation: bool },
    /// The route requires a session only when the policy is guarded (the
    /// product surface).
    GuardedOnly { roles: RoleMask, mutation: bool },
}

/// The §16.1 route authorization table: (method, path pattern) to access.
///
/// Patterns are matched by exact path, except the trailing `*` wildcards
/// which match any path with the given prefix. Every parameterized subpath
/// (operations, batches, artifacts, groups, telemetry, the trust
/// confirmation, and the administration surface) is covered by one of
/// those prefixes, so a new route nested under an existing prefix is
/// guarded by the same entry instead of falling through to the public
/// fallback. The list is ordered: the more specific endpoint-address
/// patterns (`trust`, `import`, `refresh`) precede the enrollment
/// `POST /api/v1/endpoints` and the read prefix.
const ROUTE_TABLE: &[(Method, &str, RouteAccess)] = &[
    // The public sign-in surface.
    (Method::GET, "/api/v1/health", RouteAccess::Public),
    (Method::GET, "/api/v1/about", RouteAccess::Public),
    (Method::POST, "/api/v1/auth/login", RouteAccess::Public),
    (Method::POST, "/api/v1/auth/bootstrap", RouteAccess::Public),
    (Method::GET, "/api/v1/auth/me", RouteAccess::Public),
    // The session-bound authentication surface (every mode).
    (
        Method::POST,
        "/api/v1/auth/logout",
        RouteAccess::Always {
            roles: RoleMask::ANY,
            mutation: true,
        },
    ),
    (
        Method::POST,
        "/api/v1/auth/password",
        RouteAccess::Always {
            roles: RoleMask::ANY,
            mutation: true,
        },
    ),
    // The §16.1 administration surface (Administrator only).
    (
        Method::GET,
        "/api/v1/admin/sessions",
        RouteAccess::Always {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: false,
        },
    ),
    (
        Method::POST,
        "/api/v1/admin/sessions",
        RouteAccess::Always {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: true,
        },
    ),
    (
        Method::GET,
        "/api/v1/admin/users",
        RouteAccess::Always {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: false,
        },
    ),
    (
        Method::POST,
        "/api/v1/admin/users",
        RouteAccess::Always {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: true,
        },
    ),
    (
        Method::POST,
        "/api/v1/admin/users*",
        RouteAccess::Always {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: true,
        },
    ),
    // The audit view (§16.1 Administrator and Operator).
    (
        Method::GET,
        "/api/v1/audit",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_OR_OPERATOR,
            mutation: false,
        },
    ),
    // Operation lists, operation details, and batch reports: every role
    // reads, submission is Administrator and Operator (§16.1). The
    // wildcards cover the `{operation_id}` and `{batch_id}` details.
    (
        Method::GET,
        "/api/v1/operations*",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ANY,
            mutation: false,
        },
    ),
    (
        Method::GET,
        "/api/v1/batches*",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ANY,
            mutation: false,
        },
    ),
    (
        Method::POST,
        "/api/v1/operations",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_OR_OPERATOR,
            mutation: true,
        },
    ),
    // Artifact viewing is every role; upload is Administrator and Operator.
    // The wildcards cover the `{artifact_id}` detail read and the chunk
    // upload and finalize writes under it.
    (
        Method::GET,
        "/api/v1/artifacts*",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ANY,
            mutation: false,
        },
    ),
    (
        Method::POST,
        "/api/v1/artifacts*",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_OR_OPERATOR,
            mutation: true,
        },
    ),
    // Credentials are Administrator only (§16.1).
    (
        Method::GET,
        "/api/v1/credentials",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: false,
        },
    ),
    (
        Method::POST,
        "/api/v1/credentials",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: true,
        },
    ),
    // Trust, import, and refresh are Administrator only; the address
    // patterns precede the enrollment route below. The trust wildcard also
    // covers the per-address confirmation `POST /api/v1/endpoints/trust/expect`.
    (
        Method::POST,
        "/api/v1/endpoints/trust*",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: true,
        },
    ),
    (
        Method::POST,
        "/api/v1/endpoints/import",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: true,
        },
    ),
    (
        Method::POST,
        "/api/v1/endpoints/refresh",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: true,
        },
    ),
    (
        Method::POST,
        "/api/v1/endpoints",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: true,
        },
    ),
    // Endpoint reads (inventory, resources, capabilities, diagnostics) are
    // every role; the wildcard covers the inventory route itself and every
    // per-endpoint read below it.
    (
        Method::GET,
        "/api/v1/endpoints*",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ANY,
            mutation: false,
        },
    ),
    // Tag removal under an endpoint is a group/tag write: Administrator.
    (
        Method::DELETE,
        "/api/v1/endpoints*",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: true,
        },
    ),
    // Group and tag views are every role; writes are Administrator. The
    // group read wildcard covers the `{group_id}` detail.
    (
        Method::GET,
        "/api/v1/groups*",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ANY,
            mutation: false,
        },
    ),
    (
        Method::GET,
        "/api/v1/tags",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ANY,
            mutation: false,
        },
    ),
    (
        Method::POST,
        "/api/v1/groups",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: true,
        },
    ),
    (
        Method::PUT,
        "/api/v1/groups*",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: true,
        },
    ),
    (
        Method::DELETE,
        "/api/v1/groups*",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: true,
        },
    ),
    (
        Method::PUT,
        "/api/v1/tags",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: true,
        },
    ),
    // Events, telemetry, and the §14.2 homepage overview are every role. The
    // telemetry wildcard covers the `{series_id}/samples` read.
    (
        Method::GET,
        "/api/v1/events",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ANY,
            mutation: false,
        },
    ),
    (
        Method::GET,
        "/api/v1/overview",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ANY,
            mutation: false,
        },
    ),
    (
        Method::GET,
        "/api/v1/telemetry*",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ANY,
            mutation: false,
        },
    ),
    // The center console surface (§15.5, §15.6, §21 0.7.0): the site,
    // endpoint, and operation views are every role — the handlers apply the
    // D3 site scope of the actor's assignment to every listed row. Binding
    // management is Administrator only (§16.1 管理中心绑定); center
    // operation submission is Administrator and Operator, and the handler
    // applies the same site scope to the target site.
    (
        Method::GET,
        "/api/v1/center*",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ANY,
            mutation: false,
        },
    ),
    (
        Method::POST,
        "/api/v1/center/bindings*",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_ONLY,
            mutation: true,
        },
    ),
    (
        Method::POST,
        "/api/v1/center/operations",
        RouteAccess::GuardedOnly {
            roles: RoleMask::ADMINISTRATOR_OR_OPERATOR,
            mutation: true,
        },
    ),
];

/// Resolves the authorization of one request path under one console scope.
///
/// The center management entries of [`ROUTE_TABLE`] exist only on the Center
/// console (audit follow-up F2): an Edge console does not register the
/// `/api/v1/center/*` routes, so its authorization table must not name them
/// either — the surface is absent in both the router and the middleware.
fn route_access(method: &Method, path: &str, scope: crate::ConsoleScope) -> RouteAccess {
    for (route_method, pattern, access) in ROUTE_TABLE {
        if route_method != method {
            continue;
        }
        if pattern.starts_with(CENTER_SURFACE_PREFIX) && scope != crate::ConsoleScope::Center {
            continue;
        }
        let matches = if let Some(prefix) = pattern.strip_suffix('*') {
            path.starts_with(prefix)
        } else {
            path == *pattern
        };
        if matches {
            return *access;
        }
    }
    // Every other path — static assets, the UI shell, and the fallback — is
    // public: the console must load before a session exists.
    RouteAccess::Public
}

/// The shared prefix of every center management route.
const CENTER_SURFACE_PREFIX: &str = "/api/v1/center";

/// The per-request authentication state shared with the handlers.
#[derive(Clone, Debug)]
pub(crate) struct AuthState {
    policy: AuthPolicy,
    rate_limiter: LoginRateLimiter,
}

impl AuthState {
    pub(crate) fn new(policy: AuthPolicy) -> Self {
        Self {
            policy,
            rate_limiter: LoginRateLimiter::new(),
        }
    }

    pub(crate) fn policy(&self) -> &AuthPolicy {
        &self.policy
    }
}

/// The §16.2 in-process sign-in rate limiter: 5 failures per username and
/// 20 per client address in a 15-minute sliding window.
///
/// Both bucket maps are memory-bounded (security-review N3): a bucket is
/// only removed once every entry has left the window, so without a
/// backstop each map would accumulate every distinct key ever presented.
/// [`BucketMap`] therefore sweeps the whole map once
/// [`BUCKET_PRUNE_THRESHOLD`] new keys have been inserted since the last
/// sweep, reclaiming every bucket whose entries have all expired — the
/// dormant keys the per-access pruning never reaches.
#[derive(Clone, Debug)]
struct LoginRateLimiter {
    by_username: Arc<Mutex<BucketMap>>,
    by_ip: Arc<Mutex<BucketMap>>,
}

/// One rate-limit bucket map with the bookkeeping that bounds its size.
#[derive(Debug)]
struct BucketMap {
    buckets: HashMap<String, VecDeque<Instant>>,
    /// New keys inserted since the last full sweep; reaching
    /// [`BUCKET_PRUNE_THRESHOLD`] triggers one.
    inserts_since_prune: usize,
}

impl BucketMap {
    fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            inserts_since_prune: 0,
        }
    }
}

impl LoginRateLimiter {
    fn new() -> Self {
        Self {
            by_username: Arc::new(Mutex::new(BucketMap::new())),
            by_ip: Arc::new(Mutex::new(BucketMap::new())),
        }
    }

    /// Reports whether another attempt is allowed for this username and
    /// address. The username bound is the more specific one: a blocked
    /// username is refused even when the address budget remains.
    fn allows(&self, username: &str, ip: &str, now: Instant) -> bool {
        Self::allows_key(
            &self.by_username,
            &bounded_username_key(username),
            now,
            USERNAME_FAILURE_LIMIT,
        ) && Self::allows_key(&self.by_ip, ip, now, IP_FAILURE_LIMIT)
    }

    /// Records one failed attempt for this username and address.
    fn record_failure(&self, username: &str, ip: &str, now: Instant) {
        Self::record_key(
            &self.by_username,
            &bounded_username_key(username),
            now,
            USERNAME_FAILURE_LIMIT,
        );
        Self::record_key(&self.by_ip, ip, now, IP_FAILURE_LIMIT);
    }

    fn allows_key(bucket: &Arc<Mutex<BucketMap>>, key: &str, now: Instant, limit: usize) -> bool {
        let Ok(mut guard) = bucket.lock() else {
            return false;
        };
        let buckets = &mut *guard;
        let failures = match buckets.buckets.entry(key.to_owned()) {
            Entry::Vacant(entry) => {
                buckets.inserts_since_prune += 1;
                entry.insert(VecDeque::new())
            }
            Entry::Occupied(entry) => entry.into_mut(),
        };
        while failures
            .front()
            .is_some_and(|at| now.duration_since(*at) >= RATE_WINDOW)
        {
            failures.pop_front();
        }
        let allowed = failures.len() < limit;
        Self::prune_if_due(&mut buckets.buckets, &mut buckets.inserts_since_prune, now);
        allowed
    }

    fn record_key(bucket: &Arc<Mutex<BucketMap>>, key: &str, now: Instant, limit: usize) {
        if let Ok(mut guard) = bucket.lock() {
            let buckets = &mut *guard;
            let failures = match buckets.buckets.entry(key.to_owned()) {
                Entry::Vacant(entry) => {
                    buckets.inserts_since_prune += 1;
                    entry.insert(VecDeque::new())
                }
                Entry::Occupied(entry) => entry.into_mut(),
            };
            while failures
                .front()
                .is_some_and(|at| now.duration_since(*at) >= RATE_WINDOW)
            {
                failures.pop_front();
            }
            if failures.len() < limit {
                failures.push_back(now);
            }
            Self::prune_if_due(&mut buckets.buckets, &mut buckets.inserts_since_prune, now);
        }
    }

    /// Runs the full sweep once the map has grown by
    /// [`BUCKET_PRUNE_THRESHOLD`] buckets since the last one. Only vacant
    /// inserts can grow the map, so only they are counted (N3).
    fn prune_if_due(
        buckets: &mut HashMap<String, VecDeque<Instant>>,
        inserts_since_prune: &mut usize,
        now: Instant,
    ) {
        if *inserts_since_prune >= BUCKET_PRUNE_THRESHOLD {
            *inserts_since_prune = 0;
            Self::prune_expired(buckets, now);
        }
    }

    /// Removes every bucket whose entries have all left the window — the
    /// dormant keys the per-access pruning never reaches (N3). The sweep
    /// applies the same expiry rule as the access path, so a bucket is
    /// reclaimed only when the next access would empty it anyway, and the
    /// limit verdicts are untouched.
    fn prune_expired(buckets: &mut HashMap<String, VecDeque<Instant>>, now: Instant) {
        buckets.retain(|_, failures| {
            while failures
                .front()
                .is_some_and(|at| now.duration_since(*at) >= RATE_WINDOW)
            {
                failures.pop_front();
            }
            !failures.is_empty()
        });
    }
}

/// Bounds a presented username to the [`RATE_LIMIT_USERNAME_CHARS`]-long
/// bucket key.
///
/// The sign-in surface keys the per-username bucket on the *presented*
/// username — before validation, so invalid-name attempts still consume the
/// budget. The wire value is attacker-controlled and only bounded by the
/// request body limit, so the raw string must never reach the bucket map:
/// the key is the first
/// [`MAX_PRINCIPAL_NAME_CHARS`](rutilus_domain::MAX_PRINCIPAL_NAME_CHARS)
/// characters. The periodic pruning (N3) bounds the *number* of buckets;
/// this bound keeps each key itself bounded, and both are needed. The
/// borrow is returned when the value is already within the bound, so the
/// common (valid-name) path allocates nothing.
fn bounded_username_key(username: &str) -> std::borrow::Cow<'_, str> {
    if username.chars().count() <= RATE_LIMIT_USERNAME_CHARS {
        std::borrow::Cow::Borrowed(username)
    } else {
        std::borrow::Cow::Owned(username.chars().take(RATE_LIMIT_USERNAME_CHARS).collect())
    }
}

/// The auth middleware: resolves the acting session and principal of every
/// request (§16.2).
pub(crate) async fn auth_middleware<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response
where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let access = route_access(
        request.method(),
        request.uri().path(),
        crate::ConsoleScope::of(state.origin),
    );
    let guarded = state.auth.policy().is_guarded();
    let (uri, headers) = (request.uri().clone(), request.headers().clone());

    match access {
        RouteAccess::Public => {
            request
                .extensions_mut()
                .insert(AuthContext::unauthenticated(state.actor));
            next.run(request).await
        }
        RouteAccess::Always { roles, mutation } | RouteAccess::GuardedOnly { roles, mutation } => {
            // In open mode the product surface is served without a session;
            // the always-required routes still need one.
            let requires_session = guarded || matches!(access, RouteAccess::Always { .. });
            if !requires_session {
                request
                    .extensions_mut()
                    .insert(AuthContext::unauthenticated(state.actor));
                return next.run(request).await;
            }
            let Some((context, session, presented_token)) =
                resolve_session(&state, &headers, mutation).await
            else {
                return json_error(
                    StatusCode::UNAUTHORIZED,
                    "a valid session is required".to_owned(),
                );
            };
            if !roles.allows(context.role.unwrap_or(Role::Viewer)) {
                return json_error(
                    StatusCode::FORBIDDEN,
                    "this role cannot reach the requested surface".to_owned(),
                );
            }
            request.extensions_mut().insert(context);
            let mut response = next.run(request).await;
            // Every authenticated response re-issues the cookie with the
            // `Max-Age` still left on the session's fixed `expires_at`, so
            // the browser's deadline always matches the row. Activity never
            // extends the session — the countdown continues while it is in
            // use. The presenting token is re-issued unchanged — the row
            // stores only its hash.
            let secure = is_https(&uri, &headers);
            response.headers_mut().append(
                SET_COOKIE,
                session_cookie(presented_token, session.expires_at(), secure),
            );
            response
        }
    }
}

/// Resolves the presenting session into an acting context.
///
/// The token hash lookup, expiry and revocation checks, the principal
/// enablement check, the CSRF comparison of mutating requests, and the
/// last-use touch all happen here, so every handler behind the middleware
/// sees an already-validated identity. The resolved session and the
/// presenting wire token are returned with the context so the middleware
/// can refresh the cookie lifetime.
async fn resolve_session<'a, Services, Gateway, Time>(
    state: &WebState<Services, Gateway, Time>,
    headers: &'a HeaderMap,
    mutation: bool,
) -> Option<(AuthContext, Session, &'a str)>
where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let cookie = cookie_value(headers, SESSION_COOKIE_NAME)?;
    let token_hash = state.services.token_hash(cookie);
    let session = state
        .services
        .find_session_by_token_hash(&token_hash)
        .await
        .ok()??;
    let now = state.clock.now();
    if !session.is_active(now) {
        return None;
    }
    if mutation && !csrf_matches(state.services.as_ref(), headers, session.csrf_hash()) {
        return None;
    }
    let principal = state
        .services
        .find_principal(session.principal_id())
        .await
        .ok()??;
    if principal.state() != PrincipalState::Enabled {
        return None;
    }
    let (role, assignment_site_id) = state
        .services
        .find_role_assignment(session.principal_id())
        .await
        .ok()?
        .map_or((None, None), |assignment| {
            (Some(assignment.role()), assignment.site_id())
        });
    // Activity advances the persisted last-use time at most once per
    // minute, keeping the request path write-free on a busy console. The
    // expiry itself is absolute: `expires_at` is fixed at sign-in plus
    // eight hours, so the touch never extends the session — it only keeps
    // the audit trail and the session listing truthful.
    if now - session.last_used_at() >= TOUCH_INTERVAL {
        let _ = state.services.touch_session(session.id(), now).await;
    }
    Some((
        AuthContext {
            actor: AuditActor::User,
            actor_principal_id: Some(session.principal_id()),
            session_id: Some(session.id()),
            role,
            assignment_site_id,
        },
        session,
        cookie,
    ))
}

/// Compares a presented CSRF token against the session's stored hash in
/// constant time (§16.2 "CSRF 防护").
fn csrf_matches<Services>(
    services: &Services,
    headers: &HeaderMap,
    expected_hash: &[u8; 32],
) -> bool
where
    Services: AuthServices,
{
    let Some(presented) = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let presented_hash = services.token_hash(presented);
    constant_time_eq(&presented_hash, expected_hash)
}

/// Compares two fixed-length digests without short-circuiting.
///
/// A single `|` accumulates every differing byte into one value that is
/// tested only at the end, so the loop runs the same operations for any
/// input pair — the `subtle` fold the workspace's no-`unsafe` rule allows.
fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Reads one cookie value from a request's `Cookie` header.
fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookie = headers.get(COOKIE)?.to_str().ok()?;
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(name) {
            return Some(value.strip_prefix('=')?.trim());
        }
        if let Some(value) = pair.strip_prefix(&format!("{name}=")) {
            return Some(value.trim());
        }
    }
    None
}

/// Builds the `Set-Cookie` header of one session.
///
/// The cookie is `HttpOnly` (never readable by script), `SameSite=Strict`
/// (never sent on cross-site requests), and `Secure` exactly when the
/// request arrived over HTTPS — a loopback HTTP console must still work.
fn session_cookie(token: &str, expires_at: OffsetDateTime, secure: bool) -> HeaderValue {
    let max_age = (expires_at - OffsetDateTime::now_utc())
        .whole_seconds()
        .max(0);
    let secure_flag = if secure { "; Secure" } else { "" };
    // The value is built from the base64url token, digits, and fixed
    // literals, so it is always a valid header; the fallback is unreachable
    // but keeps the construction infallible.
    HeaderValue::from_str(&format!(
        "{SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure_flag}"
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("rutilus_session=; Max-Age=0"))
}

/// Builds the `Set-Cookie` header that clears the session cookie.
fn clear_session_cookie() -> HeaderValue {
    HeaderValue::from_static("rutilus_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
}

/// The optional client address of one request, for rate limiting.
///
/// The address is only present when the router serves through
/// `into_make_service_with_connect_info`; the oneshot test bench and any
/// other direct service have no connection info, which the fallback
/// `unknown` key absorbs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MaybeClientAddr(Option<SocketAddr>);

impl<S> FromRequestParts<S> for MaybeClientAddr
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(
            ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
                .await
                .ok()
                .map(|connect_info| connect_info.0),
        ))
    }
}

/// The client address of one request, for rate limiting.
fn request_ip(connect_info: &MaybeClientAddr) -> String {
    match connect_info.0 {
        Some(address) => address.ip().to_string(),
        None => "unknown".to_owned(),
    }
}

/// Whether the request arrived over HTTPS (direct or via a TLS proxy).
fn is_https(uri: &axum::http::Uri, headers: &HeaderMap) -> bool {
    if uri.scheme_str() == Some("https") {
        return true;
    }
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|proto| {
            proto
                .split(',')
                .next()
                .is_some_and(|first| first.trim() == "https")
        })
}

/// The fixed salt of the dummy credential behind the `MINOR-1` sign-in
/// mitigation (docs/security-review.md; §16.2 side-channel protection).
///
/// The unknown-username branch of [`login`] runs one dummy Argon2id
/// verification so its cost matches the wrong-password branch — otherwise
/// the response timing of the two branches would let an attacker enumerate
/// valid usernames. The bytes are arbitrary pinned constants: deliberately
/// not random and never derived from any real user's data, so the dummy
/// computation cannot touch or leak a genuine credential. The array type
/// pins the length to the `argon2id-1` salt length, so the dummy
/// verification runs under exactly the parameters of the real path.
const DUMMY_SALT: [u8; ARGON2ID_SALT_LENGTH] = [0x1a; ARGON2ID_SALT_LENGTH];

/// The fixed derived hash of the dummy credential (see [`DUMMY_SALT`]).
///
/// Pinned to the `argon2id-1` hash length so the dummy derivation fills
/// the same 64 MiB of memory and produces the same 32-byte digest size as
/// a real verification.
const DUMMY_HASH: [u8; ARGON2ID_HASH_LENGTH] = [0x2b; ARGON2ID_HASH_LENGTH];

/// Runs one dummy Argon2id verification for the unknown-username sign-in
/// branch (security-review `MINOR-1` mitigation).
///
/// The branch has no stored hash to verify against, so the presented
/// password is verified against the fixed [`DUMMY_SALT`]/[`DUMMY_HASH`]
/// credential instead — the same `argon2id-1` parameters (64 MiB, 3
/// passes, 1 lane, 32-byte digest; the domain constants the value object
/// pins) the wrong-password branch's `verify_password` runs, so the two
/// branches cost the same and response timing cannot distinguish a
/// non-existent username from a wrong password. The verdict is always
/// discarded: the branch is a failure either way, and the cost is the
/// point.
///
/// The *presented* password — not a fixed string — is the input, so the
/// work profile matches the real branch (Argon2id cost depends slightly on
/// the password bytes); it is attacker-supplied input, never real user
/// data. The call is bounded by the login rate limiter (5 failures per
/// username, 20 per address, per 15-minute window), so the dummy cannot
/// become a denial-of-service lever.
fn dummy_password_verification<Services>(services: &Services, password: &SecretString)
where
    Services: AuthServices,
{
    // The constants' array types pin the `argon2id-1` lengths, so the
    // construction cannot fail; the `Ok` guard is a totality courtesy —
    // the workspace forbids panics in production code.
    let Ok(dummy) = Argon2IdHash::from_parts(&DUMMY_SALT, &DUMMY_HASH) else {
        return;
    };
    let _ = services.verify_password(&dummy, password);
}

/// Whether a presented password satisfies the product password policy (B1).
///
/// The floor is [`MIN_PASSWORD_CHARS`] characters counted as Unicode scalar
/// values — the same check the console form applies (`ui/src/lib.rs`
/// `BootstrapView`), so the API and the form agree on what a valid password
/// is.
#[must_use]
fn password_satisfies_policy(password: &SecretString) -> bool {
    password.expose_secret().chars().count() >= MIN_PASSWORD_CHARS
}

/// The password-policy refusal, worded like the console form
/// (`ui/src/i18n.rs` `error_password_too_short`).
fn password_policy_error() -> Response {
    json_error(
        StatusCode::BAD_REQUEST,
        "the password must contain at least 12 characters".to_owned(),
    )
}

/// The §16.2 sign-in handler.
///
/// The handler is the declarative sign-in flow — rate limit, lookup,
/// verification, session creation, audit — so the line count is inherent to
/// the steps it coordinates.
#[allow(clippy::too_many_lines)]
pub(crate) async fn login<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    uri: OriginalUri,
    headers: HeaderMap,
    connect_info: MaybeClientAddr,
    Json(request): Json<LoginRequest>,
) -> Response
where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let now = state.clock.now();
    if !password_satisfies_policy(request.password()) {
        // B1 (security batch): the API is the enforcement boundary — the
        // console form's 12-character floor is client-side convenience, not
        // a control, and under the fixed 'admin' name and the 5-per-15-minute
        // budget a one-character password is guessable in hours. The refusal
        // happens here, before the rate limiter, the lookup, and any
        // verification: it costs nothing, consumes no rate-limit budget (a
        // policy violation is not a login attempt), and writes no audit (the
        // response is the record — the same boundedness principle as the
        // rate-limited branch below).
        return password_policy_error();
    }
    let ip = request_ip(&connect_info);
    let username = request.username();
    let rate_now = Instant::now();
    let rate_limited = !state.auth.rate_limiter.allows(username, &ip, rate_now);
    if rate_limited {
        // B2 (security batch): a limiter refusal writes no audit event.
        // §16.3 audits login *outcomes* — attempts that ran; a request the
        // limiter refused before any verification never attempted one, and
        // the 429 itself is the record. Writing the started + failed pair
        // here would be unbounded — a flood of refused attempts is exactly
        // the attack that must not grow the audit table — and every audit
        // append serializes on the persistence write gate (`Semaphore(1)`),
        // so a 429 flood would starve legitimate session, telemetry, event,
        // and operation writes behind it.
        return json_error(
            StatusCode::TOO_MANY_REQUESTS,
            "too many sign-in attempts; try again later".to_owned(),
        );
    }

    let Ok(name) = PrincipalName::parse(username) else {
        state
            .auth
            .rate_limiter
            .record_failure(username, &ip, rate_now);
        record_login_failure(&state, None, now).await;
        return json_error(StatusCode::UNAUTHORIZED, "sign-in failed".to_owned());
    };
    let Some(principal) = state
        .services
        .find_principal_by_name(&name)
        .await
        .ok()
        .flatten()
    else {
        // MINOR-1 (docs/security-review.md): this branch must not return
        // observably faster than the wrong-password branch — the timing
        // difference would let an attacker enumerate valid usernames. One
        // dummy Argon2id verification balances the two paths; the failure
        // handling below stays identical either way.
        dummy_password_verification(state.services.as_ref(), request.password());
        state
            .auth
            .rate_limiter
            .record_failure(username, &ip, rate_now);
        record_login_failure(&state, None, now).await;
        return json_error(StatusCode::UNAUTHORIZED, "sign-in failed".to_owned());
    };
    if principal.state() != PrincipalState::Enabled {
        // B4 (security batch, extends MINOR-1): this branch must not return
        // observably faster than the wrong-password branch either — the
        // account is *known to exist and known to be disabled* here, so a
        // cheap return would be a positive username oracle. One dummy
        // Argon2id verification (the same cost equalizer as the
        // unknown-username branch) balances the disabled branch against the
        // wrong-password branch; the failure handling below stays identical.
        dummy_password_verification(state.services.as_ref(), request.password());
        state
            .auth
            .rate_limiter
            .record_failure(username, &ip, rate_now);
        record_login_failure(&state, Some(principal.id()), now).await;
        return json_error(StatusCode::UNAUTHORIZED, "sign-in failed".to_owned());
    }
    let Some(credential) = state
        .services
        .find_password_credential(principal.id())
        .await
        .ok()
        .flatten()
    else {
        // B4 (security batch, extends MINOR-1): the principal is known to
        // exist but holds no password credential — a cheap return here would
        // answer "this username exists" observably faster than the
        // wrong-password branch. One dummy Argon2id verification balances
        // the branch; the failure handling below stays identical.
        dummy_password_verification(state.services.as_ref(), request.password());
        state
            .auth
            .rate_limiter
            .record_failure(username, &ip, rate_now);
        record_login_failure(&state, Some(principal.id()), now).await;
        return json_error(StatusCode::UNAUTHORIZED, "sign-in failed".to_owned());
    };
    if !state
        .services
        .verify_password(credential.hash(), request.password())
    {
        state
            .auth
            .rate_limiter
            .record_failure(username, &ip, rate_now);
        record_login_failure(&state, Some(principal.id()), now).await;
        return json_error(StatusCode::UNAUTHORIZED, "sign-in failed".to_owned());
    }
    if let Some(authenticator) = state
        .services
        .list_totp_authenticators(principal.id())
        .await
        .ok()
        .into_iter()
        .flatten()
        .find(|authenticator| authenticator.state() == rutilus_domain::TotpState::Active)
    {
        let Some(code) = request.totp_code() else {
            state
                .auth
                .rate_limiter
                .record_failure(username, &ip, rate_now);
            record_login_failure(&state, Some(principal.id()), now).await;
            return json_error(StatusCode::UNAUTHORIZED, "sign-in failed".to_owned());
        };
        let Ok(step) = state.services.verify_totp(
            authenticator.secret(),
            code,
            now,
            authenticator.last_used_step(),
        ) else {
            state
                .auth
                .rate_limiter
                .record_failure(username, &ip, rate_now);
            record_login_failure(&state, Some(principal.id()), now).await;
            return json_error(StatusCode::UNAUTHORIZED, "sign-in failed".to_owned());
        };
        // The conditional step write refuses a replay that raced ahead; a
        // refused step means the code was already consumed.
        if !state
            .services
            .record_totp_step(authenticator.id(), step)
            .await
            .ok()
            .unwrap_or(false)
        {
            state
                .auth
                .rate_limiter
                .record_failure(username, &ip, rate_now);
            record_login_failure(&state, Some(principal.id()), now).await;
            return json_error(StatusCode::UNAUTHORIZED, "sign-in failed".to_owned());
        }
    }
    let Ok(tokens) = state.services.issue_tokens() else {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let session = Session::new(
        SessionId::generate(),
        principal.id(),
        *tokens.session_token_hash(),
        *tokens.csrf_token_hash(),
        now,
        now + SESSION_LIFETIME,
    );
    if state.services.create_session(&session).await.is_err() {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    }
    record_login_success(&state, principal.id(), now).await;
    let secure = is_https(&uri.0, &headers);
    let mut response = Json(LoginResponse::new(tokens.csrf_token().to_owned())).into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        session_cookie(tokens.session_token(), session.expires_at(), secure),
    );
    no_store(&mut response);
    response
}

/// The §16.2 sign-out handler.
pub(crate) async fn logout<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    context: axum::extract::Extension<AuthContext>,
    Json(_request): Json<LogoutRequest>,
) -> Response
where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let now = state.clock.now();
    let Some(session_id) = context.session_id() else {
        return json_error(
            StatusCode::UNAUTHORIZED,
            "a valid session is required".to_owned(),
        );
    };
    if state
        .services
        .revoke_session(session_id, now)
        .await
        .is_err()
    {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    }
    record_management_event(
        &state,
        context.actor(),
        context.actor_principal_id(),
        ProductPermission::Authenticate,
        AuditAction::Logout,
        true,
        now,
    )
    .await;
    let mut response = Json(LoginResponse::new(String::new())).into_response();
    response
        .headers_mut()
        .insert(SET_COOKIE, clear_session_cookie());
    no_store(&mut response);
    response
}

/// The §16.2 first-startup claim handler.
///
/// The handler is the declarative claim flow — code lookup, optional TOTP
/// enrollment, credential and session creation, audit, gate arming — so the
/// line count is inherent to the steps it coordinates.
#[allow(clippy::too_many_lines)]
pub(crate) async fn bootstrap_complete<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    uri: OriginalUri,
    headers: HeaderMap,
    Json(request): Json<BootstrapCompleteRequest>,
) -> Response
where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let now = state.clock.now();
    if !password_satisfies_policy(request.password()) {
        // B1 (security batch): the claim sets the product's first
        // credential, so the API boundary — not the console form — must
        // enforce the minimum. The refusal happens before anything is
        // consumed: the one-time code survives a rejected claim.
        return password_policy_error();
    }
    if !request.has_complete_totp_pair() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "the TOTP secret and its activation code must travel together".to_owned(),
        );
    }
    let Ok(admin_name) = PrincipalName::parse(BOOTSTRAP_PRINCIPAL_NAME) else {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Some(principal) = state
        .services
        .find_principal_by_name(&admin_name)
        .await
        .ok()
        .flatten()
    else {
        return json_error(StatusCode::UNAUTHORIZED, "bootstrap failed".to_owned());
    };
    let code_hash = state.services.hash_bootstrap_code(request.code());
    let Some(code) = state
        .services
        .find_bootstrap_code_by_hash(&code_hash)
        .await
        .ok()
        .flatten()
    else {
        record_login_failure(&state, Some(principal.id()), now).await;
        return json_error(StatusCode::UNAUTHORIZED, "bootstrap failed".to_owned());
    };
    if code.used_at().is_some() {
        record_login_failure(&state, Some(principal.id()), now).await;
        return json_error(StatusCode::UNAUTHORIZED, "bootstrap failed".to_owned());
    }
    // The optional TOTP enrollment is verified before the claim consumes
    // anything, so a bad secret or code never burns the one-time code.
    let authenticator = match request.totp_secret() {
        Some(encoded) => {
            let Some(decoded) =
                base32::decode(base32::Alphabet::Rfc4648 { padding: false }, encoded)
            else {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "the TOTP secret is not valid base32".to_owned(),
                );
            };
            let Ok(secret) = <[u8; TOTP_SECRET_LENGTH]>::try_from(decoded.as_slice()) else {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "the TOTP secret must decode to 20 bytes".to_owned(),
                );
            };
            let secret = SecretBox::new(Box::new(secret));
            let Some(code) = request.totp_code() else {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "the TOTP activation code is required".to_owned(),
                );
            };
            let mut authenticator = TotpAuthenticator::new(
                rutilus_domain::TotpAuthenticatorId::generate(),
                principal.id(),
                secret,
                now,
            );
            if authenticator.activate(code, now).is_err() {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "the TOTP activation code is invalid".to_owned(),
                );
            }
            Some(authenticator)
        }
        None => None,
    };
    let Ok(hash) = state.services.hash_password(request.password()) else {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Ok(credential) = PasswordCredential::try_from_parts(principal.id(), hash, now) else {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Ok(tokens) = state.services.issue_tokens() else {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let session = Session::new(
        SessionId::generate(),
        principal.id(),
        *tokens.session_token_hash(),
        *tokens.csrf_token_hash(),
        now,
        now + SESSION_LIFETIME,
    );
    if state
        .services
        .consume_bootstrap_code(
            code.id(),
            principal.id(),
            &credential,
            authenticator.as_ref(),
            &session,
            now,
        )
        .await
        .is_err()
    {
        return json_error(StatusCode::UNAUTHORIZED, "bootstrap failed".to_owned());
    }
    record_login_success(&state, principal.id(), now).await;
    if authenticator.is_some() {
        record_management_event(
            &state,
            AuditActor::User,
            Some(principal.id()),
            ProductPermission::ManageUsers,
            AuditAction::ManageTotp,
            true,
            now,
        )
        .await;
    }
    // The claim is the point of no return for the loopback lifecycle: the
    // console starts enforcing sessions from this request on.
    if let AuthPolicy::PendingBootstrap(gate) = &state.auth.policy {
        gate.arm();
    }
    let secure = is_https(&uri.0, &headers);
    let mut response = Json(BootstrapCompleteResponse::new(
        tokens.csrf_token().to_owned(),
    ))
    .into_response();
    response.headers_mut().insert(
        SET_COOKIE,
        session_cookie(tokens.session_token(), session.expires_at(), secure),
    );
    no_store(&mut response);
    response
}

/// The §16.2 password-change handler.
pub(crate) async fn change_password<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    context: axum::extract::Extension<AuthContext>,
    Json(request): Json<SetPasswordRequest>,
) -> Response
where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let now = state.clock.now();
    if !password_satisfies_policy(request.new_password()) {
        // B1 (security batch): same enforcement as the sign-in and bootstrap
        // boundaries — the API, not the form, is the policy boundary for the
        // new password.
        return password_policy_error();
    }
    let Some(principal_id) = context.actor_principal_id() else {
        return json_error(
            StatusCode::UNAUTHORIZED,
            "a valid session is required".to_owned(),
        );
    };
    let Some(credential) = state
        .services
        .find_password_credential(principal_id)
        .await
        .ok()
        .flatten()
    else {
        return json_error(
            StatusCode::UNAUTHORIZED,
            "password change failed".to_owned(),
        );
    };
    if !state
        .services
        .verify_password(credential.hash(), request.current_password())
    {
        return json_error(
            StatusCode::UNAUTHORIZED,
            "password change failed".to_owned(),
        );
    }
    let Ok(hash) = state.services.hash_password(request.new_password()) else {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let Ok(updated) = PasswordCredential::try_from_parts(principal_id, hash, now) else {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    if state
        .services
        .save_password_credential(&updated)
        .await
        .is_err()
    {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    }
    // §16.2 "密码或角色变化撤销旧 Session": a password change revokes every
    // session of the principal, including the presenting one — the client
    // must sign in again.
    if state
        .services
        .revoke_sessions_for_principal(principal_id, now)
        .await
        .is_err()
    {
        // B3 (security batch): the revocation is not optional — a silently
        // failed revocation would leave every old token valid until its
        // eight-hour deadline with no user or audit signal (§16.2 控制静默
        // 失效). The password change already succeeded and is not rolled
        // back; the failure is surfaced as an explicit 500 and recorded as
        // a failed change-password outcome so the partial state is visible.
        record_outcome(
            &state,
            AuditActor::User,
            Some(principal_id),
            ProductPermission::Authenticate,
            AuditAction::ChangePassword,
            false,
            Some((
                AuditFailure::AuthenticationFailed,
                AuditFailureVerification::Inconclusive,
            )),
            now,
        )
        .await;
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    }
    record_management_event(
        &state,
        AuditActor::User,
        Some(principal_id),
        ProductPermission::Authenticate,
        AuditAction::ChangePassword,
        true,
        now,
    )
    .await;
    let mut response = Json(LoginResponse::new(String::new())).into_response();
    response
        .headers_mut()
        .insert(SET_COOKIE, clear_session_cookie());
    no_store(&mut response);
    response
}

/// The §16.2 session-state handler: the console's first-screen decision.
pub(crate) async fn me<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    headers: HeaderMap,
) -> Response
where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let bootstrap_pending = state
        .services
        .has_unconsumed_bootstrap_code()
        .await
        .unwrap_or(false);
    let Some(cookie) = cookie_value(&headers, SESSION_COOKIE_NAME) else {
        return me_response(bootstrap_pending, None);
    };
    let token_hash = state.services.token_hash(cookie);
    let Some(session) = state
        .services
        .find_session_by_token_hash(&token_hash)
        .await
        .ok()
        .flatten()
    else {
        return me_response(bootstrap_pending, None);
    };
    if !session.is_active(state.clock.now()) {
        return me_response(bootstrap_pending, None);
    }
    let Some(principal) = state
        .services
        .find_principal(session.principal_id())
        .await
        .ok()
        .flatten()
    else {
        return me_response(bootstrap_pending, None);
    };
    if principal.state() != PrincipalState::Enabled {
        return me_response(bootstrap_pending, None);
    }
    let role = state
        .services
        .find_role_assignment(principal.id())
        .await
        .ok()
        .flatten()
        .map(|assignment| assignment.role());
    me_response(bootstrap_pending, Some((principal, role)))
}

fn me_response(bootstrap_pending: bool, principal: Option<(Principal, Option<Role>)>) -> Response {
    let authenticated = principal.is_some();
    let summary = principal.map(|(principal, role)| {
        PrincipalSummaryResponse::new(
            principal.id().to_string(),
            principal.name().to_string(),
            wire_state(principal.state()),
            role.map(wire_role),
        )
    });
    let response = Json(MeResponse::new(authenticated, bootstrap_pending, summary));
    let mut response = response.into_response();
    no_store(&mut response);
    response
}

/// The §16.2 session administration listing.
pub(crate) async fn list_sessions<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    context: axum::extract::Extension<AuthContext>,
) -> Response
where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let Ok(principals) = state.services.list_principals().await else {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut sessions = Vec::new();
    for principal in principals {
        let Ok(principal_sessions) = state.services.list_sessions(principal.id()).await else {
            return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
        };
        for session in principal_sessions {
            sessions.push(SessionSummaryResponse::new(
                session.id().to_string(),
                principal.id().to_string(),
                principal.name().to_string(),
                session.created_at(),
                session.last_used_at(),
                session.expires_at(),
                session.revoked_at(),
                Some(session.id()) == context.session_id(),
            ));
        }
    }
    json_ok(Json(SessionAdminResponse::new(sessions)))
}

/// Revokes one presented session (§16.2).
pub(crate) async fn revoke_session<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    context: axum::extract::Extension<AuthContext>,
    Json(request): Json<RevokeSessionRequest>,
) -> Response
where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let session_id = SessionId::from_uuid(request.session_id());
    if state
        .services
        .revoke_session(session_id, state.clock.now())
        .await
        .is_err()
    {
        return json_error(
            StatusCode::NOT_FOUND,
            "the session does not exist".to_owned(),
        );
    }
    record_management_event(
        &state,
        context.actor(),
        context.actor_principal_id(),
        ProductPermission::ManageUsers,
        AuditAction::ManageSessions,
        true,
        state.clock.now(),
    )
    .await;
    json_ok(Json(LoginResponse::new(String::new())))
}

/// The §16.1 user administration listing.
pub(crate) async fn list_users<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
) -> Response
where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let (Ok(principals), Ok(assignments)) = (
        state.services.list_principals().await,
        state.services.list_role_assignments().await,
    ) else {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let role_by_principal = assignments
        .into_iter()
        .map(|assignment| (assignment.principal_id(), assignment.role()))
        .collect::<HashMap<_, _>>();
    let users = principals
        .into_iter()
        .map(|principal| {
            UserSummaryResponse::new(
                principal.id().to_string(),
                principal.name().to_string(),
                wire_state(principal.state()),
                role_by_principal
                    .get(&principal.id())
                    .copied()
                    .map(wire_role),
                principal.created_at(),
            )
        })
        .collect();
    json_ok(Json(UserAdminResponse::new(users)))
}

/// Creates one product user with its §16.1 role.
pub(crate) async fn create_user<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    context: axum::extract::Extension<AuthContext>,
    Json(request): Json<CreateUserRequest>,
) -> Response
where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let now = state.clock.now();
    let Ok(name) = PrincipalName::parse(request.name()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "the principal name is invalid".to_owned(),
        );
    };
    if state
        .services
        .find_principal_by_name(&name)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return json_error(
            StatusCode::CONFLICT,
            "a principal with this name already exists".to_owned(),
        );
    }
    let principal = Principal::new(PrincipalId::generate(), name, now);
    if state.services.create_principal(&principal).await.is_err() {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let assignment = RoleAssignment::new(
        principal.id(),
        domain_role(request.role()),
        context.actor_principal_id(),
        now,
        None,
    );
    if state.services.assign_role(&assignment).await.is_err() {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    }
    record_management_event(
        &state,
        context.actor(),
        context.actor_principal_id(),
        ProductPermission::ManageUsers,
        AuditAction::ManageUsers,
        true,
        now,
    )
    .await;
    json_ok(Json(LoginResponse::new(String::new())))
}

/// Transitions one principal's enabled/disabled state (§16.1).
pub(crate) async fn set_user_state<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    context: axum::extract::Extension<AuthContext>,
    AxumPath(principal_id): AxumPath<String>,
    Json(request): Json<SetPrincipalStateRequest>,
) -> Response
where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let now = state.clock.now();
    let Ok(principal_id) = principal_id.parse::<PrincipalId>() else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "the principal id is invalid".to_owned(),
        );
    };
    if state
        .services
        .find_principal(principal_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return json_error(
            StatusCode::NOT_FOUND,
            "the principal does not exist".to_owned(),
        );
    }
    let state_value = domain_state(request.state());
    if state
        .services
        .set_principal_state(principal_id, state_value, now)
        .await
        .is_err()
    {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    }
    // §16.2 "密码或角色变化撤销旧 Session": disabling revokes the
    // principal's sessions, so the account stops working immediately.
    if state_value == PrincipalState::Disabled {
        let _ = state
            .services
            .revoke_sessions_for_principal(principal_id, now)
            .await;
    }
    record_management_event(
        &state,
        context.actor(),
        context.actor_principal_id(),
        ProductPermission::ManageUsers,
        AuditAction::ManageUsers,
        true,
        now,
    )
    .await;
    json_ok(Json(LoginResponse::new(String::new())))
}

/// Reassigns one principal's §16.1 role.
pub(crate) async fn assign_user_role<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    context: axum::extract::Extension<AuthContext>,
    AxumPath(principal_id): AxumPath<String>,
    Json(request): Json<AssignRoleRequest>,
) -> Response
where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let now = state.clock.now();
    let Ok(principal_id) = principal_id.parse::<PrincipalId>() else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "the principal id is invalid".to_owned(),
        );
    };
    if state
        .services
        .find_principal(principal_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return json_error(
            StatusCode::NOT_FOUND,
            "the principal does not exist".to_owned(),
        );
    }
    let assignment = RoleAssignment::new(
        principal_id,
        domain_role(request.role()),
        context.actor_principal_id(),
        now,
        None,
    );
    if state.services.assign_role(&assignment).await.is_err() {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    }
    // §16.2 "密码或角色变化撤销旧 Session": a role change revokes the
    // principal's sessions, so the new role applies from the next sign-in.
    let _ = state
        .services
        .revoke_sessions_for_principal(principal_id, now)
        .await;
    record_management_event(
        &state,
        context.actor(),
        context.actor_principal_id(),
        ProductPermission::ManageUsers,
        AuditAction::ManageUsers,
        true,
        now,
    )
    .await;
    json_ok(Json(LoginResponse::new(String::new())))
}

fn wire_state(state: PrincipalState) -> PrincipalStateResponse {
    match state {
        PrincipalState::Enabled => PrincipalStateResponse::Enabled,
        PrincipalState::Disabled => PrincipalStateResponse::Disabled,
    }
}

fn domain_state(state: PrincipalStateResponse) -> PrincipalState {
    match state {
        PrincipalStateResponse::Enabled => PrincipalState::Enabled,
        PrincipalStateResponse::Disabled => PrincipalState::Disabled,
    }
}

fn wire_role(role: Role) -> RoleResponse {
    match role {
        Role::Administrator => RoleResponse::Administrator,
        Role::Operator => RoleResponse::Operator,
        Role::Viewer => RoleResponse::Viewer,
    }
}

fn domain_role(role: RoleResponse) -> Role {
    match role {
        RoleResponse::Administrator => Role::Administrator,
        RoleResponse::Operator => Role::Operator,
        RoleResponse::Viewer => Role::Viewer,
    }
}

/// Builds one audit operation context for an authentication or management
/// action (§16.3).
fn audit_context<Services, Gateway, Time>(
    state: &WebState<Services, Gateway, Time>,
    actor: AuditActor,
    actor_principal_id: Option<PrincipalId>,
    permission: ProductPermission,
    action: AuditAction,
) -> Result<AuditOperationContext, AuditOperationContextError>
where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    AuditOperationContext::try_new_with_actor_principal(
        AuditOperationId::generate(),
        actor,
        state.origin,
        AuditTarget::Product,
        AuditParameterSummary::EndpointRefresh,
        permission,
        action,
        AuditRedfishOperation::None,
        actor_principal_id,
    )
}

/// Records a failed sign-in: `started` then `failed`, so the audit trail
/// shows the attempt and the rejection (§16.3).
///
/// Rate-limited refusals never reach this function (B2): the limiter
/// rejected the request before it attempted anything, and the 429 response
/// is the record — auditing every refused attempt would grow the table
/// without bound and serialize each append on the persistence write gate.
async fn record_login_failure<Services, Gateway, Time>(
    state: &WebState<Services, Gateway, Time>,
    principal_id: Option<PrincipalId>,
    now: OffsetDateTime,
) where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let actor = if principal_id.is_some() {
        AuditActor::User
    } else {
        AuditActor::System
    };
    record_outcome(
        state,
        actor,
        principal_id,
        ProductPermission::Authenticate,
        AuditAction::Login,
        false,
        Some((
            AuditFailure::AuthenticationFailed,
            AuditFailureVerification::Rejected,
        )),
        now,
    )
    .await;
}

/// Records a successful sign-in.
async fn record_login_success<Services, Gateway, Time>(
    state: &WebState<Services, Gateway, Time>,
    principal_id: PrincipalId,
    now: OffsetDateTime,
) where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    record_outcome(
        state,
        AuditActor::User,
        Some(principal_id),
        ProductPermission::Authenticate,
        AuditAction::Login,
        true,
        None,
        now,
    )
    .await;
}

/// Records one authentication or management outcome as a start/terminal
/// pair (§16.3).
async fn record_management_event<Services, Gateway, Time>(
    state: &WebState<Services, Gateway, Time>,
    actor: AuditActor,
    actor_principal_id: Option<PrincipalId>,
    permission: ProductPermission,
    action: AuditAction,
    succeeded: bool,
    now: OffsetDateTime,
) where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    record_outcome(
        state,
        actor,
        actor_principal_id,
        permission,
        action,
        succeeded,
        None,
        now,
    )
    .await;
}

/// Appends the `started` event and one terminal event of an audited
/// authentication or management action.
///
/// An audit append failure never fails the request: the boundary is
/// best-effort on the sign-in path, exactly like the product boundaries.
#[allow(clippy::too_many_arguments)]
async fn record_outcome<Services, Gateway, Time>(
    state: &WebState<Services, Gateway, Time>,
    actor: AuditActor,
    actor_principal_id: Option<PrincipalId>,
    permission: ProductPermission,
    action: AuditAction,
    succeeded: bool,
    failure: Option<(AuditFailure, AuditFailureVerification)>,
    now: OffsetDateTime,
) where
    Services: AuditEventWriter + AuthServices,
    Time: Clock,
{
    let Ok(context) = audit_context(state, actor, actor_principal_id, permission, action) else {
        return;
    };
    let started = AuditEvent::started(context.clone(), now);
    let _ = state.services.append_audit_event(&started).await;
    let Ok(sequence) = AuditSequence::FIRST.next() else {
        return;
    };
    let terminal = if succeeded {
        AuditEvent::succeeded(context, sequence, now)
    } else if let Some((failure, verification)) = failure {
        AuditEvent::failed(context, sequence, failure, verification, now)
    } else {
        return;
    };
    let Ok(terminal) = terminal else {
        return;
    };
    let _ = state.services.append_audit_event(&terminal).await;
}

fn json_ok<Body: IntoResponse>(body: Body) -> Response {
    let mut response = body.into_response();
    no_store(&mut response);
    response
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn role_masks_follow_the_section_16_1_matrix() {
        assert!(RoleMask::ANY.allows(Role::Administrator));
        assert!(RoleMask::ANY.allows(Role::Operator));
        assert!(RoleMask::ANY.allows(Role::Viewer));
        assert!(RoleMask::ADMINISTRATOR_ONLY.allows(Role::Administrator));
        assert!(!RoleMask::ADMINISTRATOR_ONLY.allows(Role::Operator));
        assert!(!RoleMask::ADMINISTRATOR_ONLY.allows(Role::Viewer));
        assert!(RoleMask::ADMINISTRATOR_OR_OPERATOR.allows(Role::Administrator));
        assert!(RoleMask::ADMINISTRATOR_OR_OPERATOR.allows(Role::Operator));
        assert!(!RoleMask::ADMINISTRATOR_OR_OPERATOR.allows(Role::Viewer));
    }

    /// The authorization verdict of one path on the Edge console surface.
    fn edge_access(method: &Method, path: &str) -> RouteAccess {
        route_access(method, path, crate::ConsoleScope::Edge)
    }

    /// The authorization verdict of one path on the Center console surface.
    fn center_access(method: &Method, path: &str) -> RouteAccess {
        route_access(method, path, crate::ConsoleScope::Center)
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn route_table_pins_the_authorization_matrix() {
        // Public sign-in surface.
        assert_eq!(
            edge_access(&Method::GET, "/api/v1/health"),
            RouteAccess::Public
        );
        assert_eq!(
            edge_access(&Method::POST, "/api/v1/auth/login"),
            RouteAccess::Public
        );
        assert_eq!(
            edge_access(&Method::POST, "/api/v1/auth/bootstrap"),
            RouteAccess::Public
        );
        assert_eq!(
            edge_access(&Method::GET, "/api/v1/auth/me"),
            RouteAccess::Public
        );
        // Static assets and the fallback stay public.
        assert_eq!(edge_access(&Method::GET, "/app.css"), RouteAccess::Public);
        assert_eq!(edge_access(&Method::GET, "/missing"), RouteAccess::Public);

        // Every-role reads.
        assert_eq!(
            edge_access(&Method::GET, "/api/v1/endpoints"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ANY,
                mutation: false
            }
        );
        assert_eq!(
            edge_access(
                &Method::GET,
                "/api/v1/endpoints/6f6f9e40-2c5a-4b4e-9f6f-7f7f7f7f7f7f/resources"
            ),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ANY,
                mutation: false
            }
        );
        assert_eq!(
            edge_access(&Method::GET, "/api/v1/operations"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ANY,
                mutation: false
            }
        );
        assert_eq!(
            edge_access(
                &Method::GET,
                "/api/v1/operations/77f4e8c1-91a0-4b3e-8a5d-000000000001"
            ),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ANY,
                mutation: false
            }
        );
        assert_eq!(
            edge_access(&Method::GET, "/api/v1/batches"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ANY,
                mutation: false
            }
        );
        assert_eq!(
            edge_access(
                &Method::GET,
                "/api/v1/batches/77f4e8c1-91a0-4b3e-8a5d-000000000002"
            ),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ANY,
                mutation: false
            }
        );
        // Administrator+Operator writes.
        assert_eq!(
            edge_access(&Method::POST, "/api/v1/operations"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ADMINISTRATOR_OR_OPERATOR,
                mutation: true
            }
        );
        // Artifact reads are every role; the upload, chunk, and finalize
        // writes are Administrator+Operator with the CSRF requirement.
        assert_eq!(
            edge_access(&Method::GET, "/api/v1/artifacts"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ANY,
                mutation: false
            }
        );
        assert_eq!(
            edge_access(
                &Method::GET,
                "/api/v1/artifacts/77f4e8c1-91a0-4b3e-8a5d-000000000003"
            ),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ANY,
                mutation: false
            }
        );
        assert_eq!(
            edge_access(&Method::POST, "/api/v1/artifacts"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ADMINISTRATOR_OR_OPERATOR,
                mutation: true
            }
        );
        assert_eq!(
            edge_access(
                &Method::POST,
                "/api/v1/artifacts/77f4e8c1-91a0-4b3e-8a5d-000000000003/chunks"
            ),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ADMINISTRATOR_OR_OPERATOR,
                mutation: true
            }
        );
        assert_eq!(
            edge_access(
                &Method::POST,
                "/api/v1/artifacts/77f4e8c1-91a0-4b3e-8a5d-000000000003/finalize"
            ),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ADMINISTRATOR_OR_OPERATOR,
                mutation: true
            }
        );
        // Administrator-only surfaces.
        assert_eq!(
            edge_access(&Method::GET, "/api/v1/credentials"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ADMINISTRATOR_ONLY,
                mutation: false
            }
        );
        assert_eq!(
            edge_access(&Method::POST, "/api/v1/credentials"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ADMINISTRATOR_ONLY,
                mutation: true
            }
        );
        assert_eq!(
            edge_access(&Method::POST, "/api/v1/endpoints/trust"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ADMINISTRATOR_ONLY,
                mutation: true
            }
        );
        assert_eq!(
            edge_access(
                &Method::POST,
                "/api/v1/endpoints/trust/9f3d1c2a-3b6e-4f8a-9c1d-000000000001/expect"
            ),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ADMINISTRATOR_ONLY,
                mutation: true
            }
        );
        // The address-specific POSTs precede the enrollment route.
        assert_eq!(
            edge_access(&Method::POST, "/api/v1/endpoints/refresh"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ADMINISTRATOR_ONLY,
                mutation: true
            }
        );
        assert_eq!(
            edge_access(&Method::POST, "/api/v1/endpoints"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ADMINISTRATOR_ONLY,
                mutation: true
            }
        );
        // Group and telemetry reads are every role, including the
        // parameterized details.
        assert_eq!(
            edge_access(&Method::GET, "/api/v1/groups"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ANY,
                mutation: false
            }
        );
        assert_eq!(
            edge_access(
                &Method::GET,
                "/api/v1/groups/77f4e8c1-91a0-4b3e-8a5d-000000000004"
            ),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ANY,
                mutation: false
            }
        );
        assert_eq!(
            edge_access(&Method::GET, "/api/v1/telemetry"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ANY,
                mutation: false
            }
        );
        assert_eq!(
            edge_access(
                &Method::GET,
                "/api/v1/telemetry/77f4e8c1-91a0-4b3e-8a5d-000000000005/samples"
            ),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ANY,
                mutation: false
            }
        );
        // The §14.2 homepage aggregate is a read: every role, no session in
        // Open mode.
        assert_eq!(
            edge_access(&Method::GET, "/api/v1/overview"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ANY,
                mutation: false
            }
        );
        // The administration surface requires a session in every mode.
        assert_eq!(
            edge_access(&Method::GET, "/api/v1/admin/users"),
            RouteAccess::Always {
                roles: RoleMask::ADMINISTRATOR_ONLY,
                mutation: false
            }
        );
        assert_eq!(
            edge_access(&Method::POST, "/api/v1/admin/users/some-uuid/state"),
            RouteAccess::Always {
                roles: RoleMask::ADMINISTRATOR_ONLY,
                mutation: true
            }
        );
        assert_eq!(
            edge_access(&Method::POST, "/api/v1/auth/logout"),
            RouteAccess::Always {
                roles: RoleMask::ANY,
                mutation: true
            }
        );

        // The center management surface is Center-only (audit follow-up
        // F2): on an Edge console the routes are not registered, so the
        // authorization table treats the paths as public fallback paths —
        // they resolve to the static-asset 404, never to a handler.
        assert_eq!(
            edge_access(&Method::GET, "/api/v1/center/sites"),
            RouteAccess::Public
        );
        assert_eq!(
            edge_access(&Method::POST, "/api/v1/center/operations"),
            RouteAccess::Public
        );
        assert_eq!(
            center_access(&Method::GET, "/api/v1/center/sites"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ANY,
                mutation: false
            }
        );
        assert_eq!(
            center_access(&Method::POST, "/api/v1/center/bindings"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ADMINISTRATOR_ONLY,
                mutation: true
            }
        );
        assert_eq!(
            center_access(&Method::POST, "/api/v1/center/operations"),
            RouteAccess::GuardedOnly {
                roles: RoleMask::ADMINISTRATOR_OR_OPERATOR,
                mutation: true
            }
        );
    }

    #[test]
    fn constant_time_comparison_detects_any_difference() {
        let left = [0x5a_u8; 32];
        let mut right = [0x5a_u8; 32];
        assert!(constant_time_eq(&left, &right));
        right[31] ^= 1;
        assert!(!constant_time_eq(&left, &right));
        right[31] ^= 1;
        right[0] ^= 1;
        assert!(!constant_time_eq(&left, &right));
    }

    #[test]
    fn cookie_parsing_extracts_the_named_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_static("other=1; rutilus_session=abc123; keep=true"),
        );
        assert_eq!(cookie_value(&headers, SESSION_COOKIE_NAME), Some("abc123"));
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static("rutilus_session=abc123"));
        assert_eq!(cookie_value(&headers, SESSION_COOKIE_NAME), Some("abc123"));
        let headers = HeaderMap::new();
        assert_eq!(cookie_value(&headers, SESSION_COOKIE_NAME), None);
        let mut headers = HeaderMap::new();
        headers.insert(COOKIE, HeaderValue::from_static("other=1"));
        assert_eq!(cookie_value(&headers, SESSION_COOKIE_NAME), None);
    }

    #[test]
    fn session_cookie_is_http_only_same_site_and_optionally_secure() -> Result<(), Box<dyn Error>> {
        let cookie = session_cookie("token-value", OffsetDateTime::now_utc(), false);
        let value = cookie.to_str()?;
        assert!(value.starts_with("rutilus_session=token-value; Path=/"));
        assert!(value.contains("HttpOnly"));
        assert!(value.contains("SameSite=Strict"));
        assert!(value.contains("Max-Age="));
        assert!(!value.contains("Secure"));
        let secure = session_cookie("token-value", OffsetDateTime::now_utc(), true);
        assert!(secure.to_str()?.contains("Secure"));
        let cleared = clear_session_cookie();
        assert!(cleared.to_str()?.contains("Max-Age=0"));
        Ok(())
    }

    #[test]
    fn rate_limiter_enforces_per_username_and_per_ip_budgets() {
        let limiter = LoginRateLimiter::new();
        let now = Instant::now();

        for _ in 0..USERNAME_FAILURE_LIMIT {
            assert!(limiter.allows("admin", "192.0.2.10", now));
            limiter.record_failure("admin", "192.0.2.10", now);
        }
        assert!(
            !limiter.allows("admin", "192.0.2.10", now),
            "the username budget must exhaust"
        );
        assert!(
            limiter.allows("operator", "192.0.2.10", now),
            "another username must keep its own budget"
        );
        // The address budget is independent and larger: one address can
        // absorb failures from many usernames, so each iteration attacks
        // from a fresh username to isolate the address bound.
        for index in 0..(IP_FAILURE_LIMIT - USERNAME_FAILURE_LIMIT) {
            let username = format!("user-{index}");
            assert!(limiter.allows(&username, "192.0.2.10", now));
            limiter.record_failure(&username, "192.0.2.10", now);
        }
        assert!(
            !limiter.allows("user-last", "192.0.2.10", now),
            "the address budget must exhaust too"
        );
        assert!(
            limiter.allows("operator", "192.0.2.20", now),
            "another address must keep its own budget"
        );

        // The window slides: an attempt outside the window reopens.
        let later = now + RATE_WINDOW + StdDuration::from_secs(1);
        assert!(limiter.allows("admin", "192.0.2.10", later));
    }

    #[test]
    fn rate_limiter_bounds_attacker_controlled_username_keys() {
        let limiter = LoginRateLimiter::new();
        let now = Instant::now();
        let prefix = "a".repeat(RATE_LIMIT_USERNAME_CHARS);

        // A presented username beyond the principal-name bound is invalid,
        // but it must still consume the per-username budget under the
        // bounded key: every form sharing the 64-character prefix — long
        // invalid variants and the exact valid-length prefix — exhausts one
        // shared bucket, and the map never stores the full wire string.
        for _ in 0..USERNAME_FAILURE_LIMIT {
            assert!(limiter.allows(&format!("{prefix}payload"), "192.0.2.30", now));
            limiter.record_failure(&format!("{prefix}payload"), "192.0.2.30", now);
        }
        assert!(
            !limiter.allows(&prefix, "192.0.2.30", now),
            "the long invalid forms must share the prefix's bucket"
        );
        assert!(
            !limiter.allows(&format!("{prefix}other"), "192.0.2.30", now),
            "a different long invalid form must share the same bounded bucket"
        );
        assert!(
            limiter.allows("bbbb", "192.0.2.30", now),
            "another prefix keeps its own bucket"
        );

        // A long value shorter than the bound passes through unmodified —
        // the borrow path must not truncate legitimate names.
        assert_eq!(bounded_username_key("admin"), "admin");
        let long = format!("{prefix}tail");
        assert_eq!(
            bounded_username_key(&long),
            prefix,
            "the bounded key is the first 64 characters"
        );
        assert_eq!(bounded_username_key(&long).len(), RATE_LIMIT_USERNAME_CHARS);
    }

    #[test]
    fn rate_limiter_prunes_expired_buckets_to_a_bounded_size() -> Result<(), Box<dyn Error>> {
        // The N3 fix: a dormant bucket (all entries left the window) must
        // be reclaimed by the periodic sweep even when it is never
        // revisited. Fill the username map with a full threshold of
        // buckets, slide the window, then fill another threshold: the last
        // insert trips the sweep, which must reclaim the expired fill and
        // land the map back at exactly the fresh fill's size — the bound
        // is "one window's working set plus the threshold", never an
        // all-time accumulation of distinct keys.
        let limiter = LoginRateLimiter::new();
        let now = Instant::now();
        for index in 0..BUCKET_PRUNE_THRESHOLD {
            limiter.record_failure(&format!("user-{index}"), "192.0.2.10", now);
        }
        let after = now + RATE_WINDOW + StdDuration::from_secs(1);
        for index in BUCKET_PRUNE_THRESHOLD..(2 * BUCKET_PRUNE_THRESHOLD) {
            limiter.record_failure(&format!("user-{index}"), "192.0.2.10", after);
        }

        let buckets = limiter
            .by_username
            .lock()
            .map_err(|_| "the rate limiter mutex must not be poisoned")?;
        assert_eq!(
            buckets.buckets.len(),
            BUCKET_PRUNE_THRESHOLD,
            "the sweep must reclaim the expired fill, leaving only the fresh one"
        );
        assert!(
            !buckets.buckets.contains_key("user-0"),
            "a bucket from the expired fill must be gone"
        );
        assert!(
            buckets
                .buckets
                .contains_key(&format!("user-{BUCKET_PRUNE_THRESHOLD}")),
            "a bucket from the fresh fill must survive"
        );
        assert_eq!(
            buckets.inserts_since_prune, 0,
            "the sweep must reset the insert counter so the bound recurs"
        );
        // The per-address map saw one address throughout: it must stay at
        // one bucket — the sweep never touches an alive bucket.
        let ip_buckets = limiter
            .by_ip
            .lock()
            .map_err(|_| "the rate limiter mutex must not be poisoned")?;
        assert_eq!(ip_buckets.buckets.len(), 1);
        Ok(())
    }

    #[test]
    fn rate_limiter_prune_spares_active_buckets() -> Result<(), Box<dyn Error>> {
        // The sweep must reclaim only fully-expired buckets: a bucket
        // holding a fresh budget keeps it across the sweep, and the limit
        // verdicts around the sweep are unchanged.
        let limiter = LoginRateLimiter::new();
        let now = Instant::now();
        // Fill the map to one insert below the sweep threshold with stale
        // buckets, then let the window pass.
        for index in 0..(BUCKET_PRUNE_THRESHOLD - 1) {
            limiter.record_failure(&format!("stale-{index}"), "192.0.2.20", now);
        }
        let after = now + RATE_WINDOW + StdDuration::from_secs(1);
        // The first fresh insert trips the sweep while "admin" goes on to
        // hold a full budget at the sweep time.
        for _ in 0..USERNAME_FAILURE_LIMIT {
            limiter.record_failure("admin", "192.0.2.10", after);
        }

        let buckets = limiter
            .by_username
            .lock()
            .map_err(|_| "the rate limiter mutex must not be poisoned")?;
        assert_eq!(
            buckets.buckets.len(),
            1,
            "only the fresh admin bucket may survive the sweep"
        );
        drop(buckets);
        assert!(
            !limiter.allows("admin", "192.0.2.10", after),
            "the swept survivor must keep its exhausted budget"
        );
        assert!(
            limiter.allows("another", "192.0.2.10", after),
            "a fresh username must still open a budget after the sweep"
        );
        assert!(
            limiter.allows("admin2", "192.0.2.99", after),
            "a fresh address must still open a budget after the sweep"
        );
        Ok(())
    }

    #[test]
    fn rate_limiter_prune_reclaims_buckets_created_by_allows_only() -> Result<(), Box<dyn Error>> {
        // `allows` runs before verification and creates a bucket even for
        // attempts that never record a failure, so an attacker cycling
        // distinct usernames grows the map without ever failing a login.
        // Empty buckets carry no budget, so the sweep must reclaim them
        // too — the map returns to empty after each full threshold cycle.
        let limiter = LoginRateLimiter::new();
        let now = Instant::now();
        for index in 0..BUCKET_PRUNE_THRESHOLD {
            limiter.allows(&format!("user-{index}"), "192.0.2.40", now);
        }
        let after = now + RATE_WINDOW + StdDuration::from_secs(1);
        for index in BUCKET_PRUNE_THRESHOLD..(2 * BUCKET_PRUNE_THRESHOLD) {
            limiter.allows(&format!("user-{index}"), "192.0.2.40", after);
        }
        let buckets = limiter
            .by_username
            .lock()
            .map_err(|_| "the rate limiter mutex must not be poisoned")?;
        assert!(
            buckets.buckets.is_empty(),
            "buckets that never recorded a failure must be reclaimed by the sweep"
        );
        assert_eq!(buckets.inserts_since_prune, 0);
        Ok(())
    }

    #[test]
    fn prune_expired_reclaims_only_buckets_whose_entries_left_the_window() {
        // Every entry is recorded at or after `start` and swept at `soon`
        // (one second later) or `later` (one second past the window), so
        // all ages are built from additions only.
        let start = Instant::now();
        let soon = start + StdDuration::from_secs(1);
        let later = start + RATE_WINDOW + StdDuration::from_secs(1);
        let expired = start;
        // The straddling bucket's fresh failure, recorded one second
        // inside the window at sweep time.
        let fresh = start + RATE_WINDOW;

        // The empty table sweeps to an empty table.
        let mut buckets = HashMap::new();
        LoginRateLimiter::prune_expired(&mut buckets, soon);
        assert!(buckets.is_empty());

        // A single fresh bucket survives (swept one second after the
        // entry), and a single expired bucket is reclaimed (swept one
        // second past the window).
        let mut buckets = HashMap::new();
        buckets.insert("alive".to_owned(), VecDeque::from([expired]));
        LoginRateLimiter::prune_expired(&mut buckets, soon);
        assert!(buckets.contains_key("alive"));
        let mut buckets = HashMap::new();
        buckets.insert("dead".to_owned(), VecDeque::from([expired]));
        LoginRateLimiter::prune_expired(&mut buckets, later);
        assert!(buckets.is_empty());

        // A bucket straddling the window boundary — an expired failure
        // followed by a fresh one — is popped to its fresh tail, exactly
        // as the access path would: the fresh failure still counts toward
        // the budget instead of being wiped with the expired one.
        let mut buckets = HashMap::new();
        buckets.insert("straddling".to_owned(), VecDeque::from([expired, fresh]));
        LoginRateLimiter::prune_expired(&mut buckets, later);
        assert_eq!(
            buckets.get("straddling").map(VecDeque::len),
            Some(1),
            "the fresh entry must keep the straddling bucket"
        );
        assert!(
            buckets
                .get("straddling")
                .is_some_and(|failures| failures.contains(&fresh))
        );

        // An all-expired table returns to empty.
        let mut buckets = HashMap::new();
        for index in 0..8 {
            buckets.insert(format!("dead-{index}"), VecDeque::from([expired]));
        }
        LoginRateLimiter::prune_expired(&mut buckets, later);
        assert!(buckets.is_empty());
    }

    #[test]
    fn dummy_credential_is_a_fixed_constant_in_the_argon2id_format() -> Result<(), Box<dyn Error>> {
        // The MINOR-1 dummy credential is pinned bytes — the same salt and
        // hash on every call, typed to the `argon2id-1` lengths — so the
        // unknown-username branch's dummy verification runs under exactly
        // the parameters of the real password path and touches no real
        // user's data. (The behavioral half of the mitigation — that the
        // unknown-username, disabled-account, and missing-credential
        // branches each actually perform their verification — is asserted
        // at the route level in web/src/lib.rs, where the mock services
        // count `verify_password` calls.)
        let dummy = Argon2IdHash::from_parts(&DUMMY_SALT, &DUMMY_HASH)
            .map_err(|_| "the pinned dummy salt and hash lengths are invalid")?;
        assert_eq!(dummy.salt(), &DUMMY_SALT);
        assert_eq!(dummy.hash(), &DUMMY_HASH);
        assert_eq!(dummy.salt().len(), ARGON2ID_SALT_LENGTH);
        assert_eq!(dummy.hash().len(), ARGON2ID_HASH_LENGTH);
        Ok(())
    }

    #[test]
    fn password_policy_counts_characters_not_bytes() {
        // The floor matches the console form's check (`chars().count() < 12`):
        // exactly 12 characters satisfy it, shorter values are refused, and
        // the count is Unicode scalar values — a 24-byte string of six
        // four-byte characters is still six characters, and twelve CJK
        // characters satisfy the floor at 36 bytes.
        let twelve_ascii: SecretString = "123456789012".to_owned().into();
        assert!(password_satisfies_policy(&twelve_ascii));
        let eleven_ascii: SecretString = "12345678901".to_owned().into();
        assert!(!password_satisfies_policy(&eleven_ascii));
        let empty: SecretString = String::new().into();
        assert!(!password_satisfies_policy(&empty));
        let six_wide: SecretString = "🌮🌮🌮🌮🌮🌮".to_owned().into();
        assert_eq!(six_wide.expose_secret().len(), 24);
        assert!(!password_satisfies_policy(&six_wide));
        let twelve_cjk: SecretString = "一二三四五六七八九十甲乙".to_owned().into();
        assert_eq!(twelve_cjk.expose_secret().len(), 36);
        assert!(password_satisfies_policy(&twelve_cjk));
    }

    #[test]
    fn auth_gate_starts_open_and_arms_guarded() {
        let gate = AuthGate::open();
        assert!(!gate.is_guarded());
        let policy = AuthPolicy::PendingBootstrap(gate.clone());
        assert!(!policy.is_guarded());
        gate.arm();
        assert!(policy.is_guarded());
        assert!(!AuthPolicy::Open.is_guarded());
        assert!(AuthPolicy::Guarded.is_guarded());
    }
}
