use std::error::Error;

use rutilus_entity::{
    bootstrap_code, password_credential, principal, role_assignment, session, totp_authenticator,
};
use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection,
    EntityTrait, PaginatorTrait, QueryFilter, Set,
};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use time::OffsetDateTime;
use uuid::Uuid;

const PRODUCT_USER_TABLES: [&str; 6] = [
    "principals",
    "password_credentials",
    "totp_authenticators",
    "sessions",
    "role_assignments",
    "bootstrap_codes",
];

const PRODUCT_USERS_MIGRATION: &str = "m20260807_000005_product_users";

#[tokio::test]
async fn product_users_migration_creates_and_drops_the_six_tables() -> Result<(), Box<dyn Error>> {
    let database = connect().await?;

    Migrator::up(&database, None).await?;
    Migrator::up(&database, None).await?;
    assert_tables(&database, true).await?;

    Migrator::down(&database, None).await?;
    assert_tables(&database, false).await?;

    Ok(())
}

// Every §16 table constraint is spelled out as its own insert-and-assert so a
// failure pinpoints the exact rule (name uniqueness and normalization, state
// and role vocabularies, the argon2id-1 format, the RFC 6238 shape, token
// hash uniqueness, both foreign key behaviors), which exceeds the pedantic
// line budget; the domain and persistence crates allow the same lint on their
// exhaustive assertion tests.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn product_users_constraints_and_cascades_hold() -> Result<(), Box<dyn Error>> {
    let database = connect().await?;
    Migrator::up(&database, None).await?;
    let now = OffsetDateTime::now_utc();

    // A principal round-trips with its normalized name, and the schema pins
    // the §16.1 state and normalization rules.
    let principal_id = Uuid::now_v7();
    principal::ActiveModel {
        id: Set(principal_id),
        name: Set(String::from("admin")),
        state: Set(String::from("enabled")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&database)
    .await?;
    let stored = principal::Entity::find_by_id(principal_id)
        .one(&database)
        .await?
        .ok_or("inserted principal is missing")?;
    assert_eq!(stored.name, "admin");
    assert_eq!(stored.state, "enabled");

    // The unique index is the atomic duplicate refusal; the lowercase CHECK
    // pins the domain normalization, so a non-normalized name is refused even
    // when the domain never would have produced one.
    let duplicate = principal::ActiveModel {
        id: Set(Uuid::now_v7()),
        name: Set(String::from("admin")),
        state: Set(String::from("enabled")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        duplicate.is_err(),
        "the same principal name must be refused"
    );
    let unnormalized = principal::ActiveModel {
        id: Set(Uuid::now_v7()),
        name: Set(String::from("Admin")),
        state: Set(String::from("enabled")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        unnormalized.is_err(),
        "a non-lowercase principal name must be refused"
    );
    let unknown_state = principal::ActiveModel {
        id: Set(Uuid::now_v7()),
        name: Set(String::from("operator")),
        state: Set(String::from("banned")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        unknown_state.is_err(),
        "an unknown principal state must be refused"
    );

    // The password credential pins the argon2id-1 format and binds the
    // principal as its primary key.
    password_credential::ActiveModel {
        principal_id: Set(principal_id),
        hash_format: Set(String::from("argon2id-1")),
        salt: Set(vec![0x11; 16]),
        hash: Set(vec![0x22; 32]),
        changed_at: Set(now),
    }
    .insert(&database)
    .await?;
    let wrong_format = password_credential::ActiveModel {
        principal_id: Set(principal_id),
        hash_format: Set(String::from("bcrypt")),
        salt: Set(vec![0x11; 16]),
        hash: Set(vec![0x22; 32]),
        changed_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        wrong_format.is_err(),
        "an unknown hash format must be refused"
    );

    // The TOTP authenticator pins the RFC 6238 shape: sha1, 6 digits, 30
    // seconds, provisioning/active states.
    let totp_id = Uuid::now_v7();
    totp_authenticator::ActiveModel {
        id: Set(totp_id),
        principal_id: Set(principal_id),
        secret: Set(vec![0x33; 20]),
        state: Set(String::from("provisioning")),
        algorithm: Set(String::from("sha1")),
        digits: Set(6),
        period: Set(30),
        created_at: Set(now),
        activated_at: Set(None),
        last_used_step: Set(None),
    }
    .insert(&database)
    .await?;
    for (column, value) in [
        ("state", "lost"),
        ("algorithm", "sha512"),
        ("digits", "8"),
        ("period", "60"),
    ] {
        let refused = totp_authenticator::ActiveModel {
            id: Set(Uuid::now_v7()),
            principal_id: Set(principal_id),
            secret: Set(vec![0x33; 20]),
            state: Set(String::from(if column == "state" {
                value
            } else {
                "provisioning"
            })),
            algorithm: Set(String::from(if column == "algorithm" {
                value
            } else {
                "sha1"
            })),
            digits: Set(if column == "digits" {
                value.parse()?
            } else {
                6
            }),
            period: Set(if column == "period" {
                value.parse()?
            } else {
                30
            }),
            created_at: Set(now),
            activated_at: Set(None),
            last_used_step: Set(None),
        }
        .insert(&database)
        .await;
        assert!(
            refused.is_err(),
            "a TOTP {column} of {value} must be refused"
        );
    }

    // A session stores only hashes; the token hash is unique because it is
    // the lookup key of every authenticated request.
    let session_id = Uuid::now_v7();
    let token_hash = vec![0x44; 32];
    session::ActiveModel {
        id: Set(session_id),
        principal_id: Set(principal_id),
        token_hash: Set(token_hash.clone()),
        csrf_hash: Set(vec![0x55; 32]),
        created_at: Set(now),
        last_used_at: Set(now),
        expires_at: Set(now + time::Duration::hours(8)),
        revoked_at: Set(None),
    }
    .insert(&database)
    .await?;
    let duplicate_token = session::ActiveModel {
        id: Set(Uuid::now_v7()),
        principal_id: Set(principal_id),
        token_hash: Set(token_hash),
        csrf_hash: Set(vec![0x55; 32]),
        created_at: Set(now),
        last_used_at: Set(now),
        expires_at: Set(now + time::Duration::hours(8)),
        revoked_at: Set(None),
    }
    .insert(&database)
    .await;
    assert!(
        duplicate_token.is_err(),
        "the same session token hash must be refused"
    );

    // The role assignment pins the three §16.1 roles and records the
    // assigner; the viewer role round-trips.
    let assigner_id = Uuid::now_v7();
    principal::ActiveModel {
        id: Set(assigner_id),
        name: Set(String::from("root")),
        state: Set(String::from("enabled")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&database)
    .await?;
    role_assignment::ActiveModel {
        principal_id: Set(principal_id),
        role: Set(String::from("administrator")),
        assigned_by: Set(Some(assigner_id)),
        assigned_at: Set(now),
        site_id: Set(None),
    }
    .insert(&database)
    .await?;
    let unknown_role = role_assignment::ActiveModel {
        principal_id: Set(Uuid::now_v7()),
        role: Set(String::from("superuser")),
        assigned_by: Set(None),
        assigned_at: Set(now),
        site_id: Set(None),
    }
    .insert(&database)
    .await;
    assert!(unknown_role.is_err(), "an unknown role must be refused");

    // A bootstrap code stores only its hash; the used_by reference cascades
    // with the principal.
    let code_id = Uuid::now_v7();
    bootstrap_code::ActiveModel {
        id: Set(code_id),
        code_hash: Set(vec![0x66; 32]),
        created_at: Set(now),
        used_at: Set(None),
        used_by: Set(Some(principal_id)),
    }
    .insert(&database)
    .await?;

    // Deleting the assigner preserves the assignment fact: SET NULL.
    principal::Entity::delete_by_id(assigner_id)
        .exec(&database)
        .await?;
    let assignment = role_assignment::Entity::find_by_id(principal_id)
        .one(&database)
        .await?
        .ok_or("the assignment must survive its assigner")?;
    assert_eq!(assignment.assigned_by, None, "SET NULL on assigner delete");

    // Deleting the principal cascades every credential, authenticator,
    // session, and code row with it.
    principal::Entity::delete_by_id(principal_id)
        .exec(&database)
        .await?;
    assert_eq!(
        password_credential::Entity::find()
            .filter(password_credential::Column::PrincipalId.eq(principal_id))
            .count(&database)
            .await?,
        0,
        "deleting a principal must cascade its password credential"
    );
    assert_eq!(
        totp_authenticator::Entity::find()
            .filter(totp_authenticator::Column::PrincipalId.eq(principal_id))
            .count(&database)
            .await?,
        0,
        "deleting a principal must cascade its TOTP authenticators"
    );
    assert_eq!(
        session::Entity::find()
            .filter(session::Column::PrincipalId.eq(principal_id))
            .count(&database)
            .await?,
        0,
        "deleting a principal must cascade its sessions"
    );
    assert_eq!(
        role_assignment::Entity::find()
            .filter(role_assignment::Column::PrincipalId.eq(principal_id))
            .count(&database)
            .await?,
        0,
        "deleting a principal must cascade its role assignment"
    );
    assert_eq!(
        bootstrap_code::Entity::find()
            .filter(bootstrap_code::Column::UsedBy.eq(principal_id))
            .count(&database)
            .await?,
        0,
        "deleting a principal must cascade its bootstrap codes"
    );

    Ok(())
}

#[tokio::test]
async fn audit_rebuild_preserves_rows_and_pins_the_actor_principal_pair()
-> Result<(), Box<dyn Error>> {
    let database = connect().await?;

    // Apply only the pre-rebuild migrations: the audit table still has the
    // original actor vocabulary, which the legacy row proves.
    Migrator::up(&database, Some(4)).await?;
    let legacy_id = Uuid::now_v7();
    let operation_id = Uuid::now_v7();
    // The legacy row is written with the pre-0.6 column list, exactly as the
    // original migration's entity would have written it.
    insert_legacy_audit_row(&database, legacy_id, operation_id).await?;
    let user_without_principal =
        insert_legacy_audit_row(&database, Uuid::now_v7(), operation_id).await;
    assert!(
        user_without_principal.is_err(),
        "the pre-rebuild schema must not know the user actor"
    );

    // The rebuild preserves every legacy row and widens the vocabulary.
    Migrator::up(&database, None).await?;
    let stored = rutilus_entity::audit_event::Entity::find_by_id(legacy_id)
        .one(&database)
        .await?
        .ok_or("the legacy audit row must survive the rebuild")?;
    assert_eq!(stored.actor, "system");
    assert_eq!(stored.actor_principal_id, None);

    // A user actor must pair with its principal id, and only a user actor
    // may carry one. Each row is its own audited operation so the
    // (operation_id, sequence) uniqueness does not conflate the inserts.
    let principal_uuid = Uuid::now_v7();
    let user_row = insert_audit_row(
        &database,
        Uuid::now_v7(),
        Uuid::now_v7(),
        "user",
        Some(principal_uuid),
        now(),
    )
    .await?;
    assert_eq!(user_row.actor_principal_id, Some(principal_uuid));
    let user_without_principal = insert_audit_row(
        &database,
        Uuid::now_v7(),
        Uuid::now_v7(),
        "user",
        None,
        now(),
    )
    .await;
    assert!(
        user_without_principal.is_err(),
        "a user actor must name the acting principal"
    );
    let system_with_principal = insert_audit_row(
        &database,
        Uuid::now_v7(),
        Uuid::now_v7(),
        "system",
        Some(principal_uuid),
        now(),
    )
    .await;
    assert!(
        system_with_principal.is_err(),
        "a non-user actor must not carry a principal identity"
    );

    // Roll back through the product-users migration (parallel slices may have
    // registered later migrations, so the step count is derived from the
    // registration order instead of assumed). The user-actor row this test
    // wrote is removed first: the restored pre-0.6 schema cannot represent
    // it, and the down refuses such rows rather than silently dropping them
    // (the documented restore contract).
    rutilus_entity::audit_event::Entity::delete_by_id(user_row.id)
        .exec(&database)
        .await?;
    let steps = rollback_steps_to(PRODUCT_USERS_MIGRATION)?;
    Migrator::down(&database, Some(steps)).await?;

    // The rollback restores the pre-0.6 shape: the legacy row survives with
    // its actor vocabulary, and the user actor is refused again. The row is
    // read through raw SQL because the 0.6 entity model names the column the
    // restored table no longer has.
    let count = audit_row_count(&database).await?;
    assert_eq!(count, 1, "the legacy audit row must survive the rollback");
    let user_after_rollback =
        insert_legacy_audit_row(&database, Uuid::now_v7(), operation_id).await;
    assert!(
        user_after_rollback.is_err(),
        "the rolled-back schema must not know the user actor"
    );
    assert_tables(&database, false).await?;

    Ok(())
}

/// The number of registered migrations to roll back so the named migration
/// is included in the rollback: everything registered after it, plus itself.
fn rollback_steps_to(name: &str) -> Result<u32, Box<dyn Error>> {
    let migrations = Migrator::migrations();
    let position = migrations
        .iter()
        .position(|migration| migration.name() == name)
        .ok_or("product users migration is not registered")?;
    Ok(u32::try_from(migrations.len() - position)?)
}

async fn audit_row_count(database: &DatabaseConnection) -> Result<i64, Box<dyn Error>> {
    use sea_orm::sea_query::{Expr, Query};
    let statement = Query::select()
        .expr(Expr::cust("COUNT(*) AS row_count"))
        .from(sea_orm::sea_query::Alias::new("audit_events"))
        .to_owned();
    let row = database
        .query_one(&statement)
        .await?
        .ok_or("audit_events must exist after the rollback")?;
    Ok(row.try_get_by_index(0)?)
}

/// Writes one audit row with the pre-0.6 column list through raw SQL, with
/// the same storage shapes the original entity used (uuid blobs, text
/// datetimes) so the row survives the rebuild byte for byte.
async fn insert_legacy_audit_row(
    database: &DatabaseConnection,
    id: Uuid,
    operation_id: Uuid,
) -> Result<(), sea_orm::DbErr> {
    database
        .execute_unprepared(&format!(
            "INSERT INTO audit_events \
             (id, operation_id, event_sequence, actor, origin, \
              target_kind, target_endpoint_id, target_endpoint_address, parameter_kind, \
              credential_id, trust_mode, row_count, permission, action, redfish_operation, \
              outcome, progress, failure, verification, occurred_at) \
             VALUES (X'{id}', X'{operation_id}', 1, 'system', 'standalone', \
              'endpoint-address', NULL, 'https://192.0.2.90', 'endpoint-enrollment', \
              X'{credential_id}', 'pinned-certificate', NULL, 'manage-endpoints', \
              'enroll-endpoint', 'probe-core-capabilities', 'started', NULL, NULL, NULL, \
              '2026-08-07 12:00:00')",
            id = id.simple(),
            operation_id = operation_id.simple(),
            credential_id = Uuid::now_v7().simple(),
        ))
        .await
        .map(|_| ())
}

async fn insert_audit_row(
    database: &DatabaseConnection,
    id: Uuid,
    operation_id: Uuid,
    actor: &str,
    actor_principal_id: Option<Uuid>,
    occurred_at: OffsetDateTime,
) -> Result<rutilus_entity::audit_event::Model, sea_orm::DbErr> {
    rutilus_entity::audit_event::ActiveModel {
        id: Set(id),
        operation_id: Set(operation_id),
        event_sequence: Set(1),
        actor: Set(actor.to_owned()),
        actor_principal_id: Set(actor_principal_id),
        origin: Set(String::from("standalone")),
        target_kind: Set(String::from("endpoint-address")),
        target_endpoint_id: Set(None),
        target_endpoint_address: Set(Some(String::from("https://192.0.2.90"))),
        parameter_kind: Set(String::from("endpoint-enrollment")),
        credential_id: Set(Some(Uuid::now_v7())),
        trust_mode: Set(Some(String::from("pinned-certificate"))),
        row_count: Set(None),
        permission: Set(String::from("manage-endpoints")),
        action: Set(String::from("enroll-endpoint")),
        redfish_operation: Set(String::from("probe-core-capabilities")),
        outcome: Set(String::from("started")),
        progress: Set(None),
        failure: Set(None),
        verification: Set(None),
        occurred_at: Set(occurred_at),
    }
    .insert(database)
    .await
}

async fn assert_tables(
    database: &DatabaseConnection,
    should_exist: bool,
) -> Result<(), Box<dyn Error>> {
    let schema = SchemaManager::new(database);
    for table in PRODUCT_USER_TABLES {
        assert_eq!(
            schema.has_table(table).await?,
            should_exist,
            "table {table}"
        );
    }
    Ok(())
}

async fn connect() -> Result<DatabaseConnection, Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    Ok(Database::connect(options).await?)
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}
