use std::{fmt, str::FromStr};

use uuid::Uuid;

macro_rules! define_id {
    ($name:ident, $documentation:literal) => {
        #[doc = $documentation]
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a time-ordered UUID version 7 identifier.
            #[must_use]
            pub fn generate() -> Self {
                Self(Uuid::now_v7())
            }

            /// Wraps an existing UUID without changing its value.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Returns the underlying UUID value.
            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value).map(Self)
            }
        }
    };
}

define_id!(
    EndpointId,
    "The stable identity of one Redfish service entry point."
);
define_id!(
    CredentialId,
    "The stable identity of a reusable BMC credential."
);
define_id!(
    CredentialVersionId,
    "The stable identity of one immutable encrypted credential version."
);
define_id!(
    ResourceId,
    "The stable local identity of one discovered Redfish resource."
);
define_id!(
    AuditEventId,
    "The immutable identity of one append-only audit event."
);
define_id!(
    AuditOperationId,
    "The correlation identity shared by one audited operation's events."
);
define_id!(
    OperationId,
    "The stable identity of one persisted product operation (§13.1).\n\n\
     This is the identity of the operation record driven by the §13.2 state\n\
     machine. It is distinct from `AuditOperationId`: an `AuditOperationId`\n\
     correlates the append-only audit events that record the operation\n\
     lifecycle for accountability, while an `OperationId` names the operation\n\
     record itself. The two identifiers never interchange."
);
define_id!(
    TargetId,
    "The stable identity of one operation target (§13.1).\n\n\
     A target is one logical object (for example, one resource or one\n\
     endpoint instance) that an operation acts on; an `OperationTarget`\n\
     binds it to the endpoint that actually receives the Redfish request."
);
define_id!(
    ArtifactId,
    "The stable identity of one persisted firmware artifact (§9.3, §14.3).\n\n\
     The identity of the `artifacts` row that drives the §14.3 firmware\n\
     upload flow. The artifact file on disk is named after this identity by\n\
     the persistence `artifact_file_path` contract, so the row and the bytes\n\
     always link deterministically."
);
define_id!(
    BatchOperationId,
    "The stable identity of one persisted batch parent (§13.7).\n\n\
     A batch submission creates one `batch_operations` parent row and one\n\
     ordinary single-target child `Operation` per submitted endpoint; the\n\
     batch id names the parent that ties the children together, while the\n\
     children keep their own `OperationId` lifecycle records."
);
define_id!(
    PrincipalId,
    "The stable identity of one product user principal (§16)."
);
define_id!(
    SessionId,
    "The stable identity of one signed-in product session (§16.2).\n\n\
     The session id names the `sessions` row; the token presented by the\n\
     client is a separate random value whose SHA-256 hash is stored in that\n\
     row, so the id never leaves the product as a bearer secret."
);
define_id!(
    TotpAuthenticatorId,
    "The stable identity of one optional TOTP authenticator (§16.2)."
);
define_id!(
    BootstrapCodeId,
    "The stable identity of one one-time bootstrap code (§16.2).\n\n\
     First startup generates a bootstrap code so the initial administrator\n\
     can claim the product; the code hash is stored, never the code itself."
);
define_id!(
    InstanceId,
    "The stable identity of one registered deployment instance (design D6).\n\n\
     On the center side an instance row names one registered site; on the\n\
     site side the row names the site's own identity — a single-center\n\
     binding means exactly one row."
);
define_id!(
    CenterBindingId,
    "The stable identity of one site-to-center binding record (design D2, D6)."
);
define_id!(
    OutboxEntryId,
    "The stable identity of one envelope queued for delivery to the center\n\
     (§17, D4)."
);
define_id!(
    InboxEntryId,
    "The stable identity of one envelope received from the center (§17, D4)."
);
define_id!(
    SyncCursorId,
    "The stable identity of one per-instance sync-stream cursor (§17)."
);

#[cfg(test)]
mod tests {
    use super::{
        ArtifactId, AuditEventId, AuditOperationId, BatchOperationId, BootstrapCodeId,
        CenterBindingId, CredentialId, CredentialVersionId, EndpointId, InboxEntryId, InstanceId,
        OperationId, OutboxEntryId, PrincipalId, ResourceId, SessionId, SyncCursorId, TargetId,
        TotpAuthenticatorId,
    };

    #[test]
    fn generated_identifiers_are_unique_uuid_v7_values() {
        let first = EndpointId::generate();
        let second = EndpointId::generate();

        assert_ne!(first, second);
        assert_eq!(first.into_uuid().get_version_num(), 7);
        assert_eq!(second.into_uuid().get_version_num(), 7);
    }

    #[test]
    fn endpoint_identifier_round_trips_through_text() -> Result<(), uuid::Error> {
        let original = EndpointId::generate();
        let parsed = original.to_string().parse::<EndpointId>()?;

        assert_eq!(parsed, original);
        Ok(())
    }

    #[test]
    fn credential_identifiers_round_trip_through_text() -> Result<(), uuid::Error> {
        let credential = CredentialId::generate();
        let version = CredentialVersionId::generate();

        assert_eq!(credential.to_string().parse::<CredentialId>()?, credential);
        assert_eq!(version.to_string().parse::<CredentialVersionId>()?, version);
        Ok(())
    }

    #[test]
    fn resource_identifier_round_trips_through_text() -> Result<(), uuid::Error> {
        let resource = ResourceId::generate();

        assert_eq!(resource.to_string().parse::<ResourceId>()?, resource);
        Ok(())
    }

    #[test]
    fn audit_identifiers_round_trip_through_text() -> Result<(), uuid::Error> {
        let event = AuditEventId::generate();
        let operation = AuditOperationId::generate();

        assert_eq!(event.to_string().parse::<AuditEventId>()?, event);
        assert_eq!(
            operation.to_string().parse::<AuditOperationId>()?,
            operation
        );
        Ok(())
    }

    #[test]
    fn operation_and_target_identifiers_are_uuid_v7_and_round_trip() -> Result<(), uuid::Error> {
        let operation = OperationId::generate();
        let target = TargetId::generate();

        assert_eq!(operation.into_uuid().get_version_num(), 7);
        assert_eq!(target.into_uuid().get_version_num(), 7);
        assert_eq!(operation.to_string().parse::<OperationId>()?, operation);
        assert_eq!(target.to_string().parse::<TargetId>()?, target);
        Ok(())
    }

    #[test]
    fn artifact_identifier_is_uuid_v7_and_round_trips() -> Result<(), uuid::Error> {
        let artifact = ArtifactId::generate();

        assert_eq!(artifact.into_uuid().get_version_num(), 7);
        assert_eq!(artifact.to_string().parse::<ArtifactId>()?, artifact);
        Ok(())
    }

    #[test]
    fn batch_operation_identifier_is_uuid_v7_and_round_trips() -> Result<(), uuid::Error> {
        let batch = BatchOperationId::generate();

        assert_eq!(batch.into_uuid().get_version_num(), 7);
        assert_eq!(batch.to_string().parse::<BatchOperationId>()?, batch);
        Ok(())
    }

    #[test]
    fn product_user_identifiers_are_uuid_v7_and_round_trip() -> Result<(), uuid::Error> {
        let principal = PrincipalId::generate();
        assert_eq!(principal.into_uuid().get_version_num(), 7);
        assert_eq!(principal.to_string().parse::<PrincipalId>()?, principal);

        let session = SessionId::generate();
        assert_eq!(session.into_uuid().get_version_num(), 7);
        assert_eq!(session.to_string().parse::<SessionId>()?, session);

        let authenticator = TotpAuthenticatorId::generate();
        assert_eq!(authenticator.into_uuid().get_version_num(), 7);
        assert_eq!(
            authenticator.to_string().parse::<TotpAuthenticatorId>()?,
            authenticator
        );

        let bootstrap = BootstrapCodeId::generate();
        assert_eq!(bootstrap.into_uuid().get_version_num(), 7);
        assert_eq!(bootstrap.to_string().parse::<BootstrapCodeId>()?, bootstrap);
        Ok(())
    }

    #[test]
    fn center_shape_identifiers_are_uuid_v7_and_round_trip() -> Result<(), uuid::Error> {
        let instance = InstanceId::generate();
        let binding = CenterBindingId::generate();
        let outbox = OutboxEntryId::generate();
        let inbox = InboxEntryId::generate();
        let cursor = SyncCursorId::generate();

        assert_eq!(instance.into_uuid().get_version_num(), 7);
        assert_eq!(binding.into_uuid().get_version_num(), 7);
        assert_eq!(outbox.into_uuid().get_version_num(), 7);
        assert_eq!(inbox.into_uuid().get_version_num(), 7);
        assert_eq!(cursor.into_uuid().get_version_num(), 7);
        assert_eq!(instance.to_string().parse::<InstanceId>()?, instance);
        assert_eq!(binding.to_string().parse::<CenterBindingId>()?, binding);
        assert_eq!(outbox.to_string().parse::<OutboxEntryId>()?, outbox);
        assert_eq!(inbox.to_string().parse::<InboxEntryId>()?, inbox);
        assert_eq!(cursor.to_string().parse::<SyncCursorId>()?, cursor);
        Ok(())
    }
}
