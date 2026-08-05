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

#[cfg(test)]
mod tests {
    use super::{
        AuditEventId, AuditOperationId, CredentialId, CredentialVersionId, EndpointId, ResourceId,
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
}
