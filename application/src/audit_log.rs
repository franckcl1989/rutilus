use std::error::Error;

use rutilus_domain::{
    AuditEvent, AuditEventError, AuditOperationContextError, AuditParameterSummaryError,
    AuditSequenceError,
};
use thiserror::Error;

use crate::BoundaryFuture;

/// Appends immutable audit facts through an application-owned boundary.
///
/// The boundary intentionally exposes no update or delete operation.
pub trait AuditEventWriter: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn append_audit_event<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;
}

impl<Writer> AuditEventWriter for &Writer
where
    Writer: AuditEventWriter + ?Sized,
{
    type Error = Writer::Error;

    fn append_audit_event<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Writer::append_audit_event(*self, event)
    }
}

/// A typed audit fact could not be constructed or durably appended.
#[derive(Debug, Error)]
pub enum AuditRecordError<AuditError>
where
    AuditError: Error + 'static,
{
    #[error("audit operation parameters are invalid: {0}")]
    Parameters(#[source] AuditParameterSummaryError),
    #[error("audit operation context is invalid: {0}")]
    Context(#[source] AuditOperationContextError),
    #[error("audit sequence cannot advance: {0}")]
    Sequence(#[source] AuditSequenceError),
    #[error("audit event is inconsistent: {0}")]
    Event(#[source] AuditEventError),
    #[error("audit append failed: {0}")]
    Write(#[source] AuditError),
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use rutilus_domain::{
        AuditAction, AuditActor, AuditOperationContext, AuditOperationId, AuditParameterSummary,
        AuditRedfishOperation, AuditTarget, DeploymentPosture, ProductPermission,
    };
    use time::OffsetDateTime;

    use super::*;

    async fn append_through<Writer: AuditEventWriter>(
        writer: &Writer,
        event: &AuditEvent,
    ) -> Result<(), Writer::Error> {
        writer.append_audit_event(event).await
    }

    #[tokio::test]
    async fn audit_writer_is_an_application_owned_forwarding_boundary() -> Result<(), Box<dyn Error>>
    {
        struct Writer(Arc<AtomicUsize>);

        #[derive(Debug, thiserror::Error)]
        #[error("audit write failed")]
        struct WriterError;

        impl AuditEventWriter for Writer {
            type Error = WriterError;

            fn append_audit_event<'a>(
                &'a self,
                _event: &'a AuditEvent,
            ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
                Box::pin(async move {
                    self.0.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                })
            }
        }

        let write_count = Arc::new(AtomicUsize::new(0));
        let writer = Writer(Arc::clone(&write_count));
        let context = AuditOperationContext::try_new(
            AuditOperationId::generate(),
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
            AuditTarget::Product,
            AuditParameterSummary::csv_endpoint_import(1)?,
            ProductPermission::ManageEndpoints,
            AuditAction::ImportEndpoints,
            AuditRedfishOperation::None,
        )?;
        let event = AuditEvent::started(context, OffsetDateTime::now_utc());

        writer.append_audit_event(&event).await?;
        append_through(&&writer, &event).await?;

        assert_eq!(write_count.load(Ordering::Relaxed), 2);
        let parameter_error = AuditParameterSummary::csv_endpoint_import(0)
            .err()
            .ok_or_else(|| std::io::Error::other("empty import parameters were accepted"))?;
        assert_eq!(
            AuditRecordError::<WriterError>::Parameters(parameter_error).to_string(),
            "audit operation parameters are invalid: an audited CSV import must contain at least one row"
        );
        Ok(())
    }
}
