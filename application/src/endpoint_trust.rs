use std::{error::Error, fmt};

use rutilus_domain::{CertificateFingerprint, EndpointAddress, TlsCertificate, TlsTrust};
use time::OffsetDateTime;

use crate::{BoundaryFuture, Clock};

/// Observes one endpoint's leaf identity without credentials or HTTP data.
pub trait TlsIdentityProbe: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn observe<'a>(
        &'a self,
        address: &'a EndpointAddress,
    ) -> BoundaryFuture<'a, Result<TlsIdentityObservation, Self::Error>>;
}

impl<Probe> TlsIdentityProbe for &Probe
where
    Probe: TlsIdentityProbe + ?Sized,
{
    type Error = Probe::Error;

    fn observe<'a>(
        &'a self,
        address: &'a EndpointAddress,
    ) -> BoundaryFuture<'a, Result<TlsIdentityObservation, Self::Error>> {
        Probe::observe(*self, address)
    }
}

/// The platform trust result for the exact leaf identity just observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemCaEvaluation {
    Verified,
    Rejected,
}

/// A credential-free certificate observation from the TLS boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsIdentityObservation {
    certificate: TlsCertificate,
    system_ca: SystemCaEvaluation,
}

impl TlsIdentityObservation {
    #[must_use]
    pub fn new(certificate: TlsCertificate, system_ca: SystemCaEvaluation) -> Self {
        Self {
            certificate,
            system_ca,
        }
    }

    #[must_use]
    pub const fn certificate(&self) -> &TlsCertificate {
        &self.certificate
    }

    #[must_use]
    pub const fn system_ca(&self) -> SystemCaEvaluation {
        self.system_ca
    }

    fn into_parts(self) -> (TlsCertificate, SystemCaEvaluation) {
        (self.certificate, self.system_ca)
    }
}

/// An endpoint address bound to the exact TLS decision established for it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedEndpoint {
    address: EndpointAddress,
    trust: TlsTrust,
}

impl TrustedEndpoint {
    pub(crate) fn new(address: EndpointAddress, trust: TlsTrust) -> Self {
        Self { address, trust }
    }

    #[must_use]
    pub const fn address(&self) -> &EndpointAddress {
        &self.address
    }

    #[must_use]
    pub const fn trust(&self) -> &TlsTrust {
        &self.trust
    }

    pub(crate) fn into_parts(self) -> (EndpointAddress, TlsTrust) {
        (self.address, self.trust)
    }
}

/// A rejected system-CA identity awaiting an administrator's explicit Pin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingEndpointTrust {
    address: EndpointAddress,
    certificate: TlsCertificate,
    observed_at: OffsetDateTime,
}

impl PendingEndpointTrust {
    #[must_use]
    pub const fn address(&self) -> &EndpointAddress {
        &self.address
    }

    #[must_use]
    pub const fn fingerprint(&self) -> CertificateFingerprint {
        self.certificate.fingerprint()
    }

    #[must_use]
    pub const fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }

    fn accept_pin_at(
        self,
        trusted_at: OffsetDateTime,
    ) -> Result<TrustedEndpoint, EndpointTrustTimelineError> {
        if trusted_at < self.observed_at {
            return Err(EndpointTrustTimelineError);
        }
        Ok(TrustedEndpoint::new(
            self.address,
            TlsTrust::PinnedCertificate {
                certificate: self.certificate,
                trusted_at,
            },
        ))
    }
}

/// The safe next step after credential-free TLS observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointTrustChallenge {
    SystemCaTrusted(TrustedEndpoint),
    ExplicitPinRequired(PendingEndpointTrust),
}

/// Coordinates the credential-free first stage of endpoint onboarding.
pub struct EndpointTrustEstablishment<Probe, Time> {
    probe: Probe,
    clock: Time,
}

impl<Probe, Time> EndpointTrustEstablishment<Probe, Time>
where
    Probe: TlsIdentityProbe,
    Time: Clock,
{
    #[must_use]
    pub fn new(probe: Probe, clock: Time) -> Self {
        Self { probe, clock }
    }

    /// Observes the TLS leaf without credentials and either establishes normal
    /// system trust or returns an explicit Pin challenge.
    ///
    /// # Errors
    ///
    /// Returns the probe boundary's typed error when the identity cannot be
    /// observed safely.
    pub async fn begin(
        &self,
        address: EndpointAddress,
    ) -> Result<EndpointTrustChallenge, Probe::Error> {
        let observation = self.probe.observe(&address).await?;
        let observed_at = self.clock.now();
        let (certificate, system_ca) = observation.into_parts();
        Ok(match system_ca {
            SystemCaEvaluation::Verified => {
                EndpointTrustChallenge::SystemCaTrusted(TrustedEndpoint::new(
                    address,
                    TlsTrust::SystemCa {
                        certificate,
                        verified_at: observed_at,
                    },
                ))
            }
            SystemCaEvaluation::Rejected => {
                EndpointTrustChallenge::ExplicitPinRequired(PendingEndpointTrust {
                    address,
                    certificate,
                    observed_at,
                })
            }
        })
    }

    /// Records the caller's explicit acceptance of the exact pending identity.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointTrustTimelineError`] if the current clock predates the
    /// credential-free observation.
    pub fn accept_pin(
        &self,
        pending: PendingEndpointTrust,
    ) -> Result<TrustedEndpoint, EndpointTrustTimelineError> {
        pending.accept_pin_at(self.clock.now())
    }
}

/// A Pin acceptance timestamp predates its credential-free observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointTrustTimelineError;

impl fmt::Display for EndpointTrustTimelineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TLS Pin acceptance cannot predate certificate observation")
    }
}

impl Error for EndpointTrustTimelineError {}

#[cfg(test)]
mod tests {
    use std::{fmt, sync::Mutex};

    use rutilus_domain::TlsCertificateError;

    use super::*;

    #[test]
    fn observation_exposes_only_the_typed_identity_projection() -> Result<(), TlsCertificateError> {
        let certificate = TlsCertificate::from_der(b"observed certificate".to_vec())?;
        let observation =
            TlsIdentityObservation::new(certificate.clone(), SystemCaEvaluation::Verified);

        assert_eq!(observation.certificate(), &certificate);
        assert_eq!(observation.system_ca(), SystemCaEvaluation::Verified);
        Ok(())
    }

    #[tokio::test]
    async fn system_ca_verification_establishes_address_bound_trust() -> Result<(), Box<dyn Error>>
    {
        let observed_at = OffsetDateTime::now_utc();
        let address = EndpointAddress::parse("https://192.0.2.90")?;
        let service = EndpointTrustEstablishment::new(
            MockProbe::new(SystemCaEvaluation::Verified)?,
            FixedClock(observed_at),
        );

        let challenge = service.begin(address.clone()).await?;

        let EndpointTrustChallenge::SystemCaTrusted(target) = challenge else {
            return Err(std::io::Error::other("system CA trust was not established").into());
        };
        assert_eq!(target.address(), &address);
        assert!(matches!(
            target.trust(),
            TlsTrust::SystemCa { verified_at, .. } if *verified_at == observed_at
        ));
        assert_eq!(service.probe.observations()?, 1);
        Ok(())
    }

    #[tokio::test]
    async fn rejected_system_ca_requires_explicit_pin_acceptance() -> Result<(), Box<dyn Error>> {
        let observed_at = OffsetDateTime::now_utc();
        let address = EndpointAddress::parse("https://192.0.2.91")?;
        let expected = TlsCertificate::from_der(b"self-signed certificate".to_vec())?;
        let service = EndpointTrustEstablishment::new(
            MockProbe::with_certificate(SystemCaEvaluation::Rejected, expected.clone()),
            FixedClock(observed_at),
        );

        let challenge = service.begin(address.clone()).await?;

        let EndpointTrustChallenge::ExplicitPinRequired(pending) = challenge else {
            return Err(std::io::Error::other("explicit Pin challenge was not returned").into());
        };
        assert_eq!(pending.address(), &address);
        assert_eq!(pending.fingerprint(), expected.fingerprint());
        assert_eq!(pending.observed_at(), observed_at);
        let target = service.accept_pin(pending)?;
        assert_eq!(target.address(), &address);
        assert!(matches!(
            target.trust(),
            TlsTrust::PinnedCertificate {
                certificate,
                trusted_at,
            } if certificate == &expected && *trusted_at == observed_at
        ));
        Ok(())
    }

    #[test]
    fn rejects_pin_acceptance_before_observation() -> Result<(), Box<dyn Error>> {
        let observed_at = OffsetDateTime::now_utc();
        let service = EndpointTrustEstablishment::new(
            MockProbe::new(SystemCaEvaluation::Rejected)?,
            FixedClock(observed_at - time::Duration::SECOND),
        );
        let pending = PendingEndpointTrust {
            address: EndpointAddress::parse("https://192.0.2.92")?,
            certificate: TlsCertificate::from_der(b"future certificate".to_vec())?,
            observed_at,
        };

        assert_eq!(service.accept_pin(pending), Err(EndpointTrustTimelineError));
        assert_eq!(
            EndpointTrustTimelineError.to_string(),
            "TLS Pin acceptance cannot predate certificate observation"
        );
        Ok(())
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct MockProbeError;

    impl fmt::Display for MockProbeError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("mock TLS observation failed")
        }
    }

    impl Error for MockProbeError {}

    struct MockProbe {
        evaluation: SystemCaEvaluation,
        certificate: TlsCertificate,
        observations: Mutex<usize>,
    }

    impl MockProbe {
        fn new(evaluation: SystemCaEvaluation) -> Result<Self, TlsCertificateError> {
            Ok(Self::with_certificate(
                evaluation,
                TlsCertificate::from_der(b"mock certificate".to_vec())?,
            ))
        }

        fn with_certificate(evaluation: SystemCaEvaluation, certificate: TlsCertificate) -> Self {
            Self {
                evaluation,
                certificate,
                observations: Mutex::new(0),
            }
        }

        fn observations(&self) -> Result<usize, MockProbeError> {
            self.observations
                .lock()
                .map(|observations| *observations)
                .map_err(|_| MockProbeError)
        }
    }

    impl TlsIdentityProbe for MockProbe {
        type Error = MockProbeError;

        fn observe<'a>(
            &'a self,
            _address: &'a EndpointAddress,
        ) -> BoundaryFuture<'a, Result<TlsIdentityObservation, Self::Error>> {
            Box::pin(async move {
                let mut observations = self.observations.lock().map_err(|_| MockProbeError)?;
                *observations += 1;
                Ok(TlsIdentityObservation::new(
                    self.certificate.clone(),
                    self.evaluation,
                ))
            })
        }
    }

    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }
}
