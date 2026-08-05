use std::{error::Error, fmt, str::FromStr};

use url::Url;

/// A validated HTTPS entry point for one Redfish service.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EndpointAddress(Url);

impl EndpointAddress {
    /// Parses an endpoint address and enforces credential and transport boundaries.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointAddressError`] when the value is not an absolute HTTPS URL,
    /// has no host, embeds credentials, or contains a query or fragment.
    pub fn parse(value: &str) -> Result<Self, EndpointAddressError> {
        let url = Url::parse(value).map_err(EndpointAddressError::InvalidUrl)?;

        if url.scheme() != "https" {
            return Err(EndpointAddressError::HttpsRequired);
        }
        if url.host_str().is_none() {
            return Err(EndpointAddressError::HostRequired);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(EndpointAddressError::EmbeddedCredentials);
        }
        if url.query().is_some() {
            return Err(EndpointAddressError::QueryNotAllowed);
        }
        if url.fragment().is_some() {
            return Err(EndpointAddressError::FragmentNotAllowed);
        }

        Ok(Self(url))
    }

    /// Borrows the validated URL.
    #[must_use]
    pub const fn as_url(&self) -> &Url {
        &self.0
    }
}

impl fmt::Display for EndpointAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for EndpointAddress {
    type Err = EndpointAddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why a candidate endpoint address cannot be used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointAddressError {
    /// The value is not an absolute URL.
    InvalidUrl(url::ParseError),
    /// BMC credentials may only be sent over HTTPS.
    HttpsRequired,
    /// A network host is required.
    HostRequired,
    /// User information must be stored as an encrypted credential, not in a URL.
    EmbeddedCredentials,
    /// Query parameters are not part of a stable service entry point.
    QueryNotAllowed,
    /// URL fragments are browser-local and cannot identify a service entry point.
    FragmentNotAllowed,
}

impl fmt::Display for EndpointAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(_) => formatter.write_str("endpoint address is not an absolute URL"),
            Self::HttpsRequired => formatter.write_str("endpoint address must use HTTPS"),
            Self::HostRequired => formatter.write_str("endpoint address must include a host"),
            Self::EmbeddedCredentials => {
                formatter.write_str("endpoint address must not contain credentials")
            }
            Self::QueryNotAllowed => {
                formatter.write_str("endpoint address must not contain a query")
            }
            Self::FragmentNotAllowed => {
                formatter.write_str("endpoint address must not contain a fragment")
            }
        }
    }
}

impl Error for EndpointAddressError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidUrl(error) => Some(error),
            Self::HttpsRequired
            | Self::HostRequired
            | Self::EmbeddedCredentials
            | Self::QueryNotAllowed
            | Self::FragmentNotAllowed => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EndpointAddress, EndpointAddressError};

    #[test]
    fn accepts_https_hosts_ports_and_base_paths() -> Result<(), EndpointAddressError> {
        let address = EndpointAddress::parse("https://bmc.example.test:8443/redfish")?;

        assert_eq!(address.to_string(), "https://bmc.example.test:8443/redfish");
        Ok(())
    }

    #[test]
    fn rejects_non_https_transport() {
        assert_eq!(
            EndpointAddress::parse("http://bmc.example.test"),
            Err(EndpointAddressError::HttpsRequired)
        );
    }

    #[test]
    fn rejects_credentials_in_the_address() {
        assert_eq!(
            EndpointAddress::parse("https://admin:secret@bmc.example.test"),
            Err(EndpointAddressError::EmbeddedCredentials)
        );
    }

    #[test]
    fn rejects_query_and_fragment_components() {
        assert_eq!(
            EndpointAddress::parse("https://bmc.example.test?raw=true"),
            Err(EndpointAddressError::QueryNotAllowed)
        );
        assert_eq!(
            EndpointAddress::parse("https://bmc.example.test#console"),
            Err(EndpointAddressError::FragmentNotAllowed)
        );
    }
}
