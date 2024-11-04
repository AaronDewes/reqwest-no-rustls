//! TLS configuration and types
//!
//! A `Client` will use transport layer security (TLS) by default to connect to
//! HTTPS destinations.
//!
//! # Backends
//!
//! reqwest supports several TLS backends, enabled with Cargo features.
//!
//! ## default-tls
//!
//! reqwest will pick a TLS backend by default. This is true when the
//! `default-tls` feature is enabled.
//!
//! While it currently uses `native-tls`, the feature set is designed to only
//! enable configuration that is shared among available backends. This allows
//! reqwest to change the default to `rustls` (or another) at some point in the
//! future.
//!
//! <div class="warning">This feature is enabled by default, and takes
//! precedence if any other crate enables it. This is true even if you declare
//! `features = []`. You must set `default-features = false` instead.</div>
//!
//! Since Cargo features are additive, other crates in your dependency tree can
//! cause the default backend to be enabled. If you wish to ensure your
//! `Client` uses a specific backend, call the appropriate builder methods
//! (such as [`use_rustls_tls()`][]).
//!
//! [`use_rustls_tls()`]: crate::ClientBuilder::use_rustls_tls()
//!
//! ## native-tls
//!
//! This backend uses the [native-tls][] crate. That will try to use the system
//! TLS on Windows and Mac, and OpenSSL on Linux targets.
//!
//! Enabling the feature explicitly allows for `native-tls`-specific
//! configuration options.
//!
//! [native-tls]: https://crates.io/crates/native-tls
//!
//! ## rustls-tls
//!
//! This backend uses the [rustls][] crate, a TLS library written in Rust.
//!
//! [rustls]: https://crates.io/crates/rustls

use std::{
    fmt,
    io::{BufRead, BufReader},
};

/// Represents a server X509 certificate.
#[derive(Clone)]
pub struct Certificate {
    #[cfg(feature = "default-tls")]
    native: native_tls_crate::Certificate,
}

/// Represents a private key and X509 cert as a client certificate.
#[derive(Clone)]
pub struct Identity {
    #[cfg_attr(not(feature = "native-tls"), allow(unused))]
    inner: ClientCert,
}

enum ClientCert {
    #[cfg(feature = "native-tls")]
    Pkcs12(native_tls_crate::Identity),
    #[cfg(feature = "native-tls")]
    Pkcs8(native_tls_crate::Identity),
}

impl Clone for ClientCert {
    fn clone(&self) -> Self {
        match self {
            #[cfg(feature = "native-tls")]
            Self::Pkcs8(i) => Self::Pkcs8(i.clone()),
            #[cfg(feature = "native-tls")]
            Self::Pkcs12(i) => Self::Pkcs12(i.clone()),
            #[cfg_attr(
                feature = "native-tls",
                allow(unreachable_patterns)
            )]
            _ => unreachable!(),
        }
    }
}

impl Certificate {
    /// Create a `Certificate` from a binary DER encoded certificate
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::io::Read;
    /// # fn cert() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut buf = Vec::new();
    /// File::open("my_cert.der")?
    ///     .read_to_end(&mut buf)?;
    /// let cert = reqwest::Certificate::from_der(&buf)?;
    /// # drop(cert);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_der(der: &[u8]) -> crate::Result<Certificate> {
        Ok(Certificate {
            #[cfg(feature = "default-tls")]
            native: native_tls_crate::Certificate::from_der(der).map_err(crate::error::builder)?,
        })
    }

    /// Create a `Certificate` from a PEM encoded certificate
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::io::Read;
    /// # fn cert() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut buf = Vec::new();
    /// File::open("my_cert.pem")?
    ///     .read_to_end(&mut buf)?;
    /// let cert = reqwest::Certificate::from_pem(&buf)?;
    /// # drop(cert);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_pem(pem: &[u8]) -> crate::Result<Certificate> {
        Ok(Certificate {
            #[cfg(feature = "default-tls")]
            native: native_tls_crate::Certificate::from_pem(pem).map_err(crate::error::builder)?,
        })
    }

    /// Create a collection of `Certificate`s from a PEM encoded certificate bundle.
    /// Example byte sources may be `.crt`, `.cer` or `.pem` files.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::io::Read;
    /// # fn cert() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut buf = Vec::new();
    /// File::open("ca-bundle.crt")?
    ///     .read_to_end(&mut buf)?;
    /// let certs = reqwest::Certificate::from_pem_bundle(&buf)?;
    /// # drop(certs);
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_pem_bundle(pem_bundle: &[u8]) -> crate::Result<Vec<Certificate>> {
        let mut reader = BufReader::new(pem_bundle);

        Self::read_pem_certs(&mut reader)?
            .iter()
            .map(|cert_vec| Certificate::from_der(cert_vec))
            .collect::<crate::Result<Vec<Certificate>>>()
    }

    #[cfg(feature = "default-tls")]
    pub(crate) fn add_to_native_tls(self, tls: &mut native_tls_crate::TlsConnectorBuilder) {
        tls.add_root_certificate(self.native);
    }

    fn read_pem_certs(reader: &mut impl BufRead) -> crate::Result<Vec<Vec<u8>>> {
        rustls_pemfile::certs(reader)
            .map(|result| match result {
                Ok(cert) => Ok(cert.as_ref().to_vec()),
                Err(_) => Err(crate::error::builder("invalid certificate encoding")),
            })
            .collect()
    }
}

impl Identity {
    /// Parses a DER-formatted PKCS #12 archive, using the specified password to decrypt the key.
    ///
    /// The archive should contain a leaf certificate and its private key, as well any intermediate
    /// certificates that allow clients to build a chain to a trusted root.
    /// The chain certificates should be in order from the leaf certificate towards the root.
    ///
    /// PKCS #12 archives typically have the file extension `.p12` or `.pfx`, and can be created
    /// with the OpenSSL `pkcs12` tool:
    ///
    /// ```bash
    /// openssl pkcs12 -export -out identity.pfx -inkey key.pem -in cert.pem -certfile chain_certs.pem
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs::File;
    /// # use std::io::Read;
    /// # fn pkcs12() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut buf = Vec::new();
    /// File::open("my-ident.pfx")?
    ///     .read_to_end(&mut buf)?;
    /// let pkcs12 = reqwest::Identity::from_pkcs12_der(&buf, "my-privkey-password")?;
    /// # drop(pkcs12);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Optional
    ///
    /// This requires the `native-tls` Cargo feature enabled.
    #[cfg(feature = "native-tls")]
    pub fn from_pkcs12_der(der: &[u8], password: &str) -> crate::Result<Identity> {
        Ok(Identity {
            inner: ClientCert::Pkcs12(
                native_tls_crate::Identity::from_pkcs12(der, password)
                    .map_err(crate::error::builder)?,
            ),
        })
    }

    /// Parses a chain of PEM encoded X509 certificates, with the leaf certificate first.
    /// `key` is a PEM encoded PKCS #8 formatted private key for the leaf certificate.
    ///
    /// The certificate chain should contain any intermediate cerficates that should be sent to
    /// clients to allow them to build a chain to a trusted root.
    ///
    /// A certificate chain here means a series of PEM encoded certificates concatenated together.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::fs;
    /// # fn pkcs8() -> Result<(), Box<dyn std::error::Error>> {
    /// let cert = fs::read("client.pem")?;
    /// let key = fs::read("key.pem")?;
    /// let pkcs8 = reqwest::Identity::from_pkcs8_pem(&cert, &key)?;
    /// # drop(pkcs8);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Optional
    ///
    /// This requires the `native-tls` Cargo feature enabled.
    #[cfg(feature = "native-tls")]
    pub fn from_pkcs8_pem(pem: &[u8], key: &[u8]) -> crate::Result<Identity> {
        Ok(Identity {
            inner: ClientCert::Pkcs8(
                native_tls_crate::Identity::from_pkcs8(pem, key).map_err(crate::error::builder)?,
            ),
        })
    }

    #[cfg(feature = "native-tls")]
    pub(crate) fn add_to_native_tls(
        self,
        tls: &mut native_tls_crate::TlsConnectorBuilder,
    ) -> crate::Result<()> {
        match self.inner {
            ClientCert::Pkcs12(id) | ClientCert::Pkcs8(id) => {
                tls.identity(id);
                Ok(())
            }
        }
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Certificate").finish()
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Identity").finish()
    }
}

/// A TLS protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(InnerVersion);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
enum InnerVersion {
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
}

// These could perhaps be From/TryFrom implementations, but those would be
// part of the public API so let's be careful
impl Version {
    /// Version 1.0 of the TLS protocol.
    pub const TLS_1_0: Version = Version(InnerVersion::Tls1_0);
    /// Version 1.1 of the TLS protocol.
    pub const TLS_1_1: Version = Version(InnerVersion::Tls1_1);
    /// Version 1.2 of the TLS protocol.
    pub const TLS_1_2: Version = Version(InnerVersion::Tls1_2);
    /// Version 1.3 of the TLS protocol.
    pub const TLS_1_3: Version = Version(InnerVersion::Tls1_3);

    #[cfg(feature = "default-tls")]
    pub(crate) fn to_native_tls(self) -> Option<native_tls_crate::Protocol> {
        match self.0 {
            InnerVersion::Tls1_0 => Some(native_tls_crate::Protocol::Tlsv10),
            InnerVersion::Tls1_1 => Some(native_tls_crate::Protocol::Tlsv11),
            InnerVersion::Tls1_2 => Some(native_tls_crate::Protocol::Tlsv12),
            InnerVersion::Tls1_3 => None,
        }
    }
}

pub(crate) enum TlsBackend {
    // This is the default and HTTP/3 feature does not use it so suppress it.
    #[allow(dead_code)]
    #[cfg(feature = "default-tls")]
    Default,
    #[cfg(feature = "native-tls")]
    BuiltNativeTls(native_tls_crate::TlsConnector),
    #[cfg(feature = "native-tls")]
    UnknownPreconfigured,
}

impl fmt::Debug for TlsBackend {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            #[cfg(feature = "default-tls")]
            TlsBackend::Default => write!(f, "Default"),
            #[cfg(feature = "native-tls")]
            TlsBackend::BuiltNativeTls(_) => write!(f, "BuiltNativeTls"),
            #[cfg(feature = "native-tls")]
            TlsBackend::UnknownPreconfigured => write!(f, "UnknownPreconfigured"),
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for TlsBackend {
    fn default() -> TlsBackend {
        #[cfg(feature = "default-tls")]
        {
            TlsBackend::Default
        }
    }
}

/// Hyper extension carrying extra TLS layer information.
/// Made available to clients on responses when `tls_info` is set.
#[derive(Clone)]
pub struct TlsInfo {
    pub(crate) peer_certificate: Option<Vec<u8>>,
}

impl TlsInfo {
    /// Get the DER encoded leaf certificate of the peer.
    pub fn peer_certificate(&self) -> Option<&[u8]> {
        self.peer_certificate.as_ref().map(|der| &der[..])
    }
}

impl std::fmt::Debug for TlsInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("TlsInfo").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "default-tls")]
    #[test]
    fn certificate_from_der_invalid() {
        Certificate::from_der(b"not der").unwrap_err();
    }

    #[cfg(feature = "default-tls")]
    #[test]
    fn certificate_from_pem_invalid() {
        Certificate::from_pem(b"not pem").unwrap_err();
    }

    #[cfg(feature = "native-tls")]
    #[test]
    fn identity_from_pkcs12_der_invalid() {
        Identity::from_pkcs12_der(b"not der", "nope").unwrap_err();
    }

    #[cfg(feature = "native-tls")]
    #[test]
    fn identity_from_pkcs8_pem_invalid() {
        Identity::from_pkcs8_pem(b"not pem", b"not key").unwrap_err();
    }

    #[test]
    fn certificates_from_pem_bundle() {
        const PEM_BUNDLE: &[u8] = b"
            -----BEGIN CERTIFICATE-----
            MIIBtjCCAVugAwIBAgITBmyf1XSXNmY/Owua2eiedgPySjAKBggqhkjOPQQDAjA5
            MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
            Um9vdCBDQSAzMB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG
            A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg
            Q0EgMzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCmXp8ZBf8ANm+gBG1bG8lKl
            ui2yEujSLtf6ycXYqm0fc4E7O5hrOXwzpcVOho6AF2hiRVd9RFgdszflZwjrZt6j
            QjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBSr
            ttvXBp43rDCGB5Fwx5zEGbF4wDAKBggqhkjOPQQDAgNJADBGAiEA4IWSoxe3jfkr
            BqWTrBqYaGFy+uGh0PsceGCmQ5nFuMQCIQCcAu/xlJyzlvnrxir4tiz+OpAUFteM
            YyRIHN8wfdVoOw==
            -----END CERTIFICATE-----

            -----BEGIN CERTIFICATE-----
            MIIB8jCCAXigAwIBAgITBmyf18G7EEwpQ+Vxe3ssyBrBDjAKBggqhkjOPQQDAzA5
            MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6b24g
            Um9vdCBDQSA0MB4XDTE1MDUyNjAwMDAwMFoXDTQwMDUyNjAwMDAwMFowOTELMAkG
            A1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJvb3Qg
            Q0EgNDB2MBAGByqGSM49AgEGBSuBBAAiA2IABNKrijdPo1MN/sGKe0uoe0ZLY7Bi
            9i0b2whxIdIA6GO9mif78DluXeo9pcmBqqNbIJhFXRbb/egQbeOc4OO9X4Ri83Bk
            M6DLJC9wuoihKqB1+IGuYgbEgds5bimwHvouXKNCMEAwDwYDVR0TAQH/BAUwAwEB
            /zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFNPsxzplbszh2naaVvuc84ZtV+WB
            MAoGCCqGSM49BAMDA2gAMGUCMDqLIfG9fhGt0O9Yli/W651+kI0rz2ZVwyzjKKlw
            CkcO8DdZEv8tmZQoTipPNU0zWgIxAOp1AE47xDqUEpHJWEadIRNyp4iciuRMStuW
            1KyLa2tJElMzrdfkviT8tQp21KW8EA==
            -----END CERTIFICATE-----
        ";

        assert!(Certificate::from_pem_bundle(PEM_BUNDLE).is_ok())
    }
}
