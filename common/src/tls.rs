//! Public key pinning for the client side of the QUIC connection.
//!
//! The client does not use a CA. Instead it is configured with the SHA-256
//! hash of the server's SubjectPublicKeyInfo (SPKI) and accepts only a
//! certificate carrying exactly that public key. The TLS handshake signature
//! is still verified, so only the holder of the matching private key can
//! complete the handshake.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

pub type Fingerprint = [u8; 32];

pub fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// SHA-256 over the DER-encoded SubjectPublicKeyInfo of a certificate.
pub fn spki_fingerprint(cert: &CertificateDer<'_>) -> Result<Fingerprint> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| anyhow!("invalid certificate: {e}"))?;
    Ok(Sha256::digest(parsed.tbs_certificate.subject_pki.raw).into())
}

pub fn format_fingerprint(fp: &Fingerprint) -> String {
    hex::encode(fp)
}

/// Parses a fingerprint as 64 hex characters; `:` separators and an optional
/// `sha256:` / `sha256/` prefix are accepted.
pub fn parse_fingerprint(s: &str) -> Result<Fingerprint> {
    let s = s.trim();
    let s = s
        .strip_prefix("sha256:")
        .or_else(|| s.strip_prefix("sha256/"))
        .unwrap_or(s);
    let cleaned: String = s.chars().filter(|c| *c != ':').collect();
    let bytes = hex::decode(&cleaned).context("fingerprint is not valid hex")?;
    match bytes.try_into() {
        Ok(fp) => Ok(fp),
        Err(bytes) => bail!("fingerprint must be 32 bytes, got {}", bytes.len()),
    }
}

#[derive(Debug)]
pub struct PinnedKeyVerifier {
    pin: Fingerprint,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedKeyVerifier {
    pub fn new(pin: Fingerprint, provider: &CryptoProvider) -> Self {
        Self {
            pin,
            algorithms: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = spki_fingerprint(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if fp == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// rustls client config that trusts only the server key matching `pin`.
pub fn pinned_client_config(pin: Fingerprint) -> Result<rustls::ClientConfig> {
    let provider = crypto_provider();
    let verifier = Arc::new(PinnedKeyVerifier::new(pin, &provider));
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![crate::ALPN.to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fingerprint_formats() {
        let hex = "ab".repeat(32);
        let colons = vec!["ab"; 32].join(":");
        assert_eq!(parse_fingerprint(&hex).unwrap(), [0xab; 32]);
        assert_eq!(parse_fingerprint(&colons).unwrap(), [0xab; 32]);
        assert_eq!(
            parse_fingerprint(&format!("sha256:{hex}")).unwrap(),
            [0xab; 32]
        );
        assert!(parse_fingerprint("abcd").is_err());
    }
}
