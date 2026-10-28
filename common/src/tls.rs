//! Public key pinning for both sides of the QUIC connection.
//!
//! Neither side uses a CA. The client is configured with the SHA-256 hash of
//! the server's SubjectPublicKeyInfo (SPKI) and accepts only a certificate
//! carrying exactly that public key; the server likewise accepts only client
//! certificates whose key is in its allowlist. The TLS handshake signatures
//! are still verified, so only the holder of a matching private key can
//! complete the handshake.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::identity::Identity;

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

/// Accepts only client certificates whose public key is in the allowlist.
#[derive(Debug)]
pub struct PinnedClientVerifier {
    pins: Vec<Fingerprint>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl PinnedClientVerifier {
    pub fn new(pins: Vec<Fingerprint>, provider: &CryptoProvider) -> Self {
        Self {
            pins,
            algorithms: provider.signature_verification_algorithms,
        }
    }
}

impl ClientCertVerifier for PinnedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let fp = spki_fingerprint(end_entity)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        if self.pins.contains(&fp) {
            Ok(ClientCertVerified::assertion())
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

/// rustls client config that trusts only the server key matching `pin` and
/// authenticates with `identity`.
pub fn pinned_client_config(pin: Fingerprint, identity: Identity) -> Result<rustls::ClientConfig> {
    let provider = crypto_provider();
    let verifier = Arc::new(PinnedKeyVerifier::new(pin, &provider));
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(identity.certs, identity.key)?;
    config.alpn_protocols = vec![crate::ALPN.to_vec()];
    Ok(config)
}

/// rustls server config presenting `identity` and requiring a client
/// certificate whose key is one of `client_pins`.
pub fn pinned_server_config(
    identity: Identity,
    client_pins: Vec<Fingerprint>,
) -> Result<rustls::ServerConfig> {
    if client_pins.is_empty() {
        bail!("at least one client pin is required");
    }
    let provider = crypto_provider();
    let verifier = Arc::new(PinnedClientVerifier::new(client_pins, &provider));
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(identity.certs, identity.key)?;
    config.alpn_protocols = vec![crate::ALPN.to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::PrivateKeyDer;

    use super::*;

    fn identity() -> (Identity, Fingerprint) {
        let generated = rcgen::generate_simple_self_signed(vec!["test".to_owned()]).unwrap();
        let cert = generated.cert.der().clone();
        let fp = spki_fingerprint(&cert).unwrap();
        let identity = Identity {
            certs: vec![cert],
            key: PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into()),
            fingerprint: format_fingerprint(&fp),
        };
        (identity, fp)
    }

    /// Runs a TLS handshake in memory, returning the first error either side hits.
    fn handshake(
        client: rustls::ClientConfig,
        server: rustls::ServerConfig,
    ) -> Result<(), rustls::Error> {
        let name = ServerName::try_from("quic-http-tunnel").unwrap();
        let mut client =
            rustls::Connection::from(rustls::ClientConnection::new(Arc::new(client), name)?);
        let mut server = rustls::Connection::from(rustls::ServerConnection::new(Arc::new(server))?);
        for _ in 0..10 {
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
            transfer(&mut client, &mut server)?;
            transfer(&mut server, &mut client)?;
        }
        panic!("handshake did not finish");
    }

    fn transfer(
        from: &mut rustls::Connection,
        to: &mut rustls::Connection,
    ) -> Result<(), rustls::Error> {
        let mut buf = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut buf).unwrap();
        }
        let mut rd = &buf[..];
        while !rd.is_empty() {
            to.read_tls(&mut rd).unwrap();
        }
        to.process_new_packets()?;
        Ok(())
    }

    #[test]
    fn mutual_pinning_accepts_pinned_keys() {
        let (server_id, server_fp) = identity();
        let (client_id, client_fp) = identity();
        let (_, other_fp) = identity();
        handshake(
            pinned_client_config(server_fp, client_id).unwrap(),
            pinned_server_config(server_id, vec![other_fp, client_fp]).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn server_rejects_unpinned_client_key() {
        let (server_id, server_fp) = identity();
        let (client_id, _) = identity();
        let (_, other_fp) = identity();
        let err = handshake(
            pinned_client_config(server_fp, client_id).unwrap(),
            pinned_server_config(server_id, vec![other_fp]).unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(err, rustls::Error::InvalidCertificate(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn server_rejects_client_without_certificate() {
        let (server_id, server_fp) = identity();
        let (_, client_fp) = identity();
        let provider = crypto_provider();
        let verifier = Arc::new(PinnedKeyVerifier::new(server_fp, &provider));
        let mut client = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        client.alpn_protocols = vec![crate::ALPN.to_vec()];
        let err = handshake(
            client,
            pinned_server_config(server_id, vec![client_fp]).unwrap(),
        )
        .unwrap_err();
        assert!(
            matches!(err, rustls::Error::NoCertificatesPresented),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn server_config_requires_a_pin() {
        let (server_id, _) = identity();
        assert!(pinned_server_config(server_id, vec![]).is_err());
    }

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
