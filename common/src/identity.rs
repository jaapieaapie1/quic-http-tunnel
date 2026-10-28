//! Self-signed certificate and key on disk, identified by its public key
//! fingerprint. Used by both ends: each side pins the other's fingerprint.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::tls::{format_fingerprint, spki_fingerprint};
use anyhow::{Context, Result, bail};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::info;

pub struct Identity {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
    /// Hex SHA-256 of the certificate's public key, what the peer pins.
    pub fingerprint: String,
}

/// Loads a certificate and key, generating a self-signed pair for `name`
/// when neither file exists.
pub fn load_or_generate(cert_path: &Path, key_path: &Path, name: &str) -> Result<Identity> {
    match (cert_path.exists(), key_path.exists()) {
        (true, true) => {}
        (false, false) => generate(cert_path, key_path, name)?,
        _ => bail!(
            "only one of {} and {} exists; provide both or neither",
            cert_path.display(),
            key_path.display()
        ),
    }

    let certs = CertificateDer::pem_file_iter(cert_path)
        .with_context(|| format!("reading {}", cert_path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing {}", cert_path.display()))?;
    let Some(leaf) = certs.first() else {
        bail!("no certificate in {}", cert_path.display());
    };
    let fingerprint = format_fingerprint(&spki_fingerprint(leaf)?);
    let key = PrivateKeyDer::from_pem_file(key_path)
        .with_context(|| format!("reading {}", key_path.display()))?;

    Ok(Identity {
        certs,
        key,
        fingerprint,
    })
}

fn generate(cert_path: &Path, key_path: &Path, name: &str) -> Result<()> {
    let generated = rcgen::generate_simple_self_signed(vec![name.to_owned()])?;
    fs::write(cert_path, generated.cert.pem())
        .with_context(|| format!("writing {}", cert_path.display()))?;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options
        .open(key_path)
        .and_then(|mut f| f.write_all(generated.signing_key.serialize_pem().as_bytes()))
        .with_context(|| format!("writing {}", key_path.display()))?;

    info!(
        cert = %cert_path.display(),
        key = %key_path.display(),
        "generated new self-signed identity"
    );
    Ok(())
}
