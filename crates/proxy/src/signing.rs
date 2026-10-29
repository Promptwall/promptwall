//! Signed policies. With `--policy-public-key`, a policy file is only used
//! when `<policy file>.sig` holds a valid Ed25519 signature of its exact bytes
//! by the matching private key. A management server, such as the enterprise
//! dashboard, or a CI pipeline signs; every proxy checks, at startup and on
//! each reload, and keeps its current policy when the check fails.
//!
//! Keys and signatures are base64 text files: the public key is the raw
//! 32-byte Ed25519 key, the private key a PKCS#8 document.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

/// A key that policies must be signed with.
#[derive(Clone, Debug)]
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read public key {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("invalid public key {}", path.display()))
    }

    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let bytes = STANDARD.decode(text.trim()).context("not base64")?;
        if bytes.len() != 32 {
            bail!(
                "an Ed25519 public key has 32 bytes, this one {}",
                bytes.len()
            );
        }
        Ok(Self(bytes))
    }

    /// Checks `signature` (base64 text) over `content`.
    pub fn verify(&self, content: &[u8], signature: &str) -> anyhow::Result<()> {
        let signature = STANDARD
            .decode(signature.trim())
            .context("the signature is not base64")?;
        UnparsedPublicKey::new(&ED25519, &self.0)
            .verify(content, &signature)
            .map_err(|_| anyhow::anyhow!("the signature does not match the policy and key"))
    }
}

/// Where the signature of a policy file is: `policy.yaml.sig`.
pub fn signature_path(policy: &Path) -> PathBuf {
    let mut name = policy.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

/// Reads a policy file and, with a key, checks its signature.
pub fn read_policy(path: &Path, key: Option<&PublicKey>) -> anyhow::Result<String> {
    let content = std::fs::read(path)
        .with_context(|| format!("cannot read policy file {}", path.display()))?;
    if let Some(key) = key {
        let sig_path = signature_path(path);
        let signature = std::fs::read_to_string(&sig_path).with_context(|| {
            format!(
                "policy signing is on, but there is no signature {}",
                sig_path.display()
            )
        })?;
        key.verify(&content, &signature)
            .with_context(|| format!("policy file {} rejected", path.display()))?;
    }
    String::from_utf8(content)
        .with_context(|| format!("policy file {} is not UTF-8", path.display()))
}

/// A new key pair: (private key, public key), as base64 text.
pub fn generate() -> anyhow::Result<(String, String)> {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("cannot generate a key"))?;
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| anyhow::anyhow!("cannot read the generated key"))?;
    Ok((
        STANDARD.encode(pkcs8.as_ref()),
        STANDARD.encode(pair.public_key().as_ref()),
    ))
}

/// Signs `content` with a private key (base64 PKCS#8 text); base64 signature.
pub fn sign(private_key: &str, content: &[u8]) -> anyhow::Result<String> {
    let pkcs8 = STANDARD
        .decode(private_key.trim())
        .context("the private key is not base64")?;
    let pair = Ed25519KeyPair::from_pkcs8(&pkcs8)
        .map_err(|_| anyhow::anyhow!("not an Ed25519 private key (PKCS#8)"))?;
    Ok(STANDARD.encode(pair.sign(content).as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_bind_content_and_key() {
        let (private, public) = generate().unwrap();
        let key = PublicKey::parse(&public).unwrap();
        let sig = sign(&private, b"version: 1").unwrap();
        key.verify(b"version: 1", &sig).unwrap();
        assert!(key.verify(b"version: 1 ", &sig).is_err(), "content changed");
        let (_, other) = generate().unwrap();
        let other = PublicKey::parse(&other).unwrap();
        assert!(other.verify(b"version: 1", &sig).is_err(), "another key");
        assert!(PublicKey::parse("c2hvcnQ=").is_err());
        assert_eq!(
            signature_path(Path::new("dir/policy.yaml")),
            Path::new("dir/policy.yaml.sig")
        );
    }
}
