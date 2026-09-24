//! Ed25519 keypair provisioning for audit-log signing.

use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::RngCore;
use thiserror::Error;

/// Errors loading or generating an audit keypair.
#[derive(Debug, Error)]
pub enum KeypairError {
    /// Filesystem read/write failure.
    #[error("keypair I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Key file contents were not valid hex / wrong length / bad signature key.
    #[error("invalid key file: {0}")]
    Invalid(String),
    /// File permissions could not be set restrictively (Unix).
    #[error("failed to set key file permissions: {0}")]
    Permissions(String),
}

/// An Ed25519 signing keypair used to sign audit records.
#[derive(Clone)]
pub struct AuditKeypair {
    signing: SigningKey,
}

impl std::fmt::Debug for AuditKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditKeypair")
            .field(
                "public",
                &hex::encode(self.signing.verifying_key().to_bytes()),
            )
            .finish_non_exhaustive()
    }
}

impl AuditKeypair {
    /// Generate a fresh random keypair (development / first-run provisioning).
    ///
    /// Production deployments should load an externally provisioned key via
    /// [`AuditKeypair::load_or_generate`] or [`AuditKeypair::from_seed_hex`]
    /// instead of relying on this.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self {
            signing: SigningKey::from_bytes(&seed),
        }
    }

    /// Construct from a 32-byte seed encoded as 64 hex characters.
    ///
    /// # Errors
    ///
    /// Returns [`KeypairError::Invalid`] if `seed_hex` is not 64 hex chars.
    pub fn from_seed_hex(seed_hex: &str) -> Result<Self, KeypairError> {
        let bytes = hex::decode(seed_hex.trim())
            .map_err(|e| KeypairError::Invalid(format!("seed is not valid hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(KeypairError::Invalid(format!(
                "seed must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Hex-encoded 32-byte secret seed (what gets written to the key file).
    #[must_use]
    pub fn seed_hex(&self) -> String {
        hex::encode(self.signing.to_bytes())
    }

    /// Hex-encoded 32-byte public verifying key.
    #[must_use]
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    /// Raw public verifying key bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Sign a 32-byte hash, returning hex-encoded 64-byte signature.
    ///
    /// # Errors
    ///
    /// [`KeypairError::Invalid`] if `hash_hex` is not valid hex — never
    /// silently signs empty/garbage bytes (L5).
    pub fn sign_hash_hex(&self, hash_hex: &str) -> Result<String, KeypairError> {
        let hash_bytes = hex::decode(hash_hex)
            .map_err(|e| KeypairError::Invalid(format!("hash is not valid hex: {e}")))?;
        if hash_bytes.len() != 32 {
            return Err(KeypairError::Invalid(format!(
                "hash must be 32 bytes, got {}",
                hash_bytes.len()
            )));
        }
        let sig: Signature = self.signing.sign(&hash_bytes);
        Ok(hex::encode(sig.to_bytes()))
    }

    /// Load from `path`, generating and writing a new key if the file does
    /// not exist (first-run provisioning).
    ///
    /// On Unix the file is written with mode `0600`. If the file exists but
    /// is world/group readable beyond owner, this is **not** silently
    /// fixed — callers should check permissions in deployment tooling; we do
    /// tighten to `0600` on generate only.
    ///
    /// # Errors
    ///
    /// I/O or invalid-file-content errors.
    pub fn load_or_generate(path: &Path) -> Result<Self, KeypairError> {
        if path.exists() {
            ensure_owner_only(path)?;
            // F13: refuse to follow a symlink at the key path.
            let contents = {
                #[cfg(unix)]
                {
                    use std::io::Read as _;
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut s = String::new();
                    std::fs::OpenOptions::new()
                        .read(true)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(path)?
                        .read_to_string(&mut s)?;
                    s
                }
                #[cfg(not(unix))]
                {
                    std::fs::read_to_string(path)?
                }
            };
            Self::from_seed_hex(&contents)
        } else {
            let kp = Self::generate();
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            write_key_exclusive(path, &kp.seed_hex())?;
            Ok(kp)
        }
    }
}

/// Create the key file with mode 0600 atomically (no world-readable window).
fn write_key_exclusive(path: &Path, seed_hex: &str) -> Result<(), KeypairError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::fs::PermissionsExt;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true).mode(0o600);
        match opts.open(path) {
            Ok(mut f) => {
                std::io::Write::write_all(&mut f, seed_hex.as_bytes())?;
                f.sync_all()?;
                // Re-assert 0600 in case umask interfered with mode().
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Lost a race: another first-run generated a key; load theirs.
                ensure_owner_only(path)?;
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }
    #[cfg(not(unix))]
    {
        // Non-Unix has no create_new+mode; write via temp+rename for atomicity.
        let tmp = path.with_extension("key.tmp");
        std::fs::write(&tmp, seed_hex)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// On Unix, refuse keys that are group/world accessible; tighten to 0600.
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn ensure_owner_only(path: &Path) -> Result<(), KeypairError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| KeypairError::Permissions(e.to_string()))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Verify a hex signature over a hex hash against a hex public key.
///
/// Returns `false` (not an error) on any malformed input — verification
/// failure is the expected answer for corrupt data.
#[must_use]
pub fn verify_signature_hex(public_key_hex: &str, hash_hex: &str, sig_hex: &str) -> bool {
    let (Ok(pk), Ok(hash), Ok(sig)) = (
        hex::decode(public_key_hex),
        hex::decode(hash_hex),
        hex::decode(sig_hex),
    ) else {
        return false;
    };
    if pk.len() != 32 || hash.is_empty() || sig.len() != 64 {
        return false;
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig);

    let Ok(verifying) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let signature = Signature::from_bytes(&sig_arr);
    verifying.verify_strict(&hash, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_sign_verify_roundtrip() {
        let kp = AuditKeypair::generate();
        let hash = "cd".repeat(32);
        let sig = kp.sign_hash_hex(&hash).unwrap();
        assert!(verify_signature_hex(&kp.public_key_hex(), &hash, &sig));
    }

    #[test]
    fn verify_rejects_tampered_hash() {
        let kp = AuditKeypair::generate();
        let hash = "cd".repeat(32);
        let sig = kp.sign_hash_hex(&hash).unwrap();
        let bad_hash = "ce".repeat(32);
        assert!(!verify_signature_hex(&kp.public_key_hex(), &bad_hash, &sig));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let kp1 = AuditKeypair::generate();
        let kp2 = AuditKeypair::generate();
        let hash = "cd".repeat(32);
        let sig = kp1.sign_hash_hex(&hash).unwrap();
        assert!(!verify_signature_hex(&kp2.public_key_hex(), &hash, &sig));
    }

    #[test]
    fn sign_hash_hex_rejects_bad_hex_and_wrong_length() {
        let kp = AuditKeypair::generate();
        assert!(kp.sign_hash_hex("not-hex").is_err());
        assert!(kp.sign_hash_hex("ab").is_err()); // 1 byte, not 32
        assert!(kp.sign_hash_hex("").is_err());
    }

    #[test]
    fn verify_rejects_garbage_inputs() {
        assert!(!verify_signature_hex("zz", "cd", "ab"));
        assert!(!verify_signature_hex("", "", ""));
        assert!(!verify_signature_hex(
            &"aa".repeat(32),
            &"bb".repeat(32),
            "cc"
        ));
    }

    #[test]
    fn seed_hex_roundtrip() {
        let kp = AuditKeypair::generate();
        let seed = kp.seed_hex();
        let restored = AuditKeypair::from_seed_hex(&seed).unwrap();
        assert_eq!(kp.public_key_hex(), restored.public_key_hex());
        assert_eq!(
            kp.sign_hash_hex("aa").ok(),
            restored.sign_hash_hex("aa").ok()
        );
    }

    #[test]
    fn from_seed_hex_rejects_bad_length() {
        assert!(AuditKeypair::from_seed_hex("abcd").is_err());
        assert!(AuditKeypair::from_seed_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn load_or_generate_creates_then_reloads() {
        let dir = std::env::temp_dir().join(format!(
            "tpt-privd-key-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k.key");

        let k1 = AuditKeypair::load_or_generate(&path).unwrap();
        assert!(path.exists());
        let k2 = AuditKeypair::load_or_generate(&path).unwrap();
        assert_eq!(k1.public_key_hex(), k2.public_key_hex());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn generated_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "tpt-privd-key-perm-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k.key");
        let _ = AuditKeypair::load_or_generate(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
