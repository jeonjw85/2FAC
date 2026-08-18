use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Argon2, Params, Version};
use data_encoding::BASE64;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::totp::Algorithm;

pub const MIN_PASSWORD_LEN: usize = 8;
const KDF_M_KIB: u32 = 64 * 1024;
const KDF_ITER: u32 = 3;
const KDF_PAR: u32 = 4;
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const FORMAT_VERSION: u32 = 1;

#[derive(Debug, PartialEq, Eq)]
pub enum VaultError {
    Io(String),
    WrongPassword,
    Corrupted,
    WeakPassword,
}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub issuer: String,
    pub name: String,
    pub secret: Zeroizing<String>,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u32,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VaultData {
    pub accounts: Vec<Account>,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    kdf_m_kib: u32,
    kdf_iter: u32,
    kdf_par: u32,
    salt: String,
    nonce: String,
    ciphertext: String,
}

pub struct KeyMaterial {
    pub salt: [u8; SALT_LEN],
    pub key: Zeroizing<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyMaterial").finish_non_exhaustive()
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.salt.zeroize();
    }
}

fn derive_key(password: &str, salt: &[u8], m_kib: u32, iter: u32, par: u32) -> Result<Zeroizing<[u8; KEY_LEN]>, VaultError> {
    let params = Params::new(m_kib, iter, par, Some(KEY_LEN)).map_err(|_| VaultError::Corrupted)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|_| VaultError::Corrupted)?;
    Ok(key)
}

fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<([u8; NONCE_LEN], Vec<u8>), VaultError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| VaultError::Corrupted)?;
    Ok((nonce_bytes, ciphertext))
}

fn decrypt(key: &[u8; KEY_LEN], nonce_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, VaultError> {
    if nonce_bytes.len() != NONCE_LEN {
        return Err(VaultError::Corrupted);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| VaultError::WrongPassword)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn write_file(path: &Path, km: &KeyMaterial, data: &VaultData, m_kib: u32, iter: u32, par: u32) -> Result<(), VaultError> {
    let plaintext = serde_json::to_vec(data).map_err(|_| VaultError::Corrupted)?;
    let (nonce, ciphertext) = encrypt(&km.key, &plaintext)?;
    let file = VaultFile {
        version: FORMAT_VERSION,
        kdf_m_kib: m_kib,
        kdf_iter: iter,
        kdf_par: par,
        salt: BASE64.encode(&km.salt),
        nonce: BASE64.encode(&nonce),
        ciphertext: BASE64.encode(&ciphertext),
    };
    let json = serde_json::to_vec(&file).map_err(|_| VaultError::Corrupted)?;
    atomic_write(path, &json)
}

pub fn exists(path: &Path) -> bool {
    path.is_file()
}

pub fn create(path: &Path, password: &str, data: &VaultData) -> Result<KeyMaterial, VaultError> {
    rekey(path, password, data)
}

pub fn rekey(path: &Path, password: &str, data: &VaultData) -> Result<KeyMaterial, VaultError> {
    if password.chars().count() < MIN_PASSWORD_LEN {
        return Err(VaultError::WeakPassword);
    }
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let key = derive_key(password, &salt, KDF_M_KIB, KDF_ITER, KDF_PAR)?;
    let km = KeyMaterial { salt, key };
    write_file(path, &km, data, KDF_M_KIB, KDF_ITER, KDF_PAR)?;
    Ok(km)
}

pub fn unlock(path: &Path, password: &str) -> Result<(KeyMaterial, VaultData), VaultError> {
    let raw = fs::read(path)?;
    unlock_content(&raw, password)
}

pub fn unlock_content(raw: &[u8], password: &str) -> Result<(KeyMaterial, VaultData), VaultError> {
    let file: VaultFile = serde_json::from_slice(raw).map_err(|_| VaultError::Corrupted)?;
    if file.version != FORMAT_VERSION {
        return Err(VaultError::Corrupted);
    }
    if file.kdf_iter < KDF_ITER || file.kdf_m_kib < KDF_M_KIB || file.kdf_par < 1 {
        return Err(VaultError::Corrupted);
    }
    let salt_arr: [u8; SALT_LEN] = BASE64
        .decode(file.salt.as_bytes())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(VaultError::Corrupted)?;
    let nonce = BASE64
        .decode(file.nonce.as_bytes())
        .map_err(|_| VaultError::Corrupted)?;
    let ciphertext = BASE64
        .decode(file.ciphertext.as_bytes())
        .map_err(|_| VaultError::Corrupted)?;
    let key = derive_key(password, &salt_arr, file.kdf_m_kib, file.kdf_iter, file.kdf_par)?;
    let mut plaintext = decrypt(&key, &nonce, &ciphertext)?;
    let data: VaultData = serde_json::from_slice(&plaintext).map_err(|_| VaultError::Corrupted)?;
    plaintext.zeroize();
    Ok((KeyMaterial { salt: salt_arr, key }, data))
}

pub fn save(path: &Path, km: &KeyMaterial, data: &VaultData) -> Result<(), VaultError> {
    write_file(path, km, data, KDF_M_KIB, KDF_ITER, KDF_PAR)
}

pub fn export_backup(path: &Path, km: &KeyMaterial, data: &VaultData) -> Result<(), VaultError> {
    write_file(path, km, data, KDF_M_KIB, KDF_ITER, KDF_PAR)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> VaultData {
        VaultData {
            accounts: vec![Account {
                id: "abc123".into(),
                issuer: "Example".into(),
                name: "alice@example.com".into(),
                secret: Zeroizing::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
                created_at: 1_700_000_000,
            }],
        }
    }

    #[test]
    fn roundtrip() {
        let dir = std::env::temp_dir().join(format!("totp-vault-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.dat");
        let data = sample_data();

        let km = create(&path, "correct horse battery", &data).unwrap();
        let (km2, loaded) = unlock(&path, "correct horse battery").unwrap();
        assert_eq!(loaded.accounts.len(), 1);
        assert_eq!(loaded.accounts[0].issuer, "Example");
        assert_eq!(*loaded.accounts[0].secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

        let mut changed = loaded.clone();
        changed.accounts[0].name = "new@example.com".into();
        save(&path, &km2, &changed).unwrap();
        let (_km3, reloaded) = unlock(&path, "correct horse battery").unwrap();
        assert_eq!(reloaded.accounts[0].name, "new@example.com");
        drop(km);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wrong_password_rejected() {
        let dir = std::env::temp_dir().join(format!("totp-vault-test2-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.dat");

        create(&path, "correct horse battery", &VaultData::default()).unwrap();
        assert_eq!(unlock(&path, "wrong password!!!!").unwrap_err(), VaultError::WrongPassword);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tampered_file_rejected() {
        let dir = std::env::temp_dir().join(format!("totp-vault-test3-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.dat");

        create(&path, "correct horse battery", &sample_data()).unwrap();
        let mut raw = fs::read(&path).unwrap();
        let last = raw.len() - 10;
        raw[last] ^= 0xff;
        fs::write(&path, &raw).unwrap();
        assert!(matches!(
            unlock(&path, "correct horse battery").unwrap_err(),
            VaultError::WrongPassword | VaultError::Corrupted
        ));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn weak_password_rejected() {
        let dir = std::env::temp_dir().join(format!("totp-vault-test4-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.dat");
        assert_eq!(create(&path, "short", &VaultData::default()).unwrap_err(), VaultError::WeakPassword);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn downgraded_kdf_rejected() {
        let dir = std::env::temp_dir().join(format!("totp-vault-test6-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.dat");
        create(&path, "correct horse battery", &VaultData::default()).unwrap();

        let mut raw = fs::read(&path).unwrap();
        let file: VaultFile = serde_json::from_slice(&raw).unwrap();
        let json = serde_json::json!({
            "version": file.version,
            "kdf_m_kib": 8,
            "kdf_iter": 1,
            "kdf_par": 1,
            "salt": file.salt,
            "nonce": file.nonce,
            "ciphertext": file.ciphertext,
        });
        raw = serde_json::to_vec(&json).unwrap();
        fs::write(&path, &raw).unwrap();

        assert_eq!(
            unlock(&path, "correct horse battery").unwrap_err(),
            VaultError::Corrupted
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rekey_changes_password() {
        let dir = std::env::temp_dir().join(format!("totp-vault-test5-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.dat");
        let data = sample_data();

        create(&path, "correct horse battery", &data).unwrap();
        let km = rekey(&path, "fresh zebra lantern", &data).unwrap();

        assert_eq!(unlock(&path, "correct horse battery").unwrap_err(), VaultError::WrongPassword);
        let (_km2, loaded) = unlock(&path, "fresh zebra lantern").unwrap();
        assert_eq!(loaded.accounts[0].issuer, "Example");

        save(&path, &km, &loaded).unwrap();
        let (_km3, reloaded) = unlock(&path, "fresh zebra lantern").unwrap();
        assert_eq!(reloaded.accounts[0].issuer, "Example");

        fs::remove_dir_all(&dir).unwrap();
    }
}
