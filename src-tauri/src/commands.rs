use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::HEXLOWER;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use crate::gauth;
use crate::import;
use crate::otpauth::{self, OtpAuthError};
use crate::totp::{self, Algorithm, TotpError};
use crate::vault::{self, Account, KeyMaterial, VaultData, VaultError};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Vault is locked")]
    Locked,
    #[error("Vault already initialized")]
    AlreadyInitialized,
    #[error("Vault not initialized")]
    NotInitialized,
    #[error("Password is too short (minimum 8 characters)")]
    WeakPassword,
    #[error("Wrong password")]
    WrongPassword,
    #[error("Vault file is corrupted")]
    Corrupted,
    #[error("Invalid base32 secret")]
    InvalidSecret,
    #[error("Invalid otpauth URI")]
    InvalidUri,
    #[error("Account not found")]
    NotFound,
    #[error("Invalid account data")]
    InvalidAccount,
    #[error("Storage error")]
    Io,
}

impl From<VaultError> for Error {
    fn from(e: VaultError) -> Self {
        match e {
            VaultError::WrongPassword => Error::WrongPassword,
            VaultError::WeakPassword => Error::WeakPassword,
            VaultError::Corrupted => Error::Corrupted,
            VaultError::Io(_) => Error::Io,
        }
    }
}

impl From<TotpError> for Error {
    fn from(_: TotpError) -> Self {
        Error::InvalidSecret
    }
}

impl From<OtpAuthError> for Error {
    fn from(_: OtpAuthError) -> Self {
        Error::InvalidUri
    }
}

#[derive(Serialize)]
pub struct Status {
    pub initialized: bool,
    pub unlocked: bool,
}

#[derive(Serialize, Clone)]
pub struct AccountMeta {
    pub id: String,
    pub issuer: String,
    pub name: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32,
    pub created_at: u64,
}

#[derive(Serialize)]
pub struct CodeInfo {
    pub code: String,
    pub remaining: u64,
    pub period: u32,
}

struct Session {
    km: KeyMaterial,
    data: VaultData,
}

struct Inner {
    vault_path: PathBuf,
    session: Option<Session>,
}

pub struct AppState {
    inner: Mutex<Inner>,
}

impl AppState {
    pub fn new(vault_path: PathBuf) -> Self {
        Self {
            inner: Mutex::new(Inner {
                vault_path,
                session: None,
            }),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Inner>, String> {
        self.inner.lock().map_err(|_| "Internal error".to_string())
    }

    pub fn lock_now(&self) -> Result<(), String> {
        let mut inner = self.lock()?;
        inner.session = None;
        Ok(())
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn new_id() -> String {
    let mut bytes = [0u8; 8];
    OsRng.fill_bytes(&mut bytes);
    HEXLOWER.encode(&bytes)
}

fn meta(account: &Account) -> AccountMeta {
    AccountMeta {
        id: account.id.clone(),
        issuer: account.issuer.clone(),
        name: account.name.clone(),
        algorithm: account.algorithm.as_str().to_string(),
        digits: account.digits,
        period: account.period,
        created_at: account.created_at,
    }
}

fn validate_fields(name: &str, digits: u32, period: u32) -> Result<(), Error> {
    if name.trim().is_empty() {
        return Err(Error::InvalidAccount);
    }
    if !(4..=9).contains(&digits) || !(5..=600).contains(&period) {
        return Err(Error::InvalidAccount);
    }
    Ok(())
}

fn parse_algorithm(s: &str) -> Result<Algorithm, Error> {
    Algorithm::parse(s).ok_or(Error::InvalidAccount)
}

fn persist(vault_path: &std::path::Path, session: &Session) -> Result<(), Error> {
    vault::save(vault_path, &session.km, &session.data)?;
    Ok(())
}

#[tauri::command]
pub fn status(state: tauri::State<'_, AppState>) -> Result<Status, String> {
    let inner = state.lock()?;
    Ok(Status {
        initialized: vault::exists(&inner.vault_path),
        unlocked: inner.session.is_some(),
    })
}

#[tauri::command]
pub fn setup(state: tauri::State<'_, AppState>, password: String) -> Result<(), String> {
    let password = zeroize::Zeroizing::new(password);
    let mut inner = state.lock()?;
    if vault::exists(&inner.vault_path) {
        return Err(Error::AlreadyInitialized.to_string());
    }
    let km = vault::create(&inner.vault_path, &password, &VaultData::default())
        .map_err(Error::from)
        .map_err(|e| e.to_string())?;
    inner.session = Some(Session {
        km,
        data: VaultData::default(),
    });
    Ok(())
}

#[tauri::command]
pub fn unlock(state: tauri::State<'_, AppState>, password: String) -> Result<(), String> {
    let password = zeroize::Zeroizing::new(password);
    let mut inner = state.lock()?;
    if inner.session.is_some() {
        return Ok(());
    }
    if !vault::exists(&inner.vault_path) {
        return Err(Error::NotInitialized.to_string());
    }
    let (km, data) = vault::unlock(&inner.vault_path, &password)
        .map_err(Error::from)
        .map_err(|e| e.to_string())?;
    inner.session = Some(Session { km, data });
    Ok(())
}

#[tauri::command]
pub fn lock(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let mut inner = state.lock()?;
    inner.session = None;
    Ok(())
}

#[tauri::command]
pub fn change_password(
    state: tauri::State<'_, AppState>,
    current: String,
    new: String,
) -> Result<(), String> {
    let current = Zeroizing::new(current);
    let new = Zeroizing::new(new);
    let mut inner = state.lock()?;
    let vault_path = inner.vault_path.clone();
    let session = inner.session.as_mut().ok_or_else(|| Error::Locked.to_string())?;
    vault::unlock(&vault_path, &current)
        .map_err(Error::from)
        .map_err(|e| e.to_string())?;
    let km = vault::rekey(&vault_path, &new, &session.data)
        .map_err(Error::from)
        .map_err(|e| e.to_string())?;
    session.km = km;
    Ok(())
}

#[tauri::command]
pub fn list_accounts(state: tauri::State<'_, AppState>) -> Result<Vec<AccountMeta>, String> {
    let inner = state.lock()?;
    let session = inner.session.as_ref().ok_or_else(|| Error::Locked.to_string())?;
    Ok(session.data.accounts.iter().map(meta).collect())
}

#[tauri::command]
pub fn add_account(
    state: tauri::State<'_, AppState>,
    issuer: String,
    name: String,
    secret: String,
    algorithm: String,
    digits: u32,
    period: u32,
) -> Result<AccountMeta, String> {
    let secret = zeroize::Zeroizing::new(secret);
    let mut inner = state.lock()?;
    let vault_path = inner.vault_path.clone();
    let session = inner.session.as_mut().ok_or_else(|| Error::Locked.to_string())?;
    validate_fields(&name, digits, period).map_err(|e| e.to_string())?;
    let algorithm = parse_algorithm(&algorithm).map_err(|e| e.to_string())?;
    let mut key_bytes = totp::decode_secret(&secret).map_err(|_| Error::InvalidSecret.to_string())?;
    let canonical = totp::canonical_secret(&key_bytes);
    key_bytes.zeroize();
    let account = Account {
        id: new_id(),
        issuer: issuer.trim().to_string(),
        name: name.trim().to_string(),
        secret: zeroize::Zeroizing::new(canonical),
        algorithm,
        digits,
        period,
        created_at: now_unix(),
    };
    let m = meta(&account);
    session.data.accounts.push(account);
    persist(&vault_path, session).map_err(|e| e.to_string())?;
    Ok(m)
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub fn update_account(
    state: tauri::State<'_, AppState>,
    id: String,
    issuer: String,
    name: String,
    algorithm: String,
    digits: u32,
    period: u32,
    secret: Option<String>,
) -> Result<AccountMeta, String> {
    let secret = secret.map(zeroize::Zeroizing::new);
    let mut inner = state.lock()?;
    let vault_path = inner.vault_path.clone();
    let session = inner.session.as_mut().ok_or_else(|| Error::Locked.to_string())?;
    validate_fields(&name, digits, period).map_err(|e| e.to_string())?;
    let algorithm = parse_algorithm(&algorithm).map_err(|e| e.to_string())?;
    let account = session
        .data
        .accounts
        .iter_mut()
        .find(|a| a.id == id)
        .ok_or_else(|| Error::NotFound.to_string())?;
    if let Some(new_secret) = secret {
        if !new_secret.trim().is_empty() {
            let mut key_bytes =
                totp::decode_secret(&new_secret).map_err(|_| Error::InvalidSecret.to_string())?;
            *account.secret = totp::canonical_secret(&key_bytes);
            key_bytes.zeroize();
        }
    }
    account.issuer = issuer.trim().to_string();
    account.name = name.trim().to_string();
    account.algorithm = algorithm;
    account.digits = digits;
    account.period = period;
    let m = meta(account);
    persist(&vault_path, session).map_err(|e| e.to_string())?;
    Ok(m)
}

#[tauri::command]
pub fn delete_account(state: tauri::State<'_, AppState>, id: String) -> Result<(), String> {
    let mut inner = state.lock()?;
    let vault_path = inner.vault_path.clone();
    let session = inner.session.as_mut().ok_or_else(|| Error::Locked.to_string())?;
    let before = session.data.accounts.len();
    session.data.accounts.retain(|a| a.id != id);
    if session.data.accounts.len() == before {
        return Err(Error::NotFound.to_string());
    }
    persist(&vault_path, session).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub fn get_code(state: tauri::State<'_, AppState>, id: String) -> Result<CodeInfo, String> {
    let inner = state.lock()?;
    let session = inner.session.as_ref().ok_or_else(|| Error::Locked.to_string())?;
    let account = session
        .data
        .accounts
        .iter()
        .find(|a| a.id == id)
        .ok_or_else(|| Error::NotFound.to_string())?;
    let mut key_bytes = totp::decode_secret(&account.secret).map_err(|_| Error::InvalidSecret.to_string())?;
    let now = now_unix();
    let code = totp::generate(&key_bytes, account.algorithm, account.digits, account.period, now)
        .map_err(|_| Error::InvalidSecret.to_string())?;
    key_bytes.zeroize();
    let remaining = account.period as u64 - (now % account.period as u64);
    Ok(CodeInfo {
        code,
        remaining,
        period: account.period,
    })
}

#[tauri::command]
pub fn export_backup(state: tauri::State<'_, AppState>, path: String) -> Result<(), String> {
    let inner = state.lock()?;
    let session = inner.session.as_ref().ok_or_else(|| Error::Locked.to_string())?;
    let dest = PathBuf::from(path);
    vault::export_backup(&dest, &session.km, &session.data)
        .map_err(Error::from)
        .map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct ImportSummary {
    pub format: String,
    pub imported: usize,
    pub skipped: usize,
    pub replaced: bool,
    pub batch_index: Option<u32>,
    pub batch_size: Option<u32>,
}

fn import_error_str(e: import::ImportError) -> String {
    match e {
        import::ImportError::PasswordRequired => "PASSWORD_REQUIRED".to_string(),
        import::ImportError::WrongPassword => Error::WrongPassword.to_string(),
        import::ImportError::Unrecognized => "Unrecognized file format".to_string(),
        import::ImportError::NoValidEntries => "No valid accounts found".to_string(),
    }
}

fn merge_entries(
    session: &mut Session,
    entries: Vec<import::ParsedEntry>,
    mut skipped: usize,
) -> (usize, usize) {
    let mut seen: HashSet<(String, String, String)> = session
        .data
        .accounts
        .iter()
        .map(|a| {
            (
                a.issuer.to_lowercase(),
                a.name.to_lowercase(),
                a.secret.to_string(),
            )
        })
        .collect();
    let mut imported = 0;
    for entry in entries {
        let mut key_bytes = match totp::decode_secret(&entry.secret) {
            Ok(b) => b,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let canonical = totp::canonical_secret(&key_bytes);
        key_bytes.zeroize();
        let name = if entry.name.trim().is_empty() {
            entry.issuer.clone()
        } else {
            entry.name
        };
        let key = (
            entry.issuer.to_lowercase(),
            name.to_lowercase(),
            canonical.clone(),
        );
        if !seen.insert(key) {
            skipped += 1;
            continue;
        }
        session.data.accounts.push(Account {
            id: new_id(),
            issuer: entry.issuer,
            name,
            secret: Zeroizing::new(canonical),
            algorithm: entry.algorithm,
            digits: entry.digits,
            period: entry.period,
            created_at: now_unix(),
        });
        imported += 1;
    }
    (imported, skipped)
}

#[tauri::command]
pub fn import_uri(state: tauri::State<'_, AppState>, uri: String) -> Result<ImportSummary, String> {
    let uri = uri.trim().to_string();
    let (format, entries, initial_skipped, batch_index, batch_size) =
        if uri.starts_with("otpauth-migration://") {
            let batch = gauth::parse_migration_uri(&uri).map_err(|e| match e {
                import::ImportError::Unrecognized => "Could not parse this code".to_string(),
                other => import_error_str(other),
            })?;
            (
                "Google Authenticator export",
                batch.entries,
                batch.skipped,
                batch.batch_index,
                batch.batch_size,
            )
        } else {
            let parsed = otpauth::parse(&uri).map_err(|_| Error::InvalidUri.to_string())?;
            (
                "otpauth URI",
                vec![import::ParsedEntry {
                    issuer: parsed.issuer,
                    name: parsed.account,
                    secret: parsed.secret,
                    algorithm: parsed.algorithm,
                    digits: parsed.digits,
                    period: parsed.period,
                }],
                0,
                None,
                None,
            )
        };
    let mut inner = state.lock()?;
    let vault_path = inner.vault_path.clone();
    let session = inner.session.as_mut().ok_or_else(|| Error::Locked.to_string())?;
    let (imported, skipped) = merge_entries(session, entries, initial_skipped);
    if imported > 0 {
        persist(&vault_path, session).map_err(|e| e.to_string())?;
    }
    Ok(ImportSummary {
        format: format.to_string(),
        imported,
        skipped,
        replaced: false,
        batch_index,
        batch_size,
    })
}

#[tauri::command]
pub fn import_file(
    state: tauri::State<'_, AppState>,
    path: String,
    password: Option<String>,
) -> Result<ImportSummary, String> {
    let password = password.map(Zeroizing::new);
    let mut inner = state.lock()?;
    let vault_path = inner.vault_path.clone();
    let session = inner.session.as_mut().ok_or_else(|| Error::Locked.to_string())?;
    let mut bytes = std::fs::read(&path).map_err(|_| "Could not read file".to_string())?;
    let parsed = match import::parse(&bytes, password.as_deref().map(String::as_str)) {
        Ok(p) => p,
        Err(e) => {
            bytes.zeroize();
            return Err(import_error_str(e));
        }
    };
    bytes.zeroize();

    let summary = match parsed {
        import::Parsed::OwnVault(_km, data) => {
            let imported = data.accounts.len();
            session.data = data;
            ImportSummary {
                format: "2fac backup".to_string(),
                imported,
                skipped: 0,
                replaced: true,
                batch_index: None,
                batch_size: None,
            }
        }
        import::Parsed::Entries {
            format,
            entries,
            skipped,
        } => {
            let (imported, skipped) = merge_entries(session, entries, skipped);
            ImportSummary {
                format: format.to_string(),
                imported,
                skipped,
                replaced: false,
                batch_index: None,
                batch_size: None,
            }
        }
    };

    if summary.imported > 0 || summary.replaced {
        persist(&vault_path, session).map_err(|e| e.to_string())?;
    }
    Ok(summary)
}
