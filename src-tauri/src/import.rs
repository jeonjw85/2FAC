use serde::Deserialize;
use serde_json::Value;

use crate::otpauth;
use crate::totp::Algorithm;
use crate::vault::{self, KeyMaterial, VaultData, VaultError};

#[derive(Debug)]
pub struct ParsedEntry {
    pub issuer: String,
    pub name: String,
    pub secret: String,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ImportError {
    PasswordRequired,
    WrongPassword,
    Unrecognized,
    NoValidEntries,
}

#[derive(Debug)]
pub enum Parsed {
    OwnVault(KeyMaterial, VaultData),
    Entries {
        format: &'static str,
        entries: Vec<ParsedEntry>,
        skipped: usize,
    },
}

#[derive(Deserialize)]
struct AegisFile {
    db: AegisDb,
}

#[derive(Deserialize)]
struct AegisDb {
    entries: Vec<AegisEntry>,
}

#[derive(Deserialize)]
struct AegisEntry {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    name: String,
    info: Option<AegisInfo>,
}

#[derive(Deserialize)]
struct AegisInfo {
    secret: Option<String>,
    algo: Option<String>,
    digits: Option<u32>,
    period: Option<u32>,
}

#[derive(Deserialize)]
struct AndOtpEntry {
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    label: String,
    secret: String,
    algorithm: Option<String>,
    digits: Option<u32>,
    period: Option<u32>,
}

fn valid_ranges(digits: u32, period: u32) -> bool {
    (4..=9).contains(&digits) && (5..=600).contains(&period)
}

fn parse_algorithm_opt(value: Option<&str>) -> Result<Algorithm, ImportError> {
    match value {
        Some(s) => Algorithm::parse(s).ok_or(ImportError::NoValidEntries),
        None => Ok(Algorithm::Sha1),
    }
}

fn parse_aegis(bytes: &[u8]) -> Result<Parsed, ImportError> {
    let file: AegisFile = serde_json::from_slice(bytes).map_err(|_| ImportError::Unrecognized)?;
    let mut entries = Vec::new();
    let mut skipped = 0;
    for entry in file.db.entries {
        if entry.kind != "totp" {
            continue;
        }
        let parsed = entry.info.as_ref().and_then(|info| {
            let secret = info.secret.as_ref()?.clone();
            let algorithm = parse_algorithm_opt(info.algo.as_deref()).ok()?;
            let digits = info.digits.unwrap_or(6);
            let period = info.period.unwrap_or(30);
            if !valid_ranges(digits, period) {
                return None;
            }
            Some(ParsedEntry {
                issuer: entry.issuer.clone(),
                name: entry.name.clone(),
                secret,
                algorithm,
                digits,
                period,
            })
        });
        match parsed {
            Some(p) => entries.push(p),
            None => skipped += 1,
        }
    }
    if entries.is_empty() {
        return Err(ImportError::NoValidEntries);
    }
    Ok(Parsed::Entries {
        format: "Aegis export",
        entries,
        skipped,
    })
}

fn parse_andotp(bytes: &[u8]) -> Result<Parsed, ImportError> {
    let items: Vec<AndOtpEntry> =
        serde_json::from_slice(bytes).map_err(|_| ImportError::Unrecognized)?;
    let mut entries = Vec::new();
    let mut skipped = 0;
    for entry in items {
        let parsed = (|| {
            if entry.secret.trim().is_empty() {
                return None;
            }
            let (issuer, name) = if entry.issuer.trim().is_empty() {
                match entry.label.split_once(':') {
                    Some((issuer, name)) => (issuer.trim().to_string(), name.trim().to_string()),
                    None => (String::new(), entry.label.trim().to_string()),
                }
            } else {
                let issuer = entry.issuer.trim().to_string();
                let label = entry.label.trim();
                let name = label
                    .strip_prefix(issuer.as_str())
                    .and_then(|rest| rest.strip_prefix(':'))
                    .unwrap_or(label)
                    .trim()
                    .to_string();
                (issuer, name)
            };
            if issuer.is_empty() && name.is_empty() {
                return None;
            }
            let algorithm = parse_algorithm_opt(entry.algorithm.as_deref()).ok()?;
            let digits = entry.digits.unwrap_or(6);
            let period = entry.period.unwrap_or(30);
            if !valid_ranges(digits, period) {
                return None;
            }
            Some(ParsedEntry {
                issuer,
                name,
                secret: entry.secret.clone(),
                algorithm,
                digits,
                period,
            })
        })();
        match parsed {
            Some(p) => entries.push(p),
            None => skipped += 1,
        }
    }
    if entries.is_empty() {
        return Err(ImportError::NoValidEntries);
    }
    Ok(Parsed::Entries {
        format: "andOTP export",
        entries,
        skipped,
    })
}

fn parse_uri_list(bytes: &[u8]) -> Result<Parsed, ImportError> {
    let text = std::str::from_utf8(bytes).map_err(|_| ImportError::Unrecognized)?;
    let mut entries = Vec::new();
    let mut skipped = 0;
    let mut saw_uri = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with("otpauth://") {
            return Err(ImportError::Unrecognized);
        }
        saw_uri = true;
        match otpauth::parse(line) {
            Ok(p) => entries.push(ParsedEntry {
                issuer: p.issuer,
                name: p.account,
                secret: p.secret,
                algorithm: p.algorithm,
                digits: p.digits,
                period: p.period,
            }),
            Err(_) => skipped += 1,
        }
    }
    if !saw_uri {
        return Err(ImportError::Unrecognized);
    }
    if entries.is_empty() {
        return Err(ImportError::NoValidEntries);
    }
    Ok(Parsed::Entries {
        format: "otpauth URI list",
        entries,
        skipped,
    })
}

pub fn parse(bytes: &[u8], password: Option<&str>) -> Result<Parsed, ImportError> {
    if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
        if let Some(obj) = value.as_object() {
            if obj.contains_key("version") && obj.contains_key("salt") && obj.contains_key("ciphertext")
            {
                let password = password.ok_or(ImportError::PasswordRequired)?;
                let (km, data) =
                    vault::unlock_content(bytes, password).map_err(|e| match e {
                        VaultError::WrongPassword => ImportError::WrongPassword,
                        _ => ImportError::Unrecognized,
                    })?;
                return Ok(Parsed::OwnVault(km, data));
            }
            if obj.contains_key("db") {
                return parse_aegis(bytes);
            }
            return Err(ImportError::Unrecognized);
        }
        if value.is_array() {
            return parse_andotp(bytes);
        }
        return Err(ImportError::Unrecognized);
    }
    parse_uri_list(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn parses_uri_list() {
        let text = format!(
            "otpauth://totp/Example:alice@example.com?secret={SECRET}&issuer=Example\n\notpauth://totp/bob?secret={SECRET}\n"
        );
        match parse(text.as_bytes(), None).unwrap() {
            Parsed::Entries {
                format,
                entries,
                skipped,
            } => {
                assert_eq!(format, "otpauth URI list");
                assert_eq!(entries.len(), 2);
                assert_eq!(skipped, 0);
                assert_eq!(entries[0].issuer, "Example");
                assert_eq!(entries[0].name, "alice@example.com");
                assert_eq!(entries[1].name, "bob");
            }
            Parsed::OwnVault(_, _) => panic!("expected entries"),
        }
    }

    #[test]
    fn parses_andotp() {
        let json = format!(
            r#"[{{"secret":"{SECRET}","issuer":"Example","label":"Example:alice@example.com","digits":6,"period":30,"algorithm":"SHA1"}},{{"secret":"{SECRET}","issuer":"","label":"bob","digits":6,"period":30,"algorithm":"SHA1"}}]"#
        );
        match parse(json.as_bytes(), None).unwrap() {
            Parsed::Entries {
                format, entries, ..
            } => {
                assert_eq!(format, "andOTP export");
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].issuer, "Example");
                assert_eq!(entries[0].name, "alice@example.com");
                assert_eq!(entries[1].issuer, "");
                assert_eq!(entries[1].name, "bob");
            }
            Parsed::OwnVault(_, _) => panic!("expected entries"),
        }
    }

    #[test]
    fn parses_aegis() {
        let json = format!(
            r#"{{"version":1,"header":null,"db":{{"version":1,"entries":[{{"type":"totp","uuid":"x","name":"alice@example.com","issuer":"Example","note":"","info":{{"secret":"{SECRET}","algo":"SHA1","digits":6,"period":30}}}}]}}}}"#
        );
        match parse(json.as_bytes(), None).unwrap() {
            Parsed::Entries {
                format, entries, ..
            } => {
                assert_eq!(format, "Aegis export");
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].issuer, "Example");
            }
            Parsed::OwnVault(_, _) => panic!("expected entries"),
        }
    }

    #[test]
    fn own_vault_password_flow() {
        let dir = std::env::temp_dir().join(format!("totp-import-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.dat");
        vault::create(&path, "correct horse battery", &VaultData::default()).unwrap();
        let bytes = std::fs::read(&path).unwrap();

        assert_eq!(parse(&bytes, None).unwrap_err(), ImportError::PasswordRequired);
        assert_eq!(
            parse(&bytes, Some("wrong password!!!!")).unwrap_err(),
            ImportError::WrongPassword
        );
        assert!(matches!(
            parse(&bytes, Some("correct horse battery")).unwrap(),
            Parsed::OwnVault(_, _)
        ));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rejects_unknown() {
        assert_eq!(parse(b"hello world", None).unwrap_err(), ImportError::Unrecognized);
        assert_eq!(parse(b"{\"foo\": 1}", None).unwrap_err(), ImportError::Unrecognized);
        assert_eq!(parse(&[0xff, 0xfe, 0xfd], None).unwrap_err(), ImportError::Unrecognized);
    }
}
