use data_encoding::{BASE32, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA512")]
    Sha512,
}

impl Algorithm {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" => Some(Self::Sha1),
            "SHA256" => Some(Self::Sha256),
            "SHA512" => Some(Self::Sha512),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct TotpError;

pub fn decode_secret(input: &str) -> Result<Vec<u8>, TotpError> {
    let clean: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if clean.is_empty() || clean.chars().any(|c| c == '=') {
        let stripped: String = clean.chars().filter(|c| *c != '=').collect();
        if stripped.is_empty() {
            return Err(TotpError);
        }
        return decode_secret(&stripped);
    }
    if let Ok(v) = BASE32.decode(clean.as_bytes()) {
        if v.is_empty() {
            return Err(TotpError);
        }
        return Ok(v);
    }
    if let Ok(v) = BASE32_NOPAD.decode(clean.as_bytes()) {
        if v.is_empty() {
            return Err(TotpError);
        }
        return Ok(v);
    }
    let rem = clean.len() % 8;
    if rem != 0 {
        let padded = format!("{}{}", clean, "=".repeat(8 - rem));
        if let Ok(v) = BASE32.decode(padded.as_bytes()) {
            if !v.is_empty() {
                return Ok(v);
            }
        }
    }
    Err(TotpError)
}

pub fn canonical_secret(secret: &[u8]) -> String {
    BASE32_NOPAD.encode(secret)
}

fn hmac_digest(algorithm: Algorithm, key: &[u8], counter: u64) -> Result<Vec<u8>, TotpError> {
    let msg = counter.to_be_bytes();
    let out = match algorithm {
        Algorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(key).map_err(|_| TotpError)?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| TotpError)?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(key).map_err(|_| TotpError)?;
            mac.update(&msg);
            mac.finalize().into_bytes().to_vec()
        }
    };
    Ok(out)
}

pub fn generate(
    secret: &[u8],
    algorithm: Algorithm,
    digits: u32,
    period: u32,
    unix_time: u64,
) -> Result<String, TotpError> {
    if !(4..=9).contains(&digits) || period == 0 || secret.is_empty() {
        return Err(TotpError);
    }
    let counter = unix_time / u64::from(period);
    let mut digest = hmac_digest(algorithm, secret, counter)?;
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin_code = (((digest[offset] & 0x7f) as u32) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    digest.zeroize();
    let modulus = 10u32.pow(digits);
    Ok(format!("{:0width$}", bin_code % modulus, width = digits as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    #[test]
    fn rfc6238_sha1_vectors() {
        let key = secret("12345678901234567890");
        assert_eq!(generate(&key, Algorithm::Sha1, 8, 30, 59).unwrap(), "94287082");
        assert_eq!(generate(&key, Algorithm::Sha1, 8, 30, 1111111109).unwrap(), "07081804");
        assert_eq!(generate(&key, Algorithm::Sha1, 8, 30, 1111111111).unwrap(), "14050471");
        assert_eq!(generate(&key, Algorithm::Sha1, 8, 30, 1234567890).unwrap(), "89005924");
        assert_eq!(generate(&key, Algorithm::Sha1, 8, 30, 2000000000).unwrap(), "69279037");
        assert_eq!(generate(&key, Algorithm::Sha1, 8, 30, 20000000000).unwrap(), "65353130");
    }

    #[test]
    fn rfc6238_sha256_vectors() {
        let key = secret("12345678901234567890123456789012");
        assert_eq!(generate(&key, Algorithm::Sha256, 8, 30, 59).unwrap(), "46119246");
        assert_eq!(generate(&key, Algorithm::Sha256, 8, 30, 20000000000).unwrap(), "77737706");
    }

    #[test]
    fn rfc6238_sha512_vectors() {
        let key = secret("1234567890123456789012345678901234567890123456789012345678901234");
        assert_eq!(generate(&key, Algorithm::Sha512, 8, 30, 59).unwrap(), "90693936");
        assert_eq!(generate(&key, Algorithm::Sha512, 8, 30, 20000000000).unwrap(), "47863826");
    }

    #[test]
    fn six_digit_padding() {
        let key = secret("12345678901234567890");
        let code = generate(&key, Algorithm::Sha1, 6, 30, 59).unwrap();
        assert_eq!(code.len(), 6);
        assert_eq!(code, "287082");
    }

    #[test]
    fn decode_secret_variants() {
        let raw = decode_secret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(raw, b"12345678901234567890");
        let b32 = canonical_secret(&raw);
        assert_eq!(decode_secret(&b32).unwrap(), raw);
        let spaced: String = b32
            .chars()
            .enumerate()
            .flat_map(|(i, c)| if i % 4 == 0 && i > 0 { vec![' ', c] } else { vec![c] })
            .collect();
        assert_eq!(decode_secret(&spaced.to_lowercase()).unwrap(), raw);
        assert!(decode_secret("").is_err());
        assert!(decode_secret("0189").is_err());
    }
}
