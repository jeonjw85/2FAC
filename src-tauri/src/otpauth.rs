use crate::totp::Algorithm;

#[derive(Debug, PartialEq, Eq)]
pub enum OtpAuthError {
    InvalidFormat,
    InvalidEncoding,
    MissingSecret,
    MissingAccount,
    InvalidAlgorithm,
    InvalidDigits,
    InvalidPeriod,
}

#[derive(Debug, PartialEq, Eq)]
pub struct OtpAuth {
    pub issuer: String,
    pub account: String,
    pub secret: String,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u32,
}

pub fn percent_decode(input: &str) -> Result<String, OtpAuthError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(OtpAuthError::InvalidEncoding);
                }
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3])
                    .map_err(|_| OtpAuthError::InvalidEncoding)?;
                out.push(u8::from_str_radix(hex, 16).map_err(|_| OtpAuthError::InvalidEncoding)?);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| OtpAuthError::InvalidEncoding)
}

pub fn parse(uri: &str) -> Result<OtpAuth, OtpAuthError> {
    let rest = uri
        .trim()
        .strip_prefix("otpauth://totp/")
        .ok_or(OtpAuthError::InvalidFormat)?;
    let (label_raw, query) = rest.split_once('?').ok_or(OtpAuthError::InvalidFormat)?;
    let label = percent_decode(label_raw)?;
    let (label_issuer, account) = match label.split_once(':') {
        Some((issuer, account)) => (issuer.trim().to_string(), account.trim().to_string()),
        None => (String::new(), label.trim().to_string()),
    };
    if account.is_empty() {
        return Err(OtpAuthError::MissingAccount);
    }

    let mut secret = None;
    let mut query_issuer = None;
    let mut algorithm = Algorithm::Sha1;
    let mut digits = 6u32;
    let mut period = 30u32;

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value)?;
        match key {
            "secret" => {
                if value.is_empty() {
                    return Err(OtpAuthError::MissingSecret);
                }
                secret = Some(value);
            }
            "issuer" => query_issuer = Some(value),
            "algorithm" => {
                algorithm = Algorithm::parse(&value).ok_or(OtpAuthError::InvalidAlgorithm)?
            }
            "digits" => {
                let d: u32 = value.parse().map_err(|_| OtpAuthError::InvalidDigits)?;
                if !(4..=9).contains(&d) {
                    return Err(OtpAuthError::InvalidDigits);
                }
                digits = d;
            }
            "period" => {
                let p: u32 = value.parse().map_err(|_| OtpAuthError::InvalidPeriod)?;
                if !(5..=600).contains(&p) {
                    return Err(OtpAuthError::InvalidPeriod);
                }
                period = p;
            }
            _ => {}
        }
    }

    let secret = secret.ok_or(OtpAuthError::MissingSecret)?;
    let issuer = if label_issuer.is_empty() {
        query_issuer.unwrap_or_default()
    } else {
        label_issuer
    };

    Ok(OtpAuth {
        issuer,
        account,
        secret,
        algorithm,
        digits,
        period,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_uri() {
        let uri = "otpauth://totp/Example:alice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA256&digits=8&period=60";
        let parsed = parse(uri).unwrap();
        assert_eq!(parsed.issuer, "Example");
        assert_eq!(parsed.account, "alice@example.com");
        assert_eq!(parsed.secret, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(parsed.algorithm, Algorithm::Sha256);
        assert_eq!(parsed.digits, 8);
        assert_eq!(parsed.period, 60);
    }

    #[test]
    fn parse_defaults_and_query_issuer() {
        let uri = "otpauth://totp/bob?secret=GEZDGNBVGY3TQOJQ&issuer=Acme";
        let parsed = parse(uri).unwrap();
        assert_eq!(parsed.issuer, "Acme");
        assert_eq!(parsed.account, "bob");
        assert_eq!(parsed.algorithm, Algorithm::Sha1);
        assert_eq!(parsed.digits, 6);
        assert_eq!(parsed.period, 30);
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(parse("https://example.com").unwrap_err(), OtpAuthError::InvalidFormat);
        assert_eq!(parse("otpauth://hotp/x?secret=AA").unwrap_err(), OtpAuthError::InvalidFormat);
        assert_eq!(parse("otpauth://totp/x?issuer=y").unwrap_err(), OtpAuthError::MissingSecret);
        assert_eq!(
            parse("otpauth://totp/x?secret=AA&digits=12").unwrap_err(),
            OtpAuthError::InvalidDigits
        );
        assert_eq!(
            parse("otpauth://totp/x?secret=AA&period=1").unwrap_err(),
            OtpAuthError::InvalidPeriod
        );
        assert_eq!(
            parse("otpauth://totp/x?secret=AA&algorithm=MD5").unwrap_err(),
            OtpAuthError::InvalidAlgorithm
        );
        assert_eq!(parse("otpauth://totp/?secret=AA").unwrap_err(), OtpAuthError::MissingAccount);
    }
}
