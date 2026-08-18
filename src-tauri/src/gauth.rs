use data_encoding::BASE64;

use crate::import::{ImportError, ParsedEntry};
use crate::otpauth;
use crate::totp::Algorithm;

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn eof(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_varint(&mut self) -> Result<u64, ImportError> {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            if self.eof() {
                return Err(ImportError::Unrecognized);
            }
            let b = self.buf[self.pos];
            self.pos += 1;
            result |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                return Err(ImportError::Unrecognized);
            }
        }
    }

    fn read_tag(&mut self) -> Result<(u32, u32), ImportError> {
        let v = self.read_varint()?;
        Ok(((v >> 3) as u32, (v & 0x7) as u32))
    }

    fn read_bytes(&mut self) -> Result<&'a [u8], ImportError> {
        let len = self.read_varint()? as usize;
        let end = self.pos.checked_add(len).ok_or(ImportError::Unrecognized)?;
        if end > self.buf.len() {
            return Err(ImportError::Unrecognized);
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn skip_field(&mut self, wire: u32) -> Result<(), ImportError> {
        match wire {
            0 => {
                self.read_varint()?;
            }
            1 => {
                let end = self.pos.checked_add(8).ok_or(ImportError::Unrecognized)?;
                if end > self.buf.len() {
                    return Err(ImportError::Unrecognized);
                }
                self.pos = end;
            }
            2 => {
                self.read_bytes()?;
            }
            5 => {
                let end = self.pos.checked_add(4).ok_or(ImportError::Unrecognized)?;
                if end > self.buf.len() {
                    return Err(ImportError::Unrecognized);
                }
                self.pos = end;
            }
            _ => return Err(ImportError::Unrecognized),
        }
        Ok(())
    }
}

fn algorithm_from(raw: u64) -> Option<Algorithm> {
    match raw {
        0 | 1 => Some(Algorithm::Sha1),
        2 => Some(Algorithm::Sha256),
        3 => Some(Algorithm::Sha512),
        _ => None,
    }
}

fn digits_from(raw: u64) -> u32 {
    match raw {
        2 => 8,
        _ => 6,
    }
}

fn parse_otp_parameters(buf: &[u8]) -> Result<Option<ParsedEntry>, ImportError> {
    let mut r = Reader::new(buf);
    let mut secret: Option<Vec<u8>> = None;
    let mut name = String::new();
    let mut issuer = String::new();
    let mut algorithm_raw = 1u64;
    let mut digits_raw = 1u64;
    let mut otp_type = 2u64;

    while !r.eof() {
        let (field, wire) = r.read_tag()?;
        match (field, wire) {
            (1, 2) => secret = Some(r.read_bytes()?.to_vec()),
            (2, 2) => name = String::from_utf8_lossy(r.read_bytes()?).into_owned(),
            (3, 2) => issuer = String::from_utf8_lossy(r.read_bytes()?).into_owned(),
            (4, 0) => algorithm_raw = r.read_varint()?,
            (5, 0) => digits_raw = r.read_varint()?,
            (6, 0) => otp_type = r.read_varint()?,
            _ => r.skip_field(wire)?,
        }
    }

    if otp_type != 2 {
        return Ok(None);
    }
    let secret = match secret {
        Some(s) if !s.is_empty() => s,
        _ => return Ok(None),
    };
    let algorithm = match algorithm_from(algorithm_raw) {
        Some(a) => a,
        None => return Ok(None),
    };

    let (issuer, name) = if issuer.trim().is_empty() {
        match name.split_once(':') {
            Some((i, n)) => (i.trim().to_string(), n.trim().to_string()),
            None => (String::new(), name.trim().to_string()),
        }
    } else {
        let issuer = issuer.trim().to_string();
        let label = name.trim();
        let name = label
            .strip_prefix(issuer.as_str())
            .and_then(|rest| rest.strip_prefix(':'))
            .unwrap_or(label)
            .trim()
            .to_string();
        (issuer, name)
    };
    if issuer.is_empty() && name.is_empty() {
        return Ok(None);
    }

    Ok(Some(ParsedEntry {
        issuer,
        name,
        secret: crate::totp::canonical_secret(&secret),
        algorithm,
        digits: digits_from(digits_raw),
        period: 30,
    }))
}

#[derive(Debug)]
pub struct MigrationBatch {
    pub entries: Vec<ParsedEntry>,
    pub skipped: usize,
    pub batch_index: Option<u32>,
    pub batch_size: Option<u32>,
}

pub fn parse_migration_payload(buf: &[u8]) -> Result<MigrationBatch, ImportError> {
    let mut r = Reader::new(buf);
    let mut entries = Vec::new();
    let mut skipped = 0;
    let mut batch_index: Option<u32> = None;
    let mut batch_size: Option<u32> = None;
    while !r.eof() {
        let (field, wire) = r.read_tag()?;
        match (field, wire) {
            (1, 2) => {
                let param = r.read_bytes()?;
                match parse_otp_parameters(param)? {
                    Some(entry) => entries.push(entry),
                    None => skipped += 1,
                }
            }
            (3, 0) => batch_size = Some(r.read_varint()? as u32),
            (4, 0) => batch_index = Some(r.read_varint()? as u32),
            _ => r.skip_field(wire)?,
        }
    }
    if entries.is_empty() {
        return Err(ImportError::NoValidEntries);
    }
    Ok(MigrationBatch {
        entries,
        skipped,
        batch_index,
        batch_size,
    })
}

fn decode_b64(input: &str) -> Result<Vec<u8>, ImportError> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let padded = match cleaned.len() % 4 {
        2 => format!("{cleaned}=="),
        3 => format!("{cleaned}="),
        _ => cleaned,
    };
    BASE64
        .decode(padded.as_bytes())
        .map_err(|_| ImportError::Unrecognized)
}

pub fn parse_migration_uri(uri: &str) -> Result<MigrationBatch, ImportError> {
    let rest = uri
        .trim()
        .strip_prefix("otpauth-migration://")
        .ok_or(ImportError::Unrecognized)?;
    let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
    let mut data: Option<String> = None;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("data=") {
            data = Some(value.to_string());
        }
    }
    let data = data.ok_or(ImportError::Unrecognized)?;

    let decoded = decode_b64(&data)
        .or_else(|_| decode_b64(&otpauth::percent_decode(&data).unwrap_or(data.clone())))?;
    parse_migration_payload(&decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                return;
            }
        }
    }

    fn tag(field: u64, wire: u64, out: &mut Vec<u8>) {
        varint((field << 3) | wire, out);
    }

    fn bytes_field(field: u64, data: &[u8], out: &mut Vec<u8>) {
        tag(field, 2, out);
        varint(data.len() as u64, out);
        out.extend_from_slice(data);
    }

    fn varint_field(field: u64, v: u64, out: &mut Vec<u8>) {
        tag(field, 0, out);
        varint(v, out);
    }

    fn otp_param(secret: &[u8], name: &str, issuer: &str, algo: u64, digits: u64) -> Vec<u8> {
        let mut p = Vec::new();
        bytes_field(1, secret, &mut p);
        bytes_field(2, name.as_bytes(), &mut p);
        if !issuer.is_empty() {
            bytes_field(3, issuer.as_bytes(), &mut p);
        }
        varint_field(4, algo, &mut p);
        varint_field(5, digits, &mut p);
        varint_field(6, 2, &mut p);
        p
    }

    #[test]
    fn parses_migration_payload() {
        let mut payload = Vec::new();
        let p1 = otp_param(b"\x12\x34\x56", "alice@example.com", "Example", 1, 1);
        bytes_field(1, &p1, &mut payload);
        let p2 = otp_param(b"\xab\xcd", "bob", "", 2, 2);
        bytes_field(1, &p2, &mut payload);
        varint_field(2, 1, &mut payload);
        varint_field(3, 3, &mut payload);
        varint_field(4, 0, &mut payload);

        let batch = parse_migration_payload(&payload).unwrap();
        assert_eq!(batch.entries.len(), 2);
        assert_eq!(batch.entries[0].issuer, "Example");
        assert_eq!(batch.entries[0].name, "alice@example.com");
        assert_eq!(batch.entries[0].digits, 6);
        assert_eq!(batch.entries[1].issuer, "");
        assert_eq!(batch.entries[1].name, "bob");
        assert_eq!(batch.entries[1].digits, 8);
        assert_eq!(batch.entries[1].algorithm, Algorithm::Sha256);
        assert_eq!(batch.batch_size, Some(3));
        assert_eq!(batch.batch_index, Some(0));
        assert_eq!(batch.skipped, 0);
    }

    #[test]
    fn skips_hotp_and_md5() {
        let mut payload = Vec::new();
        let mut hotp = Vec::new();
        bytes_field(1, b"\x11", &mut hotp);
        bytes_field(2, b"hotp-acct", &mut hotp);
        varint_field(6, 1, &mut hotp);
        bytes_field(1, &hotp, &mut payload);

        let mut md5 = Vec::new();
        bytes_field(1, b"\x22", &mut md5);
        bytes_field(2, b"md5-acct", &mut md5);
        varint_field(4, 4, &mut md5);
        varint_field(6, 2, &mut md5);
        bytes_field(1, &md5, &mut payload);

        assert_eq!(
            parse_migration_payload(&payload).unwrap_err(),
            ImportError::NoValidEntries
        );
    }

    #[test]
    fn parses_migration_uri() {
        let mut payload = Vec::new();
        let p1 = otp_param(b"\x12\x34\x56", "alice", "Example", 1, 1);
        bytes_field(1, &p1, &mut payload);
        varint_field(2, 1, &mut payload);
        let b64 = BASE64.encode(&payload);
        let uri = format!("otpauth-migration://offline?data={b64}");
        let batch = parse_migration_uri(&uri).unwrap();
        assert_eq!(batch.entries.len(), 1);
        assert_eq!(batch.entries[0].name, "alice");
    }
}
