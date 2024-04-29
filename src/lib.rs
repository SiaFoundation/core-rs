use core::fmt;
use std::io::{Error, Write};

pub trait SiaEncodable {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), Error>;
}

pub mod address;
pub mod consensus;
pub mod currency;
pub mod encoding;
pub mod seed;
pub mod signing;
pub mod specifier;
pub mod spendpolicy;
pub mod transactions;

pub(crate) mod blake2b;

pub use address::*;
pub use consensus::*;
pub use currency::*;
pub use seed::*;
use serde::Serialize;
pub use signing::*;
pub use spendpolicy::*;
pub use transactions::*;

/// encapsulates the various errors that can occur when parsing a Sia object
/// from a string
#[derive(Debug, PartialEq)]
pub enum HexParseError {
    MissingPrefix,
    InvalidLength,
    InvalidPrefix,
    InvalidChecksum, // not every object has a checksum
    HexError(hex::FromHexError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Hash256([u8; 32]);

impl Serialize for Hash256 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl Hash256 {
    pub fn new(data: [u8; 32]) -> Self {
        Hash256(data)
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
        let s = match s.split_once(':') {
            Some((_prefix, suffix)) => suffix,
            None => s,
        };

        if s.len() != 64 {
            return Err(HexParseError::InvalidLength);
        }

        let mut data = [0u8; 32];
        hex::decode_to_slice(s, &mut data).map_err(HexParseError::HexError)?;
        Ok(Hash256(data))
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "h:{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for Hash256 {
    fn from(value: &[u8]) -> Self {
        let mut h = [0; 32];
        h.copy_from_slice(value);
        Self(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_serialize_hash256() {
        let hash = Hash256::parse_string(
            "h:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6",
        )
        .unwrap();
        assert_eq!(
            serde_json::to_string(&hash).unwrap(),
            "\"h:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\""
        );
    }
}
