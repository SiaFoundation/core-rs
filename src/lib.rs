use core::fmt;

pub trait SiaEncodable {
    fn encode(&self, buf: &mut Vec<u8>);
}

pub mod address;
pub mod consensus;
pub mod currency;
pub mod encoding;
pub mod seed;
pub mod signing;
pub mod specifier;
pub mod transactions;

pub(crate) mod blake2b;

pub use address::*;
pub use consensus::*;
pub use currency::*;
pub use seed::*;
pub use signing::*;
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

impl Hash256 {
    pub fn from_slice(data: [u8; 32]) -> Self {
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

impl SiaEncodable for Hash256 {
    fn encode(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}
