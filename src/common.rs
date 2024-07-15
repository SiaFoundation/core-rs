use blake2b_simd::{Hash, Params};
use core::fmt;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub struct ChainIndex {
    pub height: u64,
    pub id: [u8; 32],
}

impl fmt::Display for ChainIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.height, hex::encode(self.id))
    }
}

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
            String::serialize(&self.to_string(), serializer)
        } else {
            <[u8; 32]>::serialize(&self.0, serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Hash256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Hash256::parse_string(&s).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
        } else {
            let data = <[u8; 32]>::deserialize(deserializer)?;
            Ok(Hash256(data))
        }
    }
}

impl Hash256 {
    pub fn new(data: [u8; 32]) -> Self {
        Hash256(data)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn as_array(&self) -> &[u8; 32] {
        &self.0
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

impl From<Hash> for Hash256 {
    fn from(hash: Hash) -> Self {
        let mut h = [0; 32];
        h.copy_from_slice(&hash.as_bytes()[..32]);
        Self(h)
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// An address that can be used to receive UTXOs
#[derive(Debug, PartialEq, Clone)]
pub struct Address([u8; 32]);

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Address::parse_string(&s).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
        } else {
            let data = <[u8; 32]>::deserialize(deserializer)?;
            Ok(Address(data))
        }
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl Address {
    pub fn new(addr: [u8; 32]) -> Address {
        Address(addr)
    }

    pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
        let s = match s.split_once(':') {
            Some((_prefix, suffix)) => suffix,
            None => s,
        };

        if s.len() != 76 {
            return Err(HexParseError::InvalidLength);
        }

        let mut data = [0u8; 38];
        hex::decode_to_slice(s, &mut data).map_err(HexParseError::HexError)?;

        let h = Params::new()
            .hash_length(32)
            .to_state()
            .update(&data[..32])
            .finalize();
        let checksum = h.as_bytes();

        if checksum[..6] != data[32..] {
            return Err(HexParseError::InvalidChecksum);
        }

        Ok(data[..32].into())
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for Address {
    fn from(val: &[u8]) -> Self {
        let mut data = [0u8; 32];
        data.copy_from_slice(val);
        Address(data)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = [0u8; 32 + 6];
        buf[..32].copy_from_slice(&self.0);

        let h = Params::new()
            .hash_length(32)
            .to_state()
            .update(&self.0)
            .finalize();

        buf[32..].copy_from_slice(&h.as_bytes()[..6]);
        write!(f, "addr:{}", hex::encode(buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{from_reader, to_bytes};

    #[test]
    fn test_serialize_hash256() {
        let hash_str = "9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6";
        let hash = Hash256(hex::decode(hash_str).unwrap().try_into().unwrap());

        // binary
        let hash_serialized = to_bytes(&hash).unwrap();
        let hash_deserialized: Hash256 = from_reader(&mut &hash_serialized[..]).unwrap();
        assert_eq!(hash_serialized, hex::decode(hash_str).unwrap()); // serialize
        assert_eq!(hash_deserialized, hash); // deserialize

        // json
        let hash_serialized = serde_json::to_string(&hash).unwrap();
        let hash_deserialized: Hash256 = serde_json::from_str(&hash_serialized).unwrap();
        assert_eq!(hash_serialized, format!("\"h:{0}\"", hash_str)); // serialize
        assert_eq!(hash_deserialized, hash); // deserialize
    }

    #[test]
    fn test_serialize_address() {
        let addr_str = "8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c";
        let checksum = "df32abee86f0";
        let address = Address(hex::decode(addr_str).unwrap().try_into().unwrap());

        // binary
        let addr_serialized = to_bytes(&address).unwrap();
        let addr_deserialized: Address = from_reader(&mut &addr_serialized[..]).unwrap();
        assert_eq!(addr_serialized, hex::decode(addr_str).unwrap()); // serialize
        assert_eq!(addr_deserialized, address); // deserialize

        // json
        let addr_serialized = serde_json::to_string(&address).unwrap();
        let addr_deserialized: Address = serde_json::from_str(&addr_serialized).unwrap();
        assert_eq!(
            addr_serialized,
            format!("\"addr:{0}{1}\"", addr_str, checksum)
        ); // serialize
        assert_eq!(addr_deserialized, address); // deserialize
    }
}
