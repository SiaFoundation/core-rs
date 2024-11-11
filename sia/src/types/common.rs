use core::fmt;

use blake2b_simd::Params;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::encoding::{
    self, SiaDecodable, SiaDecode, SiaEncodable, SiaEncode, V1SiaDecodable, V1SiaDecode,
    V1SiaEncodable, V1SiaEncode,
};
use crate::types::currency::Currency;
use crate::types::{v1, v2};

/// Helper module for base64 serialization
pub(crate) mod base64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let base64 = STANDARD.encode(v);
        s.serialize_str(&base64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        STANDARD
            .decode(base64.as_bytes())
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

// First, create a module for the base64 serialization
pub(crate) mod vec_base64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(v: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: Vec<String> = v.iter().map(|bytes| STANDARD.encode(bytes)).collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: Vec<String> = Vec::deserialize(deserializer)?;
        encoded
            .into_iter()
            .map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

// Macro to implement types used as identifiers which are 32 byte hashes and are
// serialized with a prefix
#[macro_export]
macro_rules! ImplHashID {
    ($name:ident) => {
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            $crate::encoding::SiaEncode,
            $crate::encoding::SiaDecode,
            $crate::encoding::V1SiaEncode,
            $crate::encoding::V1SiaDecode,
        )]
        pub struct $name([u8; 32]);

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if serializer.is_human_readable() {
                    String::serialize(&self.to_string(), serializer)
                } else {
                    <[u8; 32]>::serialize(&self.0, serializer)
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                $name::parse_string(&s).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
            }
        }

        impl $name {
            pub const fn new(b: [u8; 32]) -> Self {
                Self(b)
            }

            // Example method that might be used in serialization/deserialization
            pub fn parse_string(s: &str) -> Result<Self, $crate::types::HexParseError> {
                let s = match s.split_once(':') {
                    Some((_prefix, suffix)) => suffix,
                    None => s,
                };

                if s.len() != 64 {
                    return Err($crate::types::HexParseError::InvalidLength);
                }

                let mut data = [0u8; 32];
                hex::decode_to_slice(s, &mut data)
                    .map_err($crate::types::HexParseError::HexError)?;
                Ok($name(data))
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{}", hex::encode(self.0))
            }
        }

        impl From<blake2b_simd::Hash> for $name {
            fn from(hash: blake2b_simd::Hash) -> Self {
                let mut h = [0; 32];
                h.copy_from_slice(&hash.as_bytes()[..32]);
                Self(h)
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(data: [u8; 32]) -> Self {
                $name(data)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(hash: $name) -> [u8; 32] {
                hash.0
            }
        }

        impl AsRef<[u8; 32]> for $name {
            fn as_ref(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name([0; 32])
            }
        }
    };
}

ImplHashID!(Hash256);
ImplHashID!(BlockID);
ImplHashID!(SiacoinOutputID);
ImplHashID!(SiafundOutputID);
ImplHashID!(FileContractID);
ImplHashID!(TransactionID);
ImplHashID!(AttestationID);

#[derive(Debug, PartialEq, SiaEncode, SiaDecode, Serialize, Deserialize)]

pub struct ChainIndex {
    pub height: u64,
    pub id: BlockID,
}

impl fmt::Display for ChainIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.height, hex::encode(self.id))
    }
}

/// A Block is a collection of transactions
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    pub parent_id: BlockID,
    pub nonce: u64,
    pub timestamp: OffsetDateTime,
    pub miner_payouts: Vec<SiacoinOutput>,
    pub transactions: Vec<v1::Transaction>,

    pub v2: Option<v2::BlockData>,
}

impl V1SiaEncodable for Block {
    fn encode_v1<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.parent_id.encode(w)?;
        self.nonce.encode(w)?;
        self.timestamp.encode(w)?;
        self.miner_payouts.encode_v1(w)?;
        self.transactions.encode_v1(w)
    }
}

impl V1SiaDecodable for Block {
    fn decode_v1<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        Ok(Block {
            parent_id: BlockID::decode(r)?,
            nonce: u64::decode(r)?,
            timestamp: OffsetDateTime::decode(r)?,
            miner_payouts: Vec::<SiacoinOutput>::decode_v1(r)?,
            transactions: Vec::<v1::Transaction>::decode_v1(r)?,
            v2: None,
        })
    }
}

impl SiaEncodable for Block {
    fn encode<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        self.parent_id.encode(w)?;
        self.nonce.encode(w)?;
        self.timestamp.encode(w)?;
        self.miner_payouts.encode_v1(w)?;
        self.transactions.encode_v1(w)?;
        self.v2.encode(w)
    }
}

impl SiaDecodable for Block {
    fn decode<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        Ok(Block {
            parent_id: BlockID::decode(r)?,
            nonce: u64::decode(r)?,
            timestamp: OffsetDateTime::decode(r)?,
            miner_payouts: Vec::<SiacoinOutput>::decode_v1(r)?,
            transactions: Vec::<v1::Transaction>::decode_v1(r)?,
            v2: Option::<v2::BlockData>::decode(r)?,
        })
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

/// An address that can be used to receive UTXOs
#[derive(Default, Debug, PartialEq, Clone, SiaEncode, V1SiaEncode, SiaDecode, V1SiaDecode)]
pub struct Address([u8; 32]);

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Address::parse_string(&s).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl Address {
    pub(crate) const fn new(addr: [u8; 32]) -> Address {
        Address(addr)
    }

    pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
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

impl From<[u8; 32]> for Address {
    fn from(val: [u8; 32]) -> Self {
        Address(val)
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
        write!(f, "{}", hex::encode(buf))
    }
}

/// A SiacoinOutput is a Siacoin UTXO that can be spent using the unlock conditions
/// for Address
#[derive(
    Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, V1SiaEncode, V1SiaDecode,
)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinOutput {
    pub value: Currency,
    pub address: Address,
}

/// A SiafundOutput is a Siafund UTXO that can be spent using the unlock conditions
/// for Address
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct SiafundOutput {
    pub value: u64,
    pub address: Address,
}

impl V1SiaEncodable for SiafundOutput {
    fn encode_v1<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        Currency::new(self.value as u128).encode_v1(w)?;
        self.address.encode_v1(w)?;
        Currency::new(0).encode_v1(w) // siad encodes a "claim start," but its an error if it's non-zero.
    }
}

impl V1SiaDecodable for SiafundOutput {
    fn decode_v1<R: std::io::Read>(r: &mut R) -> encoding::Result<Self> {
        let se = SiafundOutput {
            value: Currency::decode_v1(r)?
                .try_into()
                .map_err(|_| encoding::Error::Custom("invalid value".to_string()))?,
            address: Address::decode_v1(r)?,
        };
        Currency::decode_v1(r)?; // ignore claim start
        Ok(se)
    }
}

/// A Leaf is a 64-byte piece of data that is stored in a Merkle tree.
#[derive(Debug, PartialEq, Clone, SiaEncode, V1SiaEncode, SiaDecode, V1SiaDecode)]
pub struct Leaf([u8; 64]);

impl From<[u8; 64]> for Leaf {
    fn from(data: [u8; 64]) -> Self {
        Leaf(data)
    }
}

impl fmt::Display for Leaf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Serialize for Leaf {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        String::serialize(&self.to_string(), serializer)
    }
}

impl<'de> Deserialize<'de> for Leaf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let data = hex::decode(s).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))?;
        if data.len() != 64 {
            return Err(serde::de::Error::custom("invalid length"));
        }
        Ok(Leaf(data.try_into().unwrap()))
    }
}

/// A StateElement is a generic element within the state accumulator.
#[derive(Debug, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct StateElement {
    pub leaf_index: u64,
    pub merkle_proof: Vec<Hash256>,
}

/// address is a helper macro to create an Address from a string literal.
/// The string literal must be a valid 76-character hex-encoded string.
/// This is not exported outside of the crate because the address checksum
/// is not validated, it is assumed to be correct.
macro_rules! address {
    ($text:expr) => {{
        const fn decode_hex_char(c: u8) -> Option<u8> {
            match c {
                b'0'..=b'9' => Some(c - b'0'),
                b'a'..=b'f' => Some(c - b'a' + 10),
                b'A'..=b'F' => Some(c - b'A' + 10),
                _ => None,
            }
        }

        const fn decode_hex_pair(hi: u8, lo: u8) -> Option<u8> {
            let hi = decode_hex_char(hi);
            let lo = decode_hex_char(lo);
            match ((hi, lo)) {
                (Some(hi), Some(lo)) => Some(hi << 4 | lo),
                _ => None,
            }
        }

        let src = $text.as_bytes();
        let len = src.len();
        assert!(len == 76, "invalid address length");
        let mut data = [0u8; 32];
        let mut i = 0;
        while i < 64 {
            let pair = decode_hex_pair(src[i], src[i + 1]);
            match pair {
                Some(byte) => data[i / 2] = byte,
                None => assert!(false, "invalid hex character"),
            }
            i += 2;
        }
        Address::new(data)
    }};
}
pub(crate) use address;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_macro() {
        const ADDRESS: &str =
            "5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9e758b4f79b34";
        let s = address!(ADDRESS);
        assert_eq!(s.to_string(), ADDRESS);
    }

    #[test]
    fn test_serialize_hash256() {
        let hash_str = "9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6";
        let hash = Hash256(hex::decode(hash_str).unwrap().try_into().unwrap());

        // binary
        let mut hash_serialized: Vec<u8> = Vec::new();
        hash.encode(&mut hash_serialized).unwrap();
        assert_eq!(hash_serialized, hex::decode(hash_str).unwrap());
        let hash_deserialized = Hash256::decode(&mut &hash_serialized[..]).unwrap();
        assert_eq!(hash_deserialized, hash); // deserialize

        // json
        let hash_serialized = serde_json::to_string(&hash).unwrap();
        let hash_deserialized: Hash256 = serde_json::from_str(&hash_serialized).unwrap();
        assert_eq!(hash_serialized, format!("\"{0}\"", hash_str)); // serialize
        assert_eq!(hash_deserialized, hash); // deserialize
    }

    #[test]
    fn test_serialize_address() {
        let addr_str = "8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c";
        let checksum = "df32abee86f0";
        let address = Address(hex::decode(addr_str).unwrap().try_into().unwrap());

        // binary
        let mut addr_serialized: Vec<u8> = Vec::new();
        address.encode(&mut addr_serialized).unwrap();
        assert_eq!(addr_serialized, hex::decode(addr_str).unwrap()); // serialize
        let addr_deserialized = Address::decode(&mut &addr_serialized[..]).unwrap();
        assert_eq!(addr_deserialized, address); // deserialize

        // json
        let addr_serialized = serde_json::to_string(&address).unwrap();
        let addr_deserialized: Address = serde_json::from_str(&addr_serialized).unwrap();
        assert_eq!(addr_serialized, format!("\"{0}{1}\"", addr_str, checksum)); // serialize
        assert_eq!(addr_deserialized, address); // deserialize
    }
}
