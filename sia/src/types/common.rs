use core::fmt;

use blake2b_simd::Params;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::encoding::{
    self, SiaDecodable, SiaDecode, SiaEncodable, SiaEncode, V1SiaDecodable, V1SiaDecode,
    V1SiaEncodable, V1SiaEncode,
};
use crate::types::currency::Currency;
use crate::types::{impl_hash_id, v1, v2};

impl_hash_id!(Hash256, hash_256);
impl_hash_id!(BlockID, block_id);
impl_hash_id!(SiacoinOutputID, siacoin_id);
impl_hash_id!(SiafundOutputID, siafund_id);
impl_hash_id!(FileContractID, contract_id);
impl_hash_id!(TransactionID, transaction_id);
impl_hash_id!(AttestationID, attestation_id);

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
    pub const fn new(addr: [u8; 32]) -> Address {
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

impl Leaf {
    pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
        if s.len() != 128 {
            return Err(HexParseError::InvalidLength);
        }

        let mut data = [0u8; 64];
        hex::decode_to_slice(s, &mut data).map_err(HexParseError::HexError)?;
        Ok(Leaf(data))
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::address;

    #[test]
    fn test_address_macro() {
        // 5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9e758b4f79b34
        const ADDRESS: &str =
            "5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9e758b4f79b34";
        let s = address!(
            "5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9e758b4f79b34"
        );
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
