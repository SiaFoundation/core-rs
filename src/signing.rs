use core::fmt;
use std::time::SystemTime;

use crate::{ChainIndex, Hash256, HexParseError};
use ed25519_dalek::{Signature as ED25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// An ed25519 public key that can be used to verify a signature
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct PublicKey([u8; 32]);

impl Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            String::serialize(&self.to_string(), serializer)
        } else {
            <[u8; 32]>::serialize(&self.0, serializer)
        }
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let mut pk = [0; 32];
            hex::decode_to_slice(s, &mut pk)
                .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))?;
            Ok(Self::new(pk))
        } else {
            Ok(PublicKey(<[u8; 32]>::deserialize(deserializer)?))
        }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        hex::encode(self.0).fmt(f)
    }
}

impl PublicKey {
    pub fn new(buf: [u8; 32]) -> Self {
        PublicKey(buf)
    }

    pub fn verify(&self, msg: &[u8], signature: &Signature) -> bool {
        let pk = VerifyingKey::from_bytes(&self.0).unwrap();
        pk.verify(msg, &ED25519Signature::from_bytes(signature.as_ref()))
            .is_ok()
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// An ed25519 private key that can be used to sign a hash
#[derive(Debug, PartialEq, Clone)]
pub struct PrivateKey([u8; 64]);

impl PrivateKey {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(seed);
        PrivateKey(sk.to_keypair_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&self.0[32..]);
        PublicKey::new(buf)
    }

    pub fn sign(&self, buf: &[u8]) -> Signature {
        let sk = SigningKey::from_bytes(&self.0[..32].try_into().unwrap());
        Signature::new(sk.sign(buf).to_bytes())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Hash256> for PrivateKey {
    fn from(hash: Hash256) -> Self {
        PrivateKey::from_seed(hash.as_array())
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        // Zero out the private key
        for byte in self.0.iter_mut() {
            *byte = 0;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            String::serialize(&self.to_string(), serializer)
        } else {
            <[u8]>::serialize(&self.0, serializer) // prefixed with length
        }
    }
}

impl Signature {
    pub fn new(sig: [u8; 64]) -> Self {
        Signature(sig)
    }

    pub fn data(&self) -> &[u8] {
        &self.0
    }

    pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
        let s = match s.split_once(':') {
            Some((_prefix, suffix)) => suffix,
            None => s,
        };

        let data = hex::decode(s).map_err(HexParseError::HexError)?;
        if data.len() != 64 {
            return Err(HexParseError::InvalidLength);
        }

        let mut sig = [0u8; 64];
        sig.copy_from_slice(&data);
        Ok(Signature(sig))
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature([0; 64])
    }
}

impl AsRef<[u8; 64]> for Signature {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "sig:{}", hex::encode(self.0))
    }
}
#[derive(Default, Debug)]
pub struct NetworkHardforks {
    pub asic_height: u64,

    pub foundation_height: u64,

    pub v2_allow_height: u64,
    pub v2_require_height: u64,
}

pub struct SigningState {
    pub index: ChainIndex,
    pub median_timestamp: SystemTime,
    pub hardforks: NetworkHardforks,
}

impl SigningState {
    pub fn new(
        index: ChainIndex,
        median_timestamp: SystemTime,
        hardforks: NetworkHardforks,
    ) -> Self {
        SigningState {
            index,
            median_timestamp,
            hardforks,
        }
    }

    pub fn replay_prefix(&self) -> &[u8] {
        if self.index.height >= self.hardforks.v2_allow_height {
            return &[2];
        } else if self.index.height >= self.hardforks.foundation_height {
            return &[1];
        } else if self.index.height >= self.hardforks.asic_height {
            return &[0];
        }
        &[]
    }
}

#[cfg(test)]
mod tests {
    use crate::encoding::{from_reader, to_bytes};

    use super::*;

    #[test]
    fn test_serialize_publickey() {
        let public_key_str = "9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6";
        let public_key = PublicKey::new(hex::decode(public_key_str).unwrap().try_into().unwrap());

        // binary
        let public_key_serialized = to_bytes(&public_key).unwrap();
        let public_key_deserialized: PublicKey =
            from_reader(&mut &public_key_serialized[..]).unwrap();
        assert_eq!(public_key_serialized, hex::decode(public_key_str).unwrap());
        assert_eq!(public_key_deserialized, public_key);

        // json
        let public_key_serialized = serde_json::to_string(&public_key).unwrap();
        let public_key_deserialized: PublicKey =
            serde_json::from_str(&public_key_serialized).unwrap();
        assert_eq!(public_key_serialized, format!("\"{0}\"", public_key_str));
        assert_eq!(public_key_deserialized, public_key);
    }

    #[test]
    fn test_json_serialize_signature() {
        assert_eq!(
            serde_json::to_string(
                &Signature::parse_string(
                    "sig:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b69aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6"
                )
                .unwrap()
            )
            .unwrap(),
            "\"sig:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b69aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\""
        );
    }
}
