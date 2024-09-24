use core::fmt;
use std::time::SystemTime;

use crate::{ChainIndex, Hash256, HexParseError};
use base64::prelude::*;
use ed25519_dalek::{Signature as ED25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{de::Error, Deserialize, Serialize};

/// An ed25519 public key that can be used to verify a signature
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    const PREFIX: &'static str = "ed25519:";
}

impl Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            String::serialize(
                &format!("{}{}", Self::PREFIX, &self.to_string()),
                serializer,
            )
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
            let s = s.strip_prefix(Self::PREFIX).ok_or(Error::custom(format!(
                "key must have prefix '{}'",
                Self::PREFIX
            )))?;
            let mut pk = [0; 32];
            hex::decode_to_slice(s, &mut pk).map_err(|e| Error::custom(format!("{:?}", e)))?;
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

impl From<[u8; 64]> for PrivateKey {
    fn from(key: [u8; 64]) -> Self {
        PrivateKey(key)
    }
}

impl From<Hash256> for PrivateKey {
    fn from(hash: Hash256) -> Self {
        PrivateKey::from_seed(hash.as_ref())
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
            String::serialize(&BASE64_STANDARD.encode(self.0), serializer)
        } else {
            <[u8]>::serialize(&self.0, serializer) // prefixed with length
        }
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Signature, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let sig = BASE64_STANDARD
                .decode(s)
                .map_err(|e| D::Error::custom(format!("{:?}", e)))?;
            if sig.len() != 64 {
                return Err(D::Error::custom("Invalid signature length"));
            }
            Ok(Signature(sig.try_into().unwrap()))
        } else {
            let data = <Vec<u8>>::deserialize(deserializer)?;
            if data.len() != 64 {
                return Err(D::Error::custom("Invalid signature length"));
            }
            Ok(Signature(data.try_into().unwrap()))
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
    use std::vec;

    use crate::{
        encoding::{from_reader, to_bytes},
        transactions::{
            CoveredFields, FileContract, FileContractID, FileContractRevision, SiacoinInput,
            SiacoinOutput, SiafundInput, SiafundOutput, StorageProof, Transaction,
            TransactionSignature,
        },
        unlock_conditions::UnlockConditions,
        Address, Currency, Leaf,
    };

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
        assert_eq!(
            public_key_serialized,
            format!("\"ed25519:{0}\"", public_key_str)
        );
        assert_eq!(public_key_deserialized, public_key);
    }

    #[test]
    fn test_transaction_sign_verify() {
        let unsigned_transaction = Transaction {
            siacoin_inputs: vec![SiacoinInput {
                parent_id: Default::default(),
                unlock_conditions: UnlockConditions {
                    timelock: 0,
                    public_keys: vec![],
                    signatures_required: 0,
                },
            }],
            siacoin_outputs: vec![SiacoinOutput {
                value: Currency::new(0),
                address: Address::from([0u8; 32]),
            }],
            file_contracts: vec![FileContract {
                file_size: 0,
                file_merkle_root: Default::default(),
                window_start: 0,
                window_end: 0,
                payout: Currency::new(0),
                valid_proof_outputs: vec![],
                missed_proof_outputs: vec![],
                unlock_hash: Hash256::default(),
                revision_number: 0,
            }],
            file_contract_revisions: vec![FileContractRevision {
                unlock_conditions: UnlockConditions {
                    timelock: 0,
                    public_keys: vec![],
                    signatures_required: 0,
                },
                parent_id: Default::default(),
                revision_number: 0,
                file_size: 0,
                file_merkle_root: Default::default(),
                window_start: 0,
                window_end: 0,
                valid_proof_outputs: vec![],
                missed_proof_outputs: vec![],
                unlock_hash: Default::default(),
            }],
            storage_proofs: vec![StorageProof {
                parent_id: FileContractID::from([0u8; 32]),
                leaf: Leaf::from([0u8; 64]),
                proof: vec![],
            }],
            siafund_inputs: vec![SiafundInput {
                parent_id: Default::default(),
                unlock_conditions: UnlockConditions {
                    timelock: 0,
                    public_keys: vec![],
                    signatures_required: 0,
                },
                claim_address: Address::from([0u8; 32]),
            }],
            siafund_outputs: vec![SiafundOutput {
                value: Currency::new(0),
                address: Address::from([0u8; 32]),
                claim_start: Currency::new(0),
            }],
            miner_fees: vec![Currency::new(0)],
            arbitrary_data: vec![vec![1, 2, 3]],
            signatures: vec![TransactionSignature {
                parent_id: Default::default(),
                public_key_index: 0,
                timelock: 0,
                covered_fields: Default::default(),
                signature: Default::default(),
            }],
        };

        let key = PrivateKey::from([
            114, 152, 250, 154, 63, 214, 160, 97, 24, 74, 157, 172, 159, 191, 32, 141, 56, 178,
            117, 28, 166, 64, 121, 47, 18, 79, 248, 41, 232, 126, 231, 140, 94, 19, 124, 209, 145,
            85, 91, 26, 80, 172, 5, 203, 35, 91, 64, 126, 9, 173, 7, 54, 83, 206, 215, 33, 39, 150,
            60, 53, 203, 125, 192, 147,
        ]);

        let mut state = SigningState::new(
            ChainIndex {
                id: Default::default(),
                height: 1,
            },
            SystemTime::UNIX_EPOCH, // not relevant
            NetworkHardforks {
                asic_height: 10,
                foundation_height: 100,
                v2_allow_height: 1000,
                v2_require_height: 10000,
            },
        );

        // various test-cases for the individual hardfork heights
        struct TestCase {
            height: u64,
            whole_transaction: bool,
            signature: Signature,
        }
        let test_cases = [
            TestCase {
                height: 1,
                whole_transaction: true,
                signature: Signature([
                    234, 238, 234, 82, 152, 120, 252, 134, 26, 199, 122, 110, 100, 234, 63, 174,
                    163, 91, 8, 4, 246, 85, 241, 247, 166, 72, 109, 221, 91, 16, 83, 6, 33, 236,
                    123, 143, 220, 242, 58, 214, 111, 116, 5, 171, 35, 69, 214, 59, 87, 13, 56, 85,
                    84, 6, 147, 151, 116, 98, 170, 70, 97, 103, 199, 4,
                ]),
            },
            TestCase {
                height: 10,
                whole_transaction: true,
                signature: Signature([
                    80, 194, 168, 49, 197, 125, 113, 187, 180, 205, 217, 28, 80, 170, 17, 159, 117,
                    95, 245, 44, 133, 182, 149, 37, 77, 245, 228, 243, 251, 102, 25, 224, 181, 18,
                    13, 31, 180, 96, 209, 73, 214, 13, 21, 228, 255, 248, 29, 107, 5, 186, 71, 10,
                    176, 249, 214, 61, 188, 210, 216, 182, 75, 104, 129, 13,
                ]),
            },
            TestCase {
                height: 100,
                whole_transaction: true,
                signature: Signature([
                    237, 185, 228, 3, 94, 93, 25, 75, 28, 201, 74, 170, 19, 48, 133, 12, 239, 114,
                    143, 204, 146, 209, 29, 76, 12, 232, 214, 93, 122, 108, 232, 26, 218, 138, 57,
                    227, 223, 58, 0, 82, 238, 69, 44, 52, 164, 63, 43, 19, 33, 123, 86, 122, 116,
                    172, 10, 48, 238, 132, 227, 129, 133, 77, 148, 6,
                ]),
            },
            TestCase {
                height: 1000,
                whole_transaction: true,
                signature: Signature([
                    152, 254, 143, 177, 91, 215, 136, 166, 244, 60, 242, 79, 141, 227, 181, 117,
                    86, 224, 29, 102, 248, 125, 210, 100, 157, 127, 248, 193, 226, 212, 138, 0,
                    116, 104, 166, 150, 90, 149, 204, 211, 219, 144, 113, 40, 25, 126, 31, 14, 55,
                    115, 85, 147, 23, 109, 97, 12, 202, 133, 151, 23, 234, 194, 253, 5,
                ]),
            },
            TestCase {
                height: 10000,
                whole_transaction: true,
                signature: Signature([
                    152, 254, 143, 177, 91, 215, 136, 166, 244, 60, 242, 79, 141, 227, 181, 117,
                    86, 224, 29, 102, 248, 125, 210, 100, 157, 127, 248, 193, 226, 212, 138, 0,
                    116, 104, 166, 150, 90, 149, 204, 211, 219, 144, 113, 40, 25, 126, 31, 14, 55,
                    115, 85, 147, 23, 109, 97, 12, 202, 133, 151, 23, 234, 194, 253, 5,
                ]),
            },
            TestCase {
                height: 1,
                whole_transaction: false,
                signature: Signature([
                    181, 144, 210, 1, 156, 166, 8, 49, 142, 181, 56, 101, 211, 105, 252, 11, 201,
                    110, 98, 25, 71, 131, 107, 123, 234, 40, 142, 178, 115, 198, 205, 108, 60, 26,
                    9, 127, 170, 98, 99, 107, 25, 113, 138, 180, 229, 195, 37, 183, 36, 178, 210,
                    21, 98, 217, 114, 185, 112, 100, 170, 121, 104, 207, 182, 1,
                ]),
            },
            TestCase {
                height: 10,
                whole_transaction: false,
                signature: Signature([
                    136, 111, 242, 99, 13, 112, 234, 124, 181, 21, 23, 158, 192, 18, 187, 33, 149,
                    13, 192, 196, 133, 226, 125, 225, 116, 234, 56, 179, 135, 166, 182, 9, 44, 41,
                    122, 186, 233, 10, 113, 89, 3, 132, 97, 222, 23, 35, 106, 32, 233, 220, 194,
                    83, 58, 200, 141, 187, 33, 205, 178, 98, 147, 149, 253, 9,
                ]),
            },
            TestCase {
                height: 100,
                whole_transaction: false,
                signature: Signature([
                    172, 255, 46, 255, 7, 203, 157, 222, 3, 90, 1, 63, 126, 149, 142, 90, 159, 179,
                    94, 24, 159, 89, 48, 110, 9, 85, 249, 161, 129, 235, 104, 65, 116, 106, 139,
                    241, 96, 111, 111, 185, 55, 111, 170, 177, 133, 225, 68, 113, 143, 119, 243,
                    71, 130, 112, 179, 17, 20, 191, 89, 133, 69, 15, 137, 8,
                ]),
            },
            TestCase {
                height: 1000,
                whole_transaction: false,
                signature: Signature([
                    154, 185, 87, 199, 88, 179, 54, 250, 4, 244, 56, 175, 57, 117, 40, 183, 17,
                    139, 220, 120, 68, 57, 5, 235, 114, 61, 246, 246, 67, 158, 110, 232, 5, 255,
                    139, 236, 235, 76, 156, 218, 108, 110, 250, 96, 172, 78, 13, 143, 186, 221,
                    207, 49, 14, 156, 193, 27, 182, 239, 101, 152, 215, 249, 55, 8,
                ]),
            },
            TestCase {
                height: 10000,
                whole_transaction: false,
                signature: Signature([
                    154, 185, 87, 199, 88, 179, 54, 250, 4, 244, 56, 175, 57, 117, 40, 183, 17,
                    139, 220, 120, 68, 57, 5, 235, 114, 61, 246, 246, 67, 158, 110, 232, 5, 255,
                    139, 236, 235, 76, 156, 218, 108, 110, 250, 96, 172, 78, 13, 143, 186, 221,
                    207, 49, 14, 156, 193, 27, 182, 239, 101, 152, 215, 249, 55, 8,
                ]),
            },
        ];

        for tc in test_cases {
            // update state
            state.index.height = tc.height;

            // covered fields are either the whole transaction or all fields
            let covered_fields = if tc.whole_transaction {
                CoveredFields {
                    whole_transaction: true,
                    ..Default::default()
                }
            } else {
                CoveredFields {
                    whole_transaction: false,
                    siacoin_inputs: vec![0],
                    siacoin_outputs: vec![0],
                    file_contracts: vec![0],
                    file_contract_revisions: vec![0],
                    storage_proofs: vec![0],
                    siafund_inputs: vec![0],
                    siafund_outputs: vec![0],
                    miner_fees: vec![0],
                    arbitrary_data: vec![0],
                    signatures: vec![0],
                }
            };

            // sign and check signature
            let signature = unsigned_transaction
                .sign(&state, &covered_fields, Hash256::default(), 1, 100, &key)
                .unwrap();
            assert_eq!(signature.signature, tc.signature);

            // manually build the sig_hash and check the signature
            let sig_hash = if tc.whole_transaction {
                unsigned_transaction
                    .whole_sig_hash(&state, &Hash256::default(), 1, 100, &Vec::new())
                    .unwrap()
            } else {
                unsigned_transaction
                    .partial_sig_hash(&state, &covered_fields)
                    .unwrap()
            };
            assert!(key
                .public_key()
                .verify(sig_hash.as_ref(), &signature.signature));
        }
    }
}
