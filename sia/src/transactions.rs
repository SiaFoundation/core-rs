use crate::encoding::{
    SiaDecodable, SiaDecode, SiaEncodable, SiaEncode, V1SiaDecodable, V1SiaDecode, V1SiaEncodable,
    V1SiaEncode,
};
use crate::signing::{PrivateKey, SigningState};
use crate::specifier::{specifier, Specifier};
use crate::unlock_conditions::UnlockConditions;
use crate::{encoding, Address, Currency, Hash256, Leaf};
use blake2b_simd::Params;
use serde::{Deserialize, Serialize};

pub type SiacoinOutputID = Hash256;
pub type SiafundOutputID = Hash256;
pub type FileContractID = Hash256;
pub type TransactionID = Hash256;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinInput {
    #[serde(rename = "parentID")]
    pub parent_id: SiacoinOutputID,
    pub unlock_conditions: UnlockConditions,
}

#[derive(
    Debug, Clone, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode, V1SiaEncode, V1SiaDecode,
)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinOutput {
    pub value: Currency,
    pub address: Address,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct SiafundInput {
    #[serde(rename = "parentID")]
    pub parent_id: SiafundOutputID,
    pub unlock_conditions: UnlockConditions,
    pub claim_address: Address,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct SiafundOutput {
    pub value: u64,
    pub address: Address,
}

impl V1SiaEncodable for SiafundOutput {
    fn encode_v1<W: std::io::Write>(&self, w: &mut W) -> encoding::Result<()> {
        Currency::new(self.value as u128).encode_v1(w)?;
        self.address.encode_v1(w)?;
        Currency::new(0).encode_v1(w) // siad encodes a "claim start," but transactions its an error if it's non-zero.
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct FileContract {
    #[serde(rename = "filesize")]
    pub file_size: u64,
    pub file_merkle_root: Hash256,
    pub window_start: u64,
    pub window_end: u64,
    pub payout: Currency,
    pub valid_proof_outputs: Vec<SiacoinOutput>,
    pub missed_proof_outputs: Vec<SiacoinOutput>,
    pub unlock_hash: Hash256,
    pub revision_number: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct FileContractRevision {
    #[serde(rename = "parentID")]
    pub parent_id: FileContractID,
    pub unlock_conditions: UnlockConditions,
    pub revision_number: u64,
    #[serde(rename = "filesize")]
    pub file_size: u64,
    pub file_merkle_root: Hash256,
    pub window_start: u64,
    pub window_end: u64,
    pub valid_proof_outputs: Vec<SiacoinOutput>,
    pub missed_proof_outputs: Vec<SiacoinOutput>,
    pub unlock_hash: Hash256,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct StorageProof {
    #[serde(rename = "parentID")]
    pub parent_id: FileContractID,
    pub leaf: Leaf,
    pub proof: Vec<Hash256>,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct CoveredFields {
    pub whole_transaction: bool,
    pub siacoin_inputs: Vec<usize>,
    pub siacoin_outputs: Vec<usize>,
    pub file_contracts: Vec<usize>,
    pub file_contract_revisions: Vec<usize>,
    pub storage_proofs: Vec<usize>,
    pub siafund_inputs: Vec<usize>,
    pub siafund_outputs: Vec<usize>,
    pub miner_fees: Vec<usize>,
    pub arbitrary_data: Vec<usize>,
    pub signatures: Vec<usize>,
}

impl CoveredFields {
    pub fn whole_transaction() -> Self {
        CoveredFields {
            whole_transaction: true,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSignature {
    #[serde(rename = "parentID")]
    pub parent_id: Hash256,
    pub public_key_index: u64,
    pub timelock: u64,
    pub covered_fields: CoveredFields,
    #[serde(with = "base64")]
    pub signature: Vec<u8>,
}

#[derive(Default, Debug, PartialEq, Serialize, Deserialize, V1SiaEncode, V1SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct Transaction {
    pub siacoin_inputs: Vec<SiacoinInput>,
    pub siacoin_outputs: Vec<SiacoinOutput>,
    pub file_contracts: Vec<FileContract>,
    pub file_contract_revisions: Vec<FileContractRevision>,
    pub storage_proofs: Vec<StorageProof>,
    pub siafund_inputs: Vec<SiafundInput>,
    pub siafund_outputs: Vec<SiafundOutput>,
    pub miner_fees: Vec<Currency>,
    pub arbitrary_data: Vec<Vec<u8>>,
    pub signatures: Vec<TransactionSignature>,
}

impl Transaction {
    const SIACOIN_OUTPUT_ID_PREFIX: Specifier = specifier!("siacoin output");
    const SIAFUND_OUTPUT_ID_PREFIX: Specifier = specifier!("siafund output");

    pub fn encode_no_sigs<W: std::io::Write>(&self, w: &mut W) -> Result<(), encoding::Error> {
        self.siacoin_inputs.encode_v1(w)?;
        self.siacoin_outputs.encode_v1(w)?;
        self.file_contracts.encode_v1(w)?;
        self.file_contract_revisions.encode_v1(w)?;
        self.storage_proofs.encode_v1(w)?;
        self.siafund_inputs.encode_v1(w)?;
        self.siafund_outputs.encode_v1(w)?;
        self.miner_fees.encode_v1(w)?;
        self.arbitrary_data.encode_v1(w)
    }

    pub(crate) fn whole_sig_hash(
        &self,
        chain: &SigningState,
        parent_id: &Hash256,
        public_key_index: u64,
        timelock: u64,
        covered_sigs: &Vec<usize>,
    ) -> Result<Hash256, encoding::Error> {
        let mut state = Params::new().hash_length(32).to_state();

        state.update(&(self.siacoin_inputs.len() as u64).to_le_bytes());
        for input in self.siacoin_inputs.iter() {
            state.update(chain.replay_prefix());
            input.encode_v1(&mut state)?;
        }

        self.siacoin_outputs.encode_v1(&mut state)?;
        self.file_contracts.encode_v1(&mut state)?;
        self.file_contract_revisions.encode_v1(&mut state)?;
        self.storage_proofs.encode_v1(&mut state)?;

        state.update(&(self.siafund_inputs.len() as u64).to_le_bytes());
        for input in self.siafund_inputs.iter() {
            state.update(chain.replay_prefix());
            input.encode_v1(&mut state)?;
        }

        self.siafund_outputs.encode_v1(&mut state)?;
        self.miner_fees.encode_v1(&mut state)?;
        self.arbitrary_data.encode_v1(&mut state)?;

        parent_id.encode_v1(&mut state)?;
        public_key_index.encode_v1(&mut state)?;
        timelock.encode_v1(&mut state)?;

        for &i in covered_sigs {
            if i >= self.signatures.len() {
                return Err(encoding::Error::Custom(
                    "signatures index out of bounds".to_string(),
                ));
            }
            self.signatures[i].encode_v1(&mut state)?;
        }

        Ok(state.finalize().into())
    }

    pub(crate) fn partial_sig_hash(
        &self,
        chain: &SigningState,
        covered_fields: &CoveredFields,
    ) -> Result<Hash256, encoding::Error> {
        let mut state = Params::new().hash_length(32).to_state();

        for &i in covered_fields.siacoin_inputs.iter() {
            if i >= self.siacoin_inputs.len() {
                return Err(encoding::Error::Custom(
                    "siacoin_inputs index out of bounds".to_string(),
                ));
            }
            state.update(chain.replay_prefix());
            self.siacoin_inputs[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.siacoin_outputs.iter() {
            if i >= self.siacoin_outputs.len() {
                return Err(encoding::Error::Custom(
                    "siacoin_outputs index out of bounds".to_string(),
                ));
            }
            self.siacoin_outputs[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.file_contracts.iter() {
            if i >= self.file_contracts.len() {
                return Err(encoding::Error::Custom(
                    "file_contracts index out of bounds".to_string(),
                ));
            }
            self.file_contracts[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.file_contract_revisions.iter() {
            if i >= self.file_contract_revisions.len() {
                return Err(encoding::Error::Custom(
                    "file_contract_revisions index out of bounds".to_string(),
                ));
            }
            self.file_contract_revisions[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.storage_proofs.iter() {
            if i >= self.storage_proofs.len() {
                return Err(encoding::Error::Custom(
                    "storage_proofs index out of bounds".to_string(),
                ));
            }
            self.storage_proofs[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.siafund_inputs.iter() {
            if i >= self.siafund_inputs.len() {
                return Err(encoding::Error::Custom(
                    "siafund_inputs index out of bounds".to_string(),
                ));
            }
            state.update(chain.replay_prefix());
            self.siafund_inputs[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.siafund_outputs.iter() {
            if i >= self.siafund_outputs.len() {
                return Err(encoding::Error::Custom(
                    "siafund_outputs index out of bounds".to_string(),
                ));
            }
            self.siafund_outputs[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.miner_fees.iter() {
            if i >= self.miner_fees.len() {
                return Err(encoding::Error::Custom(
                    "miner_fees index out of bounds".to_string(),
                ));
            }
            self.miner_fees[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.arbitrary_data.iter() {
            if i >= self.arbitrary_data.len() {
                return Err(encoding::Error::Custom(
                    "arbitrary_data index out of bounds".to_string(),
                ));
            }
            self.arbitrary_data[i].encode_v1(&mut state)?;
        }

        for &i in covered_fields.signatures.iter() {
            if i >= self.signatures.len() {
                return Err(encoding::Error::Custom(
                    "signatures index out of bounds".to_string(),
                ));
            }
            self.signatures[i].encode_v1(&mut state)?;
        }
        Ok(state.finalize().into())
    }

    pub fn sign(
        &self,
        state: &SigningState,
        covered_fields: &CoveredFields,
        parent_id: Hash256,
        public_key_index: u64,
        timelock: u64,
        private_key: &PrivateKey,
    ) -> Result<TransactionSignature, encoding::Error> {
        let sig_hash = if covered_fields.whole_transaction {
            self.whole_sig_hash(
                state,
                &parent_id,
                public_key_index,
                timelock,
                &covered_fields.signatures,
            )
        } else {
            self.partial_sig_hash(state, covered_fields)
        }?;

        Ok(TransactionSignature {
            parent_id,
            public_key_index,
            timelock,
            covered_fields: covered_fields.clone(),
            signature: private_key.sign(sig_hash.as_ref()).data().to_vec(),
        })
    }

    pub fn id(&self) -> TransactionID {
        let mut state = Params::new().hash_length(32).to_state();
        self.encode_no_sigs(&mut state).unwrap();
        let hash = state.finalize();
        hash.into()
    }

    pub fn siacoin_output_id(&self, i: usize) -> SiacoinOutputID {
        let mut state = Params::new().hash_length(32).to_state();

        state.update(Self::SIACOIN_OUTPUT_ID_PREFIX.as_bytes());
        self.encode_no_sigs(&mut state).unwrap();

        let h = state.update(&i.to_le_bytes()).finalize();
        SiacoinOutputID::from(h)
    }

    pub fn siafund_output_id(&self, i: usize) -> SiafundOutputID {
        let mut state = Params::new().hash_length(32).to_state();

        state.update(Self::SIAFUND_OUTPUT_ID_PREFIX.as_bytes());
        self.encode_no_sigs(&mut state).unwrap();

        let h = state.update(&i.to_le_bytes()).finalize();
        SiafundOutputID::from(h)
    }
}

// Create a helper module for base64 serialization
mod base64 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{NetworkHardforks, PublicKey, Signature};
    use crate::{BlockID, ChainIndex};
    use serde::de::DeserializeOwned;
    use std::fmt::Debug;
    use std::time::SystemTime;
    use std::vec;

    /// test_serialize_json is a helper to test serialization and deserialization of a struct to and from JSON.
    fn test_serialize_json<S: Serialize + DeserializeOwned + Debug + PartialEq>(
        obj: &S,
        json_str: &str,
    ) {
        let serialized = serde_json::to_string(&obj).unwrap();
        assert_eq!(serialized, json_str);
        let deserialized: S = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, *obj);
    }

    /// test_serialize_v1 is a helper to test serialization and deserialization of a struct to and from Sia's
    /// custom binary encoding.
    fn test_serialize_v1<S: V1SiaEncodable + V1SiaDecodable + Debug + PartialEq>(
        obj: &S,
        hex_binary: &str,
    ) {
        let mut serialized = Vec::new();
        obj.encode_v1(&mut serialized).unwrap();
        assert_eq!(hex::encode(serialized.clone()), hex_binary);
        let deserialized = S::decode_v1(&mut &serialized[..]).unwrap();
        assert_eq!(deserialized, *obj);
    }

    /// test_serialize is a helper to test serialization and deserialization of a struct to and from Sia's
    /// custom binary encoding.
    fn test_serialize<S: SiaEncodable + SiaDecodable + Debug + PartialEq>(
        obj: &S,
        hex_binary: &str,
    ) {
        let mut serialized = Vec::new();
        obj.encode(&mut serialized).unwrap();
        assert_eq!(hex::encode(serialized.clone()), hex_binary);
        let deserialized = S::decode(&mut &serialized[..]).unwrap();
        assert_eq!(deserialized, *obj);
    }

    #[test]
    fn test_serialize_covered_fields() {
        let mut cf = CoveredFields::default();
        cf.siacoin_inputs.push(1);
        cf.siacoin_outputs.push(2);
        cf.siacoin_outputs.push(3);

        let binary_str = "000100000000000000010000000000000002000000000000000200000000000000030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        test_serialize_v1(&cf, binary_str);

        let json_str = "{\"wholeTransaction\":false,\"siacoinInputs\":[1],\"siacoinOutputs\":[2,3],\"fileContracts\":[],\"fileContractRevisions\":[],\"storageProofs\":[],\"siafundInputs\":[],\"siafundOutputs\":[],\"minerFees\":[],\"arbitraryData\":[],\"signatures\":[]}";
        test_serialize_json(&cf, json_str);
    }

    #[test]
    fn test_serialize_siacoin_input() {
        let siacoin_input = SiacoinInput {
            parent_id: SiacoinOutputID::parse_string(
                "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24",
            )
            .unwrap(),
            unlock_conditions: UnlockConditions::new(
                123,
                vec![PublicKey::new([
                    0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b, 0x47,
                    0xda, 0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28, 0x8c, 0x1a,
                    0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6,
                ])
                .into()],
                1,
            ),
        };

        let binary_str = hex::encode([
            179, 99, 58, 19, 112, 167, 32, 2, 174, 42, 149, 109, 33, 232, 212, 129, 195, 166, 158,
            20, 102, 51, 71, 12, 246, 37, 236, 216, 63, 222, 170, 36, 123, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 0, 0, 0, 0, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0,
            0, 0, 0, 0, 0, 154, 172, 31, 251, 28, 253, 16, 121, 168, 198, 200, 123, 71, 218, 29,
            86, 126, 53, 185, 114, 52, 153, 60, 40, 140, 26, 208, 219, 29, 28, 225, 182, 1, 0, 0,
            0, 0, 0, 0, 0,
        ]);
        test_serialize_v1(&siacoin_input, binary_str.as_str());

        let json_str = "{\"parentID\":\"b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24\",\"unlockConditions\":{\"timelock\":123,\"publicKeys\":[\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\"],\"signaturesRequired\":1}}";
        test_serialize_json(&siacoin_input, json_str);
    }

    #[test]
    fn test_serialize_siafund_input() {
        let siafund_input = SiafundInput {
            parent_id: SiafundOutputID::parse_string(
                "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24",
            )
            .unwrap(),
            unlock_conditions: UnlockConditions::new(
                123,
                vec![PublicKey::new([
                    0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b, 0x47,
                    0xda, 0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28, 0x8c, 0x1a,
                    0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6,
                ])
                .into()],
                1,
            ),
            claim_address: Address::new(
                hex::decode("8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            ),
        };

        // binary
        let binary_str = hex::encode([
            179, 99, 58, 19, 112, 167, 32, 2, 174, 42, 149, 109, 33, 232, 212, 129, 195, 166, 158,
            20, 102, 51, 71, 12, 246, 37, 236, 216, 63, 222, 170, 36, 123, 0, 0, 0, 0, 0, 0, 0, 1,
            0, 0, 0, 0, 0, 0, 0, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0,
            0, 0, 0, 0, 0, 154, 172, 31, 251, 28, 253, 16, 121, 168, 198, 200, 123, 71, 218, 29,
            86, 126, 53, 185, 114, 52, 153, 60, 40, 140, 26, 208, 219, 29, 28, 225, 182, 1, 0, 0,
            0, 0, 0, 0, 0, 143, 180, 156, 207, 23, 223, 220, 201, 82, 109, 236, 110, 232, 165, 204,
            162, 15, 248, 36, 115, 2, 5, 61, 55, 119, 65, 11, 155, 4, 148, 186, 140,
        ]);
        test_serialize_v1(&siafund_input, binary_str.as_str());

        let json_str = "{\"parentID\":\"b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24\",\"unlockConditions\":{\"timelock\":123,\"publicKeys\":[\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\"],\"signaturesRequired\":1},\"claimAddress\":\"8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0\"}";
        test_serialize_json(&siafund_input, json_str);
    }

    #[test]
    fn test_serialize_siacoin_output() {
        let addr_str =
            "000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69";
        let output = SiacoinOutput {
            value: Currency::new(67856467336433871),
            address: Address::parse_string(addr_str).unwrap(),
        };

        let v1_binary_str = hex::encode([
            7, 0, 0, 0, 0, 0, 0, 0, 241, 19, 24, 247, 77, 16, 207, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        test_serialize_v1(&output, v1_binary_str.as_str());

        let v2_binary_str = "cf104df71813f10000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        test_serialize(&output, v2_binary_str);

        let json_str = format!(
            "{{\"value\":\"67856467336433871\",\"address\":\"{}\"}}",
            addr_str
        );
        test_serialize_json(&output, json_str.as_str());
    }

    #[test]
    fn test_serialize_transaction_signature() {
        let signature = TransactionSignature {
            parent_id: Hash256::parse_string(
                "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24",
            )
            .unwrap(),
            public_key_index: 1,
            timelock: 2,
            covered_fields: CoveredFields {
                whole_transaction: true,
                ..Default::default()
            },
            signature: Signature::new([3u8; 64]).data().to_vec(),
        };

        let binary_str = hex::encode([
            179, 99, 58, 19, 112, 167, 32, 2, 174, 42, 149, 109, 33, 232, 212, 129, 195, 166, 158,
            20, 102, 51, 71, 12, 246, 37, 236, 216, 63, 222, 170, 36, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0,
            0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            64, 0, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
            3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        ]);
        test_serialize_v1(&signature, binary_str.as_str());

        let json_str = "{\"parentID\":\"b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24\",\"publicKeyIndex\":1,\"timelock\":2,\"coveredFields\":{\"wholeTransaction\":true,\"siacoinInputs\":[],\"siacoinOutputs\":[],\"fileContracts\":[],\"fileContractRevisions\":[],\"storageProofs\":[],\"siafundInputs\":[],\"siafundOutputs\":[],\"minerFees\":[],\"arbitraryData\":[],\"signatures\":[]},\"signature\":\"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw==\"}";
        test_serialize_json(&signature, json_str);
    }

    #[test]
    fn test_serialize_siafund_output() {
        let addr_str =
            "000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69";
        let output = SiafundOutput {
            value: 67856467336433871,
            address: Address::parse_string(addr_str).unwrap(),
        };

        let v1_binary_str = hex::encode([
            7, 0, 0, 0, 0, 0, 0, 0, 241, 19, 24, 247, 77, 16, 207, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        test_serialize_v1(&output, v1_binary_str.as_str());

        let v2_binary_str =
            "cf104df71813f1000000000000000000000000000000000000000000000000000000000000000000";
        test_serialize(&output, v2_binary_str);

        let json_str = format!(
            "{{\"value\":67856467336433871,\"address\":\"{}\"}}",
            addr_str
        );
        test_serialize_json(&output, json_str.as_str());
    }

    #[test]
    fn test_serialize_filecontract() {
        let contract = FileContract {
            file_size: 1,
            file_merkle_root: Hash256::from([
                1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            window_start: 2,
            window_end: 3,
            payout: Currency::new(456),
            valid_proof_outputs: vec![SiacoinOutput {
                value: Currency::new(789),
                address: Address::new([
                    2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
            }],
            missed_proof_outputs: vec![SiacoinOutput {
                value: Currency::new(101112),
                address: Address::new([
                    3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
            }],
            unlock_hash: Hash256::from([
                4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            revision_number: 4,
        };

        let binary_str = hex::encode([
            1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 2, 0,
            0, 0, 0, 0, 0, 0, 1, 200, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 21, 2, 2,
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 138, 248, 3, 3, 3, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 4, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0,
            0, 0, 0, 0, 0, 0,
        ]);
        test_serialize_v1(&contract, binary_str.as_str());

        let json_str = "{\"filesize\":1,\"fileMerkleRoot\":\"0101010000000000000000000000000000000000000000000000000000000000\",\"windowStart\":2,\"windowEnd\":3,\"payout\":\"456\",\"validProofOutputs\":[{\"value\":\"789\",\"address\":\"02020200000000000000000000000000000000000000000000000000000000008749787b31db\"}],\"missedProofOutputs\":[{\"value\":\"101112\",\"address\":\"0303030000000000000000000000000000000000000000000000000000000000c596d559a239\"}],\"unlockHash\":\"0404040000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":4}";
        test_serialize_json(&contract, json_str);
    }

    #[test]
    fn test_serialize_filecontract_revision() {
        let revision = FileContractRevision {
            parent_id: FileContractID::from([
                9, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            file_size: 1,
            file_merkle_root: Hash256::from([
                1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            window_start: 2,
            window_end: 3,
            valid_proof_outputs: vec![SiacoinOutput {
                value: Currency::new(789),
                address: Address::new([
                    2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
            }],
            missed_proof_outputs: vec![SiacoinOutput {
                value: Currency::new(789),
                address: Address::new([
                    3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
            }],
            unlock_conditions: UnlockConditions::new(
                123,
                vec![PublicKey::new([
                    0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b, 0x47,
                    0xda, 0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28, 0x8c, 0x1a,
                    0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6,
                ])
                .into()],
                1,
            ),
            unlock_hash: Hash256::from([
                4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            revision_number: 4,
        };

        let binary_str = hex::encode([
            9, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 123, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 101, 100, 50, 53, 53, 49,
            57, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 154, 172, 31, 251, 28, 253, 16,
            121, 168, 198, 200, 123, 71, 218, 29, 86, 126, 53, 185, 114, 52, 153, 60, 40, 140, 26,
            208, 219, 29, 28, 225, 182, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0,
            0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 21, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0,
            0, 0, 3, 21, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        test_serialize_v1(&revision, binary_str.as_str());

        let json_str = "{\"parentID\":\"0908070000000000000000000000000000000000000000000000000000000000\",\"unlockConditions\":{\"timelock\":123,\"publicKeys\":[\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\"],\"signaturesRequired\":1},\"revisionNumber\":4,\"filesize\":1,\"fileMerkleRoot\":\"0101010000000000000000000000000000000000000000000000000000000000\",\"windowStart\":2,\"windowEnd\":3,\"validProofOutputs\":[{\"value\":\"789\",\"address\":\"02020200000000000000000000000000000000000000000000000000000000008749787b31db\"}],\"missedProofOutputs\":[{\"value\":\"789\",\"address\":\"0303030000000000000000000000000000000000000000000000000000000000c596d559a239\"}],\"unlockHash\":\"0404040000000000000000000000000000000000000000000000000000000000\"}";
        test_serialize_json(&revision, json_str);
    }

    #[test]
    fn test_serialize_storage_proof() {
        let storage_proof = StorageProof {
            parent_id: FileContractID::parse_string(
                "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24",
            )
            .unwrap(),
            leaf: Leaf::from([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
                45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
            ]),
            proof: vec![
                Hash256::parse_string(
                    "0102030000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                Hash256::parse_string(
                    "0405060000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
            ],
        };

        let binary_str = hex::encode([
            179, 99, 58, 19, 112, 167, 32, 2, 174, 42, 149, 109, 33, 232, 212, 129, 195, 166, 158,
            20, 102, 51, 71, 12, 246, 37, 236, 216, 63, 222, 170, 36, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
            54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 2, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 5, 6,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        test_serialize_v1(&storage_proof, binary_str.as_str());

        let json_str = "{\"parentID\":\"b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24\",\"leaf\":\"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40\",\"proof\":[\"0102030000000000000000000000000000000000000000000000000000000000\",\"0405060000000000000000000000000000000000000000000000000000000000\"]}";
        test_serialize_json(&storage_proof, json_str);
    }

    #[test]
    fn test_transaction_id() {
        let txn = Transaction::default();
        let id = txn.id();
        assert_eq!(
            hex::encode(id),
            "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24"
        );
    }

    #[test]
    fn test_whole_sig_hash() {
        let state = SigningState {
            index: ChainIndex {
                height: 0,
                id: BlockID::default(),
            },
            median_timestamp: SystemTime::now(),
            hardforks: NetworkHardforks {
                asic_height: 0,
                foundation_height: 0,
                v2_allow_height: 1000,
                v2_require_height: 1000,
            },
        };
        let pk = PrivateKey::from_seed(&[
            136, 215, 58, 248, 45, 30, 78, 97, 128, 111, 82, 204, 43, 233, 223, 111, 110, 29, 73,
            157, 52, 25, 242, 96, 131, 16, 187, 22, 232, 107, 17, 205,
        ]);
        let test_cases = vec![
			(
				Transaction {
					siacoin_inputs: vec![
						SiacoinInput{
							parent_id: SiacoinOutputID::from([32,11,215,36,166,174,135,0,92,215,179,18,74,229,52,154,221,194,213,216,219,47,225,205,251,84,248,2,69,252,37,117]),
							unlock_conditions: UnlockConditions::standard_unlock_conditions(pk.public_key()),
						}
					],
					siacoin_outputs: vec![
						SiacoinOutput{
							value: Currency::new(67856467336433871),
							address: Address::parse_string("000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69").unwrap(),
						}
					],
					file_contracts: Vec::new(),
					file_contract_revisions: Vec::new(),
					storage_proofs: Vec::new(),
					siafund_inputs: Vec::new(),
					siafund_outputs: Vec::new(),
					miner_fees: Vec::new(),
					arbitrary_data: Vec::new(),
					signatures: Vec::new(),
				},
				"a4b1855c546db7ec902237f730717faae96187db8ce9fe139504323a639f731e"
			)
		];

        for (txn, expected) in test_cases {
            let sig_hash = txn
                .whole_sig_hash(
                    &state,
                    &Hash256::from(<SiacoinOutputID as Into<[u8; 32]>>::into(
                        txn.siacoin_inputs[0].parent_id,
                    )),
                    0,
                    0,
                    &vec![],
                )
                .expect("expect tranasction to hash");

            assert_eq!(sig_hash.to_string(), expected)
        }
    }

    #[test]
    fn test_transaction_sign() {
        let state = SigningState {
            index: ChainIndex {
                height: 0,
                id: BlockID::default(),
            },
            median_timestamp: SystemTime::now(),
            hardforks: NetworkHardforks {
                asic_height: 0,
                foundation_height: 0,
                v2_allow_height: 1000,
                v2_require_height: 1000,
            },
        };
        let pk = PrivateKey::from_seed(&[
            136, 215, 58, 248, 45, 30, 78, 97, 128, 111, 82, 204, 43, 233, 223, 111, 110, 29, 73,
            157, 52, 25, 242, 96, 131, 16, 187, 22, 232, 107, 17, 205,
        ]);
        let test_cases = vec![
			(
				Transaction {
					siacoin_inputs: vec![
						SiacoinInput{
							parent_id: SiacoinOutputID::from([32,11,215,36,166,174,135,0,92,215,179,18,74,229,52,154,221,194,213,216,219,47,225,205,251,84,248,2,69,252,37,117]),
							unlock_conditions: UnlockConditions::standard_unlock_conditions(pk.public_key()),
						}
					],
					siacoin_outputs: vec![
						SiacoinOutput{
							value: Currency::new(67856467336433871),
							address: Address::parse_string("000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69").unwrap(),
						}
					],
					file_contracts: Vec::new(),
					file_contract_revisions: Vec::new(),
					storage_proofs: Vec::new(),
					siafund_inputs: Vec::new(),
					siafund_outputs: Vec::new(),
					miner_fees: Vec::new(),
					arbitrary_data: Vec::new(),
					signatures: Vec::new(),
				},
				"7a5db98318b5ecad2954d41ba2084c908823ebf4000b95543f352478066a0d04bf4829e3e6d086b42ff9d943f68981c479798fd42bf6f63dac254f4294a37609"
			)
		];

        for (txn, expected) in test_cases {
            let sig = txn
                .sign(
                    &state,
                    &CoveredFields::whole_transaction(),
                    Hash256::from(<SiacoinOutputID as Into<[u8; 32]>>::into(
                        txn.siacoin_inputs[0].parent_id,
                    )),
                    0,
                    0,
                    &pk,
                )
                .expect("");

            assert_eq!(hex::encode(sig.signature), expected)
        }
    }

    #[test]
    fn test_serialize_transaction() {
        let transaction = Transaction {
            siacoin_inputs: Vec::new(),
            siacoin_outputs: Vec::new(),
            file_contracts: Vec::new(),
            file_contract_revisions: Vec::new(),
            storage_proofs: Vec::new(),
            siafund_inputs: Vec::new(),
            siafund_outputs: Vec::new(),
            miner_fees: Vec::new(),
            arbitrary_data: Vec::new(),
            signatures: Vec::new(),
        };
        let binary_str = hex::encode([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        test_serialize_v1(&transaction, binary_str.as_str());

        let json_str = "{\"siacoinInputs\":[],\"siacoinOutputs\":[],\"fileContracts\":[],\"fileContractRevisions\":[],\"storageProofs\":[],\"siafundInputs\":[],\"siafundOutputs\":[],\"minerFees\":[],\"arbitraryData\":[],\"signatures\":[]}";
        test_serialize_json(&transaction, json_str);
    }
}
