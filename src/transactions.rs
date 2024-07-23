use crate::encoding::{serialize_array, to_writer, SerializeError};
use crate::signing::{PrivateKey, Signature, SigningState};
use crate::specifier::{specifier, Specifier};
use crate::unlock_conditions::UnlockConditions;
use crate::{Address, Currency, ImplHashID};
use crate::{Hash256, HexParseError};
use blake2b_simd::{Params, State};
use core::fmt;
use serde::{Deserialize, Serialize};

ImplHashID!(SiacoinOutputID, "scoid");

ImplHashID!(SiafundOutputID, "sfoid");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinInput {
    #[serde(rename = "parentID")]
    pub parent_id: SiacoinOutputID,
    pub unlock_conditions: UnlockConditions,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiacoinOutput {
    pub value: Currency,
    pub address: Address,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiafundInput {
    #[serde(rename = "parentID")]
    pub parent_id: SiafundOutputID,
    pub unlock_conditions: UnlockConditions,
    pub claim_address: Address,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiafundOutput {
    pub value: Currency,
    pub address: Address,
    pub claim_start: Currency,
}

ImplHashID!(FileContractID, "fcid");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageProof {
    #[serde(rename = "parentID")]
    pub parent_id: FileContractID,
    #[serde(serialize_with = "serialize_array")]
    pub leaf: [u8; 64],
    pub proof: Vec<Hash256>,
}

#[derive(Debug, Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoveredFields {
    pub whole_transaction: bool,
    pub siacoin_inputs: Vec<usize>,
    pub siacoin_outputs: Vec<usize>,
    pub siafund_inputs: Vec<usize>,
    pub siafund_outputs: Vec<usize>,
    pub file_contracts: Vec<usize>,
    pub file_contract_revisions: Vec<usize>,
    pub storage_proofs: Vec<usize>,
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSignature {
    #[serde(rename = "parentID")]
    pub parent_id: Hash256,
    pub public_key_index: u64,
    pub timelock: u64,
    pub covered_fields: CoveredFields,
    pub signature: Signature,
}

ImplHashID!(TransactionID, "txn");

#[derive(Default, Debug, Clone, Serialize)]
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

    pub fn encode_no_sigs(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        buf.extend_from_slice(&(self.siacoin_inputs.len() as u64).to_le_bytes());
        for input in &self.siacoin_inputs {
            to_writer(&mut buf, input).unwrap();
        }

        buf.extend_from_slice(&(self.siacoin_outputs.len() as u64).to_le_bytes());
        for output in &self.siacoin_outputs {
            to_writer(&mut buf, output).unwrap();
        }

        buf.extend_from_slice(&(self.file_contracts.len() as u64).to_le_bytes());
        for file_contract in &self.file_contracts {
            to_writer(&mut buf, file_contract).unwrap();
        }

        buf.extend_from_slice(&(self.file_contract_revisions.len() as u64).to_le_bytes());
        for file_contract_revision in &self.file_contract_revisions {
            to_writer(&mut buf, file_contract_revision).unwrap();
        }

        buf.extend_from_slice(&(self.storage_proofs.len() as u64).to_le_bytes());
        for storage_proof in &self.storage_proofs {
            to_writer(&mut buf, storage_proof).unwrap();
        }

        buf.extend_from_slice(&(self.siafund_inputs.len() as u64).to_le_bytes());
        for input in &self.siafund_inputs {
            to_writer(&mut buf, input).unwrap();
        }

        buf.extend_from_slice(&(self.siafund_outputs.len() as u64).to_le_bytes());
        for output in &self.siafund_outputs {
            to_writer(&mut buf, output).unwrap();
        }

        buf.extend_from_slice(&(self.miner_fees.len() as u64).to_le_bytes());
        for fee in &self.miner_fees {
            to_writer(&mut buf, fee).unwrap();
        }

        buf.extend_from_slice(&(self.arbitrary_data.len() as u64).to_le_bytes());
        for data in &self.arbitrary_data {
            buf.extend_from_slice(&(data.len() as u64).to_le_bytes());
            buf.extend_from_slice(data);
        }
        buf
    }

    pub fn hash_no_sigs(&self, state: &mut State) {
        state.update(&(self.siacoin_inputs.len() as u64).to_le_bytes());
        for input in self.siacoin_inputs.iter() {
            to_writer(state, input).unwrap();
        }

        state.update(&(self.siacoin_outputs.len() as u64).to_le_bytes());
        for output in self.siacoin_outputs.iter() {
            to_writer(state, output).unwrap();
        }

        state.update(&(self.file_contracts.len() as u64).to_le_bytes());
        for file_contract in self.file_contracts.iter() {
            to_writer(state, file_contract).unwrap();
        }

        state.update(&(self.file_contract_revisions.len() as u64).to_le_bytes());
        for file_contract_revision in self.file_contract_revisions.iter() {
            to_writer(state, file_contract_revision).unwrap();
        }

        state.update(&(self.storage_proofs.len() as u64).to_le_bytes());
        for storage_proof in self.storage_proofs.iter() {
            to_writer(state, storage_proof).unwrap();
        }

        state.update(&(self.siafund_inputs.len() as u64).to_le_bytes());
        for input in self.siafund_inputs.iter() {
            to_writer(state, input).unwrap();
        }

        state.update(&(self.siafund_outputs.len() as u64).to_le_bytes());
        for output in self.siafund_outputs.iter() {
            to_writer(state, output).unwrap();
        }

        state.update(&(self.miner_fees.len() as u64).to_le_bytes());
        for fee in self.miner_fees.iter() {
            to_writer(state, fee).unwrap();
        }

        state.update(&(self.arbitrary_data.len() as u64).to_le_bytes());
        for data in self.arbitrary_data.iter() {
            state.update(&(data.len() as u64).to_le_bytes());
            state.update(data);
        }
    }

    fn whole_sig_hash(
        &self,
        chain: &SigningState,
        parent_id: &Hash256,
        public_key_index: u64,
        timelock: u64,
        covered_sigs: &Vec<usize>,
    ) -> Result<Hash256, SerializeError> {
        let mut state = Params::new().hash_length(32).to_state();

        state.update(&(self.siacoin_inputs.len() as u64).to_le_bytes());
        for input in self.siacoin_inputs.iter() {
            state.update(chain.replay_prefix());
            to_writer(&mut state, input)?;
        }

        state.update(&(self.siacoin_outputs.len() as u64).to_le_bytes());
        for output in self.siacoin_outputs.iter() {
            to_writer(&mut state, output)?;
        }

        state.update(&(self.file_contracts.len() as u64).to_le_bytes());
        for file_contract in self.file_contracts.iter() {
            to_writer(&mut state, file_contract)?;
        }

        state.update(&(self.file_contract_revisions.len() as u64).to_le_bytes());
        for file_contract_revision in self.file_contract_revisions.iter() {
            to_writer(&mut state, file_contract_revision)?;
        }

        state.update(&(self.storage_proofs.len() as u64).to_le_bytes());
        for storage_proof in self.storage_proofs.iter() {
            to_writer(&mut state, storage_proof).unwrap();
        }

        state.update(&(self.siafund_inputs.len() as u64).to_le_bytes());
        for input in self.siafund_inputs.iter() {
            state.update(chain.replay_prefix());
            to_writer(&mut state, input).unwrap();
        }

        state.update(&(self.siafund_outputs.len() as u64).to_le_bytes());
        for output in self.siafund_outputs.iter() {
            to_writer(&mut state, output)?;
        }

        state.update(&(self.miner_fees.len() as u64).to_le_bytes());
        for fee in self.miner_fees.iter() {
            to_writer(&mut state, &fee)?;
        }

        state.update(&(self.arbitrary_data.len() as u64).to_le_bytes());
        for data in self.arbitrary_data.iter() {
            state.update(&(data.len() as u64).to_le_bytes());
            state.update(data);
        }

        to_writer(&mut state, parent_id)?;
        state.update(&public_key_index.to_le_bytes());
        state.update(&timelock.to_le_bytes());

        for &i in covered_sigs {
            to_writer(&mut state, &self.signatures[i])?;
        }

        Ok(state.finalize().into())
    }

    fn partial_sig_hash(
        &self,
        chain: &SigningState,
        covered_fields: &CoveredFields,
    ) -> Result<Hash256, SerializeError> {
        let mut state = Params::new().hash_length(32).to_state();

        for &i in covered_fields.siacoin_inputs.iter() {
            state.update(chain.replay_prefix());
            to_writer(&mut state, &self.siacoin_inputs[i])?;
        }

        for &i in covered_fields.siacoin_outputs.iter() {
            to_writer(&mut state, &self.siacoin_outputs[i])?;
        }

        for &i in covered_fields.file_contracts.iter() {
            to_writer(&mut state, &self.file_contracts[i])?;
        }

        for &i in covered_fields.file_contract_revisions.iter() {
            to_writer(&mut state, &self.file_contract_revisions[i])?;
        }

        for &i in covered_fields.storage_proofs.iter() {
            to_writer(&mut state, &self.storage_proofs[i])?;
        }

        for &i in covered_fields.siafund_inputs.iter() {
            to_writer(&mut state, &self.siafund_inputs[i])?;
            state.update(chain.replay_prefix());
        }

        for &i in covered_fields.siafund_outputs.iter() {
            state.update(chain.replay_prefix());
            to_writer(&mut state, &self.siafund_outputs[i])?;
        }

        for &i in covered_fields.miner_fees.iter() {
            to_writer(&mut state, &self.miner_fees[i])?;
        }

        for &i in covered_fields.arbitrary_data.iter() {
            state.update(&(self.arbitrary_data[i].len() as u64).to_le_bytes());
            state.update(&self.arbitrary_data[i]);
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
    ) -> Result<TransactionSignature, SerializeError> {
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
            signature: private_key.sign(sig_hash.as_ref()),
        })
    }

    pub fn id(&self) -> TransactionID {
        let mut state = Params::new().hash_length(32).to_state();
        self.hash_no_sigs(&mut state);
        let hash = state.finalize();
        let buf = hash.as_bytes();

        TransactionID(buf.try_into().unwrap())
    }

    pub fn siacoin_output_id(&self, i: usize) -> SiacoinOutputID {
        let mut state = Params::new().hash_length(32).to_state();

        state.update(Self::SIACOIN_OUTPUT_ID_PREFIX.as_bytes());
        self.hash_no_sigs(&mut state);

        let h = state.update(&i.to_le_bytes()).finalize();
        SiacoinOutputID::from(h)
    }

    pub fn siafund_output_id(&self, i: usize) -> SiafundOutputID {
        let mut state = Params::new().hash_length(32).to_state();

        state.update(Self::SIAFUND_OUTPUT_ID_PREFIX.as_bytes());
        self.hash_no_sigs(&mut state);

        let h = state.update(&i.to_le_bytes()).finalize();
        SiafundOutputID::from(h)
    }
}

#[cfg(test)]
mod tests {
    use crate::encoding::{from_reader, to_bytes};
    use crate::signing::{NetworkHardforks, PublicKey};
    use crate::unlock_conditions::{Algorithm, UnlockKey};
    use crate::ChainIndex;
    use std::time::SystemTime;

    use super::*;

    #[test]
    fn test_json_serialize_covered_fields() {
        let mut cf = CoveredFields::default();
        cf.siacoin_inputs.push(1);
        cf.siacoin_outputs.push(2);
        cf.siacoin_outputs.push(3);
        assert_eq!(serde_json::to_string(&cf).unwrap(), "{\"wholeTransaction\":false,\"siacoinInputs\":[1],\"siacoinOutputs\":[2,3],\"siafundInputs\":[],\"siafundOutputs\":[],\"fileContracts\":[],\"fileContractRevisions\":[],\"storageProofs\":[],\"minerFees\":[],\"arbitraryData\":[],\"signatures\":[]}")
    }

    #[test]
    fn test_serialize_covered_fields() {
        let test_cases = vec![
            (
                CoveredFields::whole_transaction(),
                vec![
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0,
                ],
            ),
            (
                CoveredFields::default(),
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0,
                ],
            ),
        ];

        for (cf, expected) in test_cases {
            let result = to_bytes(&cf).expect("failed to serialize covered fields");
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_json_serialize_transaction_signature() {
        let txn_sig = TransactionSignature {
            parent_id: Hash256::default(),
            public_key_index: 1,
            timelock: 2,
            covered_fields: CoveredFields::default(),
            signature: Signature::new([0u8; 64]),
        };
        assert_eq!(serde_json::to_string(&txn_sig).unwrap(), "{\"parentID\":\"h:0000000000000000000000000000000000000000000000000000000000000000\",\"publicKeyIndex\":1,\"timelock\":2,\"coveredFields\":{\"wholeTransaction\":false,\"siacoinInputs\":[],\"siacoinOutputs\":[],\"siafundInputs\":[],\"siafundOutputs\":[],\"fileContracts\":[],\"fileContractRevisions\":[],\"storageProofs\":[],\"minerFees\":[],\"arbitraryData\":[],\"signatures\":[]},\"signature\":\"sig:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}")
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
                vec![UnlockKey::new(
                    Algorithm::ED25519,
                    PublicKey::new([
                        0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b,
                        0x47, 0xda, 0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28,
                        0x8c, 0x1a, 0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6,
                    ]),
                )],
                1,
            ),
        };

        // binary
        let siacoin_input_serialized = to_bytes(&siacoin_input).unwrap();
        let siacoin_input_deserialized: SiacoinInput =
            from_reader(&mut &siacoin_input_serialized[..]).unwrap();
        assert_eq!(
            siacoin_input_serialized,
            [
                179, 99, 58, 19, 112, 167, 32, 2, 174, 42, 149, 109, 33, 232, 212, 129, 195, 166,
                158, 20, 102, 51, 71, 12, 246, 37, 236, 216, 63, 222, 170, 36, 123, 0, 0, 0, 0, 0,
                0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 32, 0, 0, 0, 0, 0, 0, 0, 154, 172, 31, 251, 28, 253, 16, 121, 168, 198, 200,
                123, 71, 218, 29, 86, 126, 53, 185, 114, 52, 153, 60, 40, 140, 26, 208, 219, 29,
                28, 225, 182, 1, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        assert_eq!(siacoin_input_deserialized, siacoin_input);

        // json
        let siacoin_input_serialized = serde_json::to_string(&siacoin_input).unwrap();
        let siacoin_input_deserialized: SiacoinInput =
            serde_json::from_str(&siacoin_input_serialized).unwrap();
        assert_eq!(siacoin_input_serialized, "{\"parentID\":\"scoid:b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24\",\"unlockConditions\":{\"timelock\":123,\"publicKeys\":[\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\"],\"signaturesRequired\":1}}");
        assert_eq!(siacoin_input_deserialized, siacoin_input);
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
                vec![UnlockKey::new(
                    Algorithm::ED25519,
                    PublicKey::new([
                        0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b,
                        0x47, 0xda, 0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28,
                        0x8c, 0x1a, 0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6,
                    ]),
                )],
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
        let siafund_input_serialized = to_bytes(&siafund_input).unwrap();
        let siafund_input_deserialized: SiafundInput =
            from_reader(&mut &siafund_input_serialized[..]).unwrap();
        assert_eq!(
            siafund_input_serialized,
            [
                179, 99, 58, 19, 112, 167, 32, 2, 174, 42, 149, 109, 33, 232, 212, 129, 195, 166,
                158, 20, 102, 51, 71, 12, 246, 37, 236, 216, 63, 222, 170, 36, 123, 0, 0, 0, 0, 0,
                0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 32, 0, 0, 0, 0, 0, 0, 0, 154, 172, 31, 251, 28, 253, 16, 121, 168, 198, 200,
                123, 71, 218, 29, 86, 126, 53, 185, 114, 52, 153, 60, 40, 140, 26, 208, 219, 29,
                28, 225, 182, 1, 0, 0, 0, 0, 0, 0, 0, 143, 180, 156, 207, 23, 223, 220, 201, 82,
                109, 236, 110, 232, 165, 204, 162, 15, 248, 36, 115, 2, 5, 61, 55, 119, 65, 11,
                155, 4, 148, 186, 140
            ]
        );
        assert_eq!(siafund_input_deserialized, siafund_input);

        // json
        let siafund_input_serialized = serde_json::to_string(&siafund_input).unwrap();
        let siafund_input_deserialized: SiafundInput =
            serde_json::from_str(&siafund_input_serialized).unwrap();
        assert_eq!(siafund_input_serialized, "{\"parentID\":\"sfoid:b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24\",\"unlockConditions\":{\"timelock\":123,\"publicKeys\":[\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\"],\"signaturesRequired\":1},\"claimAddress\":\"addr:8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0\"}");
        assert_eq!(siafund_input_deserialized, siafund_input);
    }

    #[test]
    fn test_serialize_siacoin_output() {
        let addr_str =
            "addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69";
        let output = SiacoinOutput {
            value: Currency::new(67856467336433871),
            address: Address::parse_string(addr_str).unwrap(),
        };

        // binary
        let output_serialized = to_bytes(&output).unwrap();
        let output_deserialized: SiacoinOutput = from_reader(&mut &output_serialized[..]).unwrap();
        assert_eq!(
            output_serialized,
            [
                7, 0, 0, 0, 0, 0, 0, 0, 241, 19, 24, 247, 77, 16, 207, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(output_deserialized, output);

        // json
        let output_serialized = serde_json::to_string(&output).unwrap();
        let output_deserialized: SiacoinOutput = serde_json::from_str(&output_serialized).unwrap();
        assert_eq!(
            output_serialized,
            format!(
                "{{\"value\":\"67856467336433871\",\"address\":\"{}\"}}",
                addr_str
            )
        );
        assert_eq!(output_deserialized, output);
    }

    #[test]
    fn test_serialize_siafund_output() {
        let addr_str =
            "addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69";
        let output = SiafundOutput {
            value: Currency::new(67856467336433871),
            address: Address::parse_string(addr_str).unwrap(),
            claim_start: Currency::new(123456789),
        };

        // binary
        let output_serialized = to_bytes(&output).unwrap();
        let output_deserialized: SiafundOutput = from_reader(&mut &output_serialized[..]).unwrap();
        assert_eq!(
            output_serialized,
            [
                7, 0, 0, 0, 0, 0, 0, 0, 241, 19, 24, 247, 77, 16, 207, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0,
                0, 0, 0, 7, 91, 205, 21
            ]
        );
        assert_eq!(output_deserialized, output);

        // json
        let output_serialized = serde_json::to_string(&output).unwrap();
        let output_deserialized: SiafundOutput = serde_json::from_str(&output_serialized).unwrap();
        assert_eq!(
            output_serialized,
            format!(
                "{{\"value\":\"67856467336433871\",\"address\":\"{}\",\"claimStart\":\"123456789\"}}",
                addr_str
            )
        );
        assert_eq!(output_deserialized, output);
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

        // binary
        let contract_serialized = to_bytes(&contract).unwrap();
        let contract_deserialized: FileContract =
            from_reader(&mut &contract_serialized[..]).unwrap();
        assert_eq!(
            contract_serialized,
            [
                1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0,
                2, 0, 0, 0, 0, 0, 0, 0, 1, 200, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3,
                21, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 1, 138, 248, 3,
                3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0
            ],
        );
        assert_eq!(contract_deserialized, contract);

        // json
        let contract_serialized = serde_json::to_string(&contract).unwrap();
        let contract_deserialized: FileContract =
            serde_json::from_str(&contract_serialized).unwrap();
        assert_eq!(contract_serialized, "{\"filesize\":1,\"fileMerkleRoot\":\"h:0101010000000000000000000000000000000000000000000000000000000000\",\"windowStart\":2,\"windowEnd\":3,\"payout\":\"456\",\"validProofOutputs\":[{\"value\":\"789\",\"address\":\"addr:02020200000000000000000000000000000000000000000000000000000000008749787b31db\"}],\"missedProofOutputs\":[{\"value\":\"101112\",\"address\":\"addr:0303030000000000000000000000000000000000000000000000000000000000c596d559a239\"}],\"unlockHash\":\"h:0404040000000000000000000000000000000000000000000000000000000000\",\"revisionNumber\":4}");
        assert_eq!(contract_deserialized, contract);
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
                vec![UnlockKey::new(
                    Algorithm::ED25519,
                    PublicKey::new([
                        0x9a, 0xac, 0x1f, 0xfb, 0x1c, 0xfd, 0x10, 0x79, 0xa8, 0xc6, 0xc8, 0x7b,
                        0x47, 0xda, 0x1d, 0x56, 0x7e, 0x35, 0xb9, 0x72, 0x34, 0x99, 0x3c, 0x28,
                        0x8c, 0x1a, 0xd0, 0xdb, 0x1d, 0x1c, 0xe1, 0xb6,
                    ]),
                )],
                1,
            ),
            unlock_hash: Hash256::from([
                4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            revision_number: 4,
        };

        // binary
        let revision_serialized = to_bytes(&revision).unwrap();
        let revision_deserialized: FileContractRevision =
            from_reader(&mut &revision_serialized[..]).unwrap();
        assert_eq!(
            revision_serialized,
            [
                9, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 123, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 101, 100, 50, 53, 53,
                49, 57, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 154, 172, 31, 251, 28,
                253, 16, 121, 168, 198, 200, 123, 71, 218, 29, 86, 126, 53, 185, 114, 52, 153, 60,
                40, 140, 26, 208, 219, 29, 28, 225, 182, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0,
                0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0,
                0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 21, 2, 2, 2, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
                0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 21, 3, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 4, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ],
        );
        assert_eq!(revision_deserialized, revision);

        // json
        let revision_serialized = serde_json::to_string(&revision).unwrap();
        let revision_deserialized: FileContractRevision =
            serde_json::from_str(&revision_serialized).unwrap();
        assert_eq!(revision_serialized, "{\"parentID\":\"fcid:0908070000000000000000000000000000000000000000000000000000000000\",\"unlockConditions\":{\"timelock\":123,\"publicKeys\":[\"ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6\"],\"signaturesRequired\":1},\"revisionNumber\":4,\"filesize\":1,\"fileMerkleRoot\":\"h:0101010000000000000000000000000000000000000000000000000000000000\",\"windowStart\":2,\"windowEnd\":3,\"validProofOutputs\":[{\"value\":\"789\",\"address\":\"addr:02020200000000000000000000000000000000000000000000000000000000008749787b31db\"}],\"missedProofOutputs\":[{\"value\":\"789\",\"address\":\"addr:0303030000000000000000000000000000000000000000000000000000000000c596d559a239\"}],\"unlockHash\":\"h:0404040000000000000000000000000000000000000000000000000000000000\"}");
        assert_eq!(revision_deserialized, revision);
    }

    #[test]
    fn test_transaction_id() {
        let txn = Transaction::default();
        let h = Params::new()
            .hash_length(32)
            .to_state()
            .update(&txn.encode_no_sigs())
            .finalize();

        assert_eq!(
            txn.encode_no_sigs(),
            [
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        let buf = h.as_bytes();
        assert_eq!(
            hex::encode(buf),
            "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24"
        );
    }

    #[test]
    fn test_whole_sig_hash() {
        let state = SigningState {
            index: ChainIndex {
                height: 0,
                id: [0; 32],
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
							address: Address::parse_string("addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69").unwrap(),
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
				"h:a4b1855c546db7ec902237f730717faae96187db8ce9fe139504323a639f731e"
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
                id: [0; 32],
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
							address: Address::parse_string("addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69").unwrap(),
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
				"sig:7a5db98318b5ecad2954d41ba2084c908823ebf4000b95543f352478066a0d04bf4829e3e6d086b42ff9d943f68981c479798fd42bf6f63dac254f4294a37609"
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

            assert_eq!(sig.signature.to_string(), expected)
        }
    }
}
