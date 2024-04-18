use core::fmt;
use std::io::{Error, Write};

use crate::consensus::ChainIndex;
use crate::transactions::{CoveredFields, Transaction};
use crate::{HexParseError, SiaEncodable};
use blake2b_simd::Params;

pub struct NetworkHardforks {
    pub asic_height: u64,

    pub foundation_height: u64,

    pub v2_allow_height: u64,
    pub v2_require_height: u64,
}

pub struct SigningState {
    index: ChainIndex,
    hardforks: NetworkHardforks,
}

#[derive(Debug, Clone)]
pub struct Signature([u8; 64]);

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

impl AsRef<[u8; 64]> for Signature {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

impl SiaEncodable for Signature {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&(self.0.len() as u64).to_le_bytes())?;
        w.write_all(&self.0)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "sig:{}", hex::encode(self.0))
    }
}

impl SigningState {
    pub fn new(index: ChainIndex, hardforks: NetworkHardforks) -> Self {
        SigningState { index, hardforks }
    }

    fn replay_prefix(&self) -> &[u8] {
        if self.index.height >= self.hardforks.v2_allow_height {
            return &[2];
        } else if self.index.height >= self.hardforks.foundation_height {
            return &[1];
        } else if self.index.height >= self.hardforks.asic_height {
            return &[0];
        }
        &[]
    }

    pub fn with_index(self, index: ChainIndex) -> Self {
        SigningState { index, ..self }
    }

    pub fn whole_sig_hash(
        &self,
        txn: &Transaction,
        parent_id: &[u8; 32],
        public_key_index: u64,
        timelock: u64,
        covered_sigs: Vec<u64>,
    ) -> [u8; 32] {
        let mut state = Params::new().hash_length(32).to_state();
        state.update(&(txn.siacoin_inputs.len() as u64).to_le_bytes());
        for input in txn.siacoin_inputs.iter() {
            state.update(self.replay_prefix());
            input.encode(&mut state).unwrap();
        }

        state.update(&(txn.siacoin_outputs.len() as u64).to_le_bytes());
        for output in txn.siacoin_outputs.iter() {
            output.encode(&mut state).unwrap();
        }

        state.update(&(txn.file_contracts.len() as u64).to_le_bytes());
        for file_contract in txn.file_contracts.iter() {
            file_contract.encode(&mut state).unwrap();
        }

        state.update(&(txn.file_contract_revisions.len() as u64).to_le_bytes());
        for file_contract_revision in txn.file_contract_revisions.iter() {
            file_contract_revision.encode(&mut state).unwrap();
        }

        state.update(&(txn.storage_proofs.len() as u64).to_le_bytes());
        for storage_proof in txn.storage_proofs.iter() {
            storage_proof.encode(&mut state).unwrap();
        }

        state.update(&(txn.siafund_inputs.len() as u64).to_le_bytes());
        for input in txn.siafund_inputs.iter() {
            state.update(self.replay_prefix());
            input.encode(&mut state).unwrap();
        }

        state.update(&(txn.siafund_outputs.len() as u64).to_le_bytes());
        for output in txn.siafund_outputs.iter() {
            output.encode(&mut state).unwrap();
        }

        state.update(&(txn.miner_fees.len() as u64).to_le_bytes());
        for fee in txn.miner_fees.iter() {
            fee.encode(&mut state).unwrap();
        }

        state.update(&(txn.arbitrary_data.len() as u64).to_le_bytes());
        for data in txn.arbitrary_data.iter() {
            state.update(&(data.len() as u64).to_le_bytes());
            state.update(data);
        }

        state.update(parent_id);
        state.update(&public_key_index.to_le_bytes());
        state.update(&timelock.to_le_bytes());

        for i in covered_sigs.into_iter() {
            txn.signatures[i as usize].encode(&mut state).unwrap();
        }

        state.finalize().as_bytes().try_into().unwrap()
    }

    pub fn partial_sig_hash(&self, txn: &Transaction, covered_fields: CoveredFields) -> [u8; 32] {
        let mut state = Params::new().hash_length(32).to_state();

        for i in covered_fields.siacoin_inputs.into_iter() {
            state.update(self.replay_prefix());
            txn.siacoin_inputs[i as usize].encode(&mut state).unwrap();
        }

        for i in covered_fields.siacoin_outputs.into_iter() {
            txn.siacoin_outputs[i as usize].encode(&mut state).unwrap();
        }

        for i in covered_fields.file_contracts.into_iter() {
            txn.file_contracts[i as usize].encode(&mut state).unwrap();
        }

        for i in covered_fields.file_contract_revisions.into_iter() {
            txn.file_contract_revisions[i as usize]
                .encode(&mut state)
                .unwrap();
        }

        for i in covered_fields.storage_proofs.into_iter() {
            txn.storage_proofs[i as usize].encode(&mut state).unwrap();
        }

        for i in covered_fields.siafund_inputs.into_iter() {
            txn.siafund_inputs[i as usize].encode(&mut state).unwrap();
            state.update(self.replay_prefix());
        }

        for i in covered_fields.siafund_outputs.into_iter() {
            txn.siafund_outputs[i as usize].encode(&mut state).unwrap();
            state.update(self.replay_prefix());
        }

        for i in covered_fields.miner_fees.into_iter() {
            txn.miner_fees[i as usize].encode(&mut state).unwrap();
        }

        for i in covered_fields.arbitrary_data.into_iter() {
            state.update(&(txn.arbitrary_data[i as usize].len() as u64).to_le_bytes());
            state.update(&txn.arbitrary_data[i as usize]);
        }

        state.finalize().as_bytes().try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn test_whole_sig_hash() {
        let state = SigningState {
            index: ChainIndex {
                height: 0,
                id: [0; 32],
            },
            hardforks: NetworkHardforks {
                asic_height: 0,
                foundation_height: 0,
                v2_allow_height: 0,
                v2_require_height: 0,
            },
        };

        let test_cases = vec![
			(
                Transaction {
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
				},
				"7a028465fc5cf200b99cd6fa4420becce66e03bc8fab62b08c5fd07e386a5281"
			),
			(
				Transaction {
					siacoin_inputs: vec![
						SiacoinInput{
							parent_id: SiacoinOutputID::new([32,11,215,36,166,174,135,0,92,215,179,18,74,229,52,154,221,194,213,216,219,47,225,205,251,84,248,2,69,252,37,117]),
							unlock_conditions: UnlockConditions{
								timelock: 0,
								required_signatures: 1,
								public_keys: vec![
									UnlockKey::parse_string("ed25519:9aac1ffb1cfd1079a8c6c87b47da1d567e35b97234993c288c1ad0db1d1ce1b6").unwrap(),
								],
							},
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
				"ed86b0d1e39b6e2d92285cd821c3b8734ddc9090a8718b5e5cffa4c38b8f1dbb"
			)
		];

        for (txn, expected) in test_cases {
            let h = state.whole_sig_hash(&txn, &[0; 32], 0, 0, vec![]);
            print!("replay prefix {}", state.replay_prefix()[0]);
            assert_eq!(hex::encode(h), expected)
        }
    }
}
