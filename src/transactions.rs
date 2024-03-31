use core::fmt;

use crate::currency::Currency;
use crate::address::{Address, UnlockConditions};
use crate::{Hash256, SiaEncodable};
use blake2b_simd::{Params, State};

const SIACOIN_OUTPUT_ID_PREFIX : [u8;16] = [b's', b'i', b'a', b'c', b'o', b'i', b'n', b' ', b'o', b'u', b't', b'p', b'u', b't', 0, 0];
const SIAFUND_OUTPUT_ID_PREFIX : [u8;16] = [b's', b'i', b'a', b'f', b'u', b'n', b'd', b' ', b'o', b'u', b't', b'p', b'u', b't', 0, 0];

pub struct SiacoinOutputID([u8;32]);

impl SiacoinOutputID {
	pub fn	as_bytes(&self) -> [u8;32] {
		self.0
	}
}

impl fmt::Display for SiacoinOutputID {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "scoid:{}", hex::encode(&self.0))
	}
}

pub struct SiacoinInput {
	pub parent_id: SiacoinOutputID,
	pub unlock_conditions: UnlockConditions,
}

impl SiaEncodable for SiacoinInput {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.parent_id.as_bytes());
		self.unlock_conditions.encode(buf);
	}
}

pub struct SiacoinOutput {
	pub address: Address,
	pub value: Currency,
}

impl SiaEncodable for SiacoinOutput {
	fn encode(&self, buf: &mut Vec<u8>) {
		self.value.encode(buf);
		self.address.encode(buf);
	}
}

pub struct SiafundOutputID([u8;32]);

impl SiafundOutputID {
	pub fn as_bytes(&self) -> [u8;32] {
		self.0
	}
}

impl fmt::Display for SiafundOutputID {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "sfoid:{}", hex::encode(&self.0))
	}
}

pub struct SiafundInput {
	pub parent_id: [u8;32],
	pub unlock_conditions: UnlockConditions,
	pub claim_address: Address,
}

impl SiaEncodable for SiafundInput {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.parent_id);
		self.unlock_conditions.encode(buf);
		self.claim_address.encode(buf);
	}
}

pub struct SiafundOutput {
	pub address: Address, 
	pub value: Currency,
	pub claim_start: Currency,
}

impl SiaEncodable for SiafundOutput {
	fn encode(&self, buf: &mut Vec<u8>) {
		self.value.encode(buf);
		self.address.encode(buf);
		self.claim_start.encode(buf);
	}
}

pub struct FileContractID([u8;32]);

impl FileContractID {
	pub fn as_bytes(&self) -> [u8;32] {
		self.0
	}
}

impl fmt::Display for FileContractID {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "fcid:{}", hex::encode(&self.0))
	}
}

pub struct FileContract {
	pub file_size: u64,
	pub file_merkle_root: Hash256,
	pub window_start: u64,
	pub window_end: u64,
	pub payout: Currency,
	pub valid_proof_outputs: Vec<SiacoinOutput>,
	pub missed_proof_outputs: Vec<SiacoinOutput>,
	pub unlock_hash: Address,
	pub revision_number: u64,
}

impl SiaEncodable for FileContract {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.file_size.to_le_bytes());
		buf.extend_from_slice(&self.file_merkle_root.as_bytes());
		buf.extend_from_slice(&self.window_start.to_le_bytes());
		buf.extend_from_slice(&self.window_end.to_le_bytes());
		self.payout.encode(buf);
		buf.extend_from_slice(&self.valid_proof_outputs.len().to_le_bytes());
		for output in &self.valid_proof_outputs {
			output.encode(buf);
		}
		buf.extend_from_slice(&self.missed_proof_outputs.len().to_le_bytes());
		for output in &self.missed_proof_outputs {
			output.encode(buf);
		}
		self.unlock_hash.encode(buf);
		buf.extend_from_slice(&self.revision_number.to_le_bytes());
	}
}

pub struct FileContractRevision {
	pub parent_id: FileContractID,
	pub unlock_conditions: UnlockConditions,
	pub revision_number: u64,
	pub file_size: u64,
	pub file_merkle_root: Hash256,
	pub window_start: u64,
	pub window_end: u64,
	pub valid_proof_outputs: Vec<SiacoinOutput>,
	pub missed_proof_outputs: Vec<SiacoinOutput>,
	pub unlock_hash: Address,
}

impl SiaEncodable for FileContractRevision {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.parent_id.as_bytes());
		self.unlock_conditions.encode(buf);
		buf.extend_from_slice(&self.revision_number.to_le_bytes());
		buf.extend_from_slice(&self.file_size.to_le_bytes());
		buf.extend_from_slice(&self.file_merkle_root.as_bytes());
		buf.extend_from_slice(&self.window_start.to_le_bytes());
		buf.extend_from_slice(&self.window_end.to_le_bytes());
		buf.extend_from_slice(&self.valid_proof_outputs.len().to_le_bytes());
		for output in &self.valid_proof_outputs {
			output.encode(buf);
		}
		buf.extend_from_slice(&self.missed_proof_outputs.len().to_le_bytes());
		for output in &self.missed_proof_outputs {
			output.encode(buf);
		}
		self.unlock_hash.encode(buf);
	}
}

pub struct StorageProof {
	pub parent_id: FileContractID,
	pub leaf: [u8;64],
	pub proof: Vec<Hash256>,
}

impl SiaEncodable for StorageProof {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.parent_id.as_bytes());
		buf.extend_from_slice(&self.leaf);
		buf.extend_from_slice(&self.proof.len().to_le_bytes());
		for proof in &self.proof {
			buf.extend_from_slice(&proof.as_bytes());
		}
	}
}

pub struct CoveredFields {
	pub whole_transaction: bool,
	pub siacoin_inputs: Vec<u64>,
	pub siacoin_outputs: Vec<u64>,
	pub siafund_inputs: Vec<u64>,
	pub siafund_outputs: Vec<u64>,
	pub file_contracts: Vec<u64>,
	pub file_contract_revisions: Vec<u64>,
	pub storage_proofs: Vec<u64>,
	pub miner_fees: Vec<u64>,
	pub arbitrary_data: Vec<u64>,
	pub signatures: Vec<u64>,
}

impl SiaEncodable for CoveredFields {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.push(self.whole_transaction as u8);
		buf.extend_from_slice(&self.siacoin_inputs.len().to_le_bytes());
		for input in &self.siacoin_inputs {
			buf.extend_from_slice(&input.to_le_bytes());
		}
		buf.extend_from_slice(&self.siacoin_outputs.len().to_le_bytes());
		for output in &self.siacoin_outputs {
			buf.extend_from_slice(&output.to_le_bytes());
		}
		buf.extend_from_slice(&self.siafund_inputs.len().to_le_bytes());
		for input in &self.siafund_inputs {
			buf.extend_from_slice(&input.to_le_bytes());
		}
		buf.extend_from_slice(&self.siafund_outputs.len().to_le_bytes());
		for output in &self.siafund_outputs {
			buf.extend_from_slice(&output.to_le_bytes());
		}
		buf.extend_from_slice(&self.file_contracts.len().to_le_bytes());
		for file_contract in &self.file_contracts {
			buf.extend_from_slice(&file_contract.to_le_bytes());
		}
		buf.extend_from_slice(&self.file_contract_revisions.len().to_le_bytes());
		for file_contract_revision in &self.file_contract_revisions {
			buf.extend_from_slice(&file_contract_revision.to_le_bytes());
		}
		buf.extend_from_slice(&self.storage_proofs.len().to_le_bytes());
		for storage_proof in &self.storage_proofs {
			buf.extend_from_slice(&storage_proof.to_le_bytes());
		}
		buf.extend_from_slice(&self.miner_fees.len().to_le_bytes());
		for miner_fee in &self.miner_fees {
			buf.extend_from_slice(&miner_fee.to_le_bytes());
		}
		buf.extend_from_slice(&self.arbitrary_data.len().to_le_bytes());
		for arbitrary_data in &self.arbitrary_data {
			buf.extend_from_slice(&arbitrary_data.to_le_bytes());
		}
		buf.extend_from_slice(&self.signatures.len().to_le_bytes());
		for signature in &self.signatures {
			buf.extend_from_slice(&signature.to_le_bytes());
		}
	}
}

pub struct Signature {
	pub parent_id: Hash256,
	pub public_key_index: u64,
	pub timelock: u64,
	pub covered_fields: CoveredFields,
	pub signature: [u8;64],
}

impl SiaEncodable for Signature {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.parent_id.as_bytes());
		buf.extend_from_slice(&self.public_key_index.to_le_bytes());
		buf.extend_from_slice(&self.timelock.to_le_bytes());
		self.covered_fields.encode(buf);
		buf.extend_from_slice(&self.signature);
	}
}

pub struct Transaction {
	pub miner_fees: Vec<Currency>,
	pub siacoin_inputs: Vec<SiacoinInput>,
	pub siacoin_outputs: Vec<SiacoinOutput>,
	pub siafund_inputs: Vec<SiafundInput>,
	pub siafund_outputs: Vec<SiafundOutput>,
	pub file_contracts: Vec<FileContract>,
	pub file_contract_revisions: Vec<FileContractRevision>,
	pub storage_proofs: Vec<StorageProof>,
	pub signatures: Vec<Signature>,
	pub arbitrary_data: Vec<Vec<u8>>,
}

impl Transaction {
	fn hash_no_sigs(&self, state: &mut State) {
		state.update(&self.siacoin_inputs.len().to_le_bytes());
		let mut buf = Vec::new();
		for input in self.siacoin_inputs.iter() {
			buf.clear();
			input.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&self.siacoin_outputs.len().to_le_bytes());
		for output in self.siacoin_outputs.iter() {
			buf.clear();
			output.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&self.file_contracts.len().to_le_bytes());
		for file_contract in self.file_contracts.iter() {
			buf.clear();
			file_contract.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&self.file_contract_revisions.len().to_le_bytes());
		for file_contract_revision in self.file_contract_revisions.iter() {
			buf.clear();
			file_contract_revision.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&self.storage_proofs.len().to_le_bytes());
		for storage_proof in self.storage_proofs.iter() {
			buf.clear();
			storage_proof.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&self.siafund_inputs.len().to_le_bytes());
		for input in self.siafund_inputs.iter() {
			buf.clear();
			input.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&self.siafund_outputs.len().to_le_bytes());
		for output in self.siafund_outputs.iter() {
			buf.clear();
			output.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&self.miner_fees.len().to_le_bytes());
		for fee in self.miner_fees.iter() {
			buf.clear();
			fee.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&self.arbitrary_data.len().to_le_bytes());
		for data in self.arbitrary_data.iter() {
			state.update(&data.len().to_le_bytes());
			state.update(&data);
		}
	}

	pub fn id(&self) -> [u8;32] {
		let mut state = Params::new()
			.hash_length(32)
			.to_state();

		self.hash_no_sigs(&mut state);
		state.finalize()
			.as_bytes()
			.try_into()
			.unwrap()
	}

	pub fn siacoin_output_id(&self, i: usize) -> [u8;32] {
		let mut state = Params::new()
			.hash_length(32)
			.to_state();

		state.update(&SIACOIN_OUTPUT_ID_PREFIX);
		self.hash_no_sigs(&mut state);
		state.update(&i.to_le_bytes())
			.finalize();

		let mut output_id = [0;32];
		output_id.copy_from_slice(&state.finalize().as_bytes()[..32]);
		return output_id;
	}

	pub fn siafund_output_id(&self, i: usize) -> [u8;32] {
		let mut state = Params::new()
			.hash_length(32)
			.to_state();

		state.update(&SIAFUND_OUTPUT_ID_PREFIX);
		self.hash_no_sigs(&mut state);
		state.update(&i.to_le_bytes())
			.finalize();

		let mut output_id = [0;32];
		output_id.copy_from_slice(&state.finalize().as_bytes()[..32]);
		return output_id;
	}
}

impl SiaEncodable for Transaction {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.siacoin_inputs.len().to_le_bytes());
		for input in &self.siacoin_inputs {
			input.encode(buf);
		}
		buf.extend_from_slice(&self.siacoin_outputs.len().to_le_bytes());
		for output in &self.siacoin_outputs {
			output.encode(buf);
		}
		buf.extend_from_slice(&self.file_contracts.len().to_le_bytes());
		for file_contract in &self.file_contracts {
			file_contract.encode(buf);
		}
		buf.extend_from_slice(&self.file_contract_revisions.len().to_le_bytes());
		for file_contract_revision in &self.file_contract_revisions {
			file_contract_revision.encode(buf);
		}
		buf.extend_from_slice(&self.storage_proofs.len().to_le_bytes());
		for storage_proof in &self.storage_proofs {
			storage_proof.encode(buf);
		}
		buf.extend_from_slice(&self.siafund_inputs.len().to_le_bytes());
		for input in &self.siafund_inputs {
			input.encode(buf);
		}
		buf.extend_from_slice(&self.siafund_outputs.len().to_le_bytes());
		for output in &self.siafund_outputs {
			output.encode(buf);
		}
		buf.extend_from_slice(&self.miner_fees.len().to_le_bytes());
		for fee in &self.miner_fees {
			fee.encode(buf);
		}
		buf.extend_from_slice(&self.arbitrary_data.len().to_le_bytes());
		for data in &self.arbitrary_data {
			buf.extend_from_slice(&data.len().to_le_bytes());
			buf.extend_from_slice(data);
		}
		buf.extend_from_slice(&self.signatures.len().to_le_bytes());
		for signature in &self.signatures {
			signature.encode(buf);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_transaction_id() {
		let txn = Transaction{
			miner_fees: vec![],
			siacoin_inputs: vec![],
			siacoin_outputs: vec![],
			siafund_inputs: vec![],
			siafund_outputs: vec![],
			file_contracts: vec![],
			file_contract_revisions: vec![],
			storage_proofs: vec![],
			signatures: vec![],
			arbitrary_data: vec![],
		};

		let id = txn.id();

		assert_eq!(id, hex::decode("b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24").unwrap().as_slice());
	}
}