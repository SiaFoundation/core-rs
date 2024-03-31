use crate::CoveredFields;
use crate::Currency;
use crate::Address;
use crate::Transaction;
use crate::SiaEncodable;
use std::time;
use blake2b_simd::Params;

pub struct ChainIndex {
	pub height: u64,
	pub id: [u8; 32],
}

pub struct HardforkDevAddress {
	height: u64,
	old_address: Address,
	new_address: Address,
}

pub struct HardforkTax {
	height: u64,
}

pub struct HardforkStorageProof {
	height: u64,
}

pub struct HardforkOak {
	height: u64,
	fix_height: u64,
	genesis_timestamp: time::SystemTime,
}

pub struct HardforkASIC {
	height: u64,
	oak_time: time::Duration,
	oak_target: [u8;32],
}

pub struct HardforkFoundation {
	height: u64,
	primary_address: Address,
	failsafe_address: Address,
}

pub struct Network {
	pub name: String,
	pub initial_coinbase: Currency,
	pub minimum_coinbase: Currency,
	pub initial_target: [u8;32],

	pub hardfork_dev_address: HardforkDevAddress,
	pub hardfork_tax: HardforkTax,
	pub hardfork_storage_proof: HardforkStorageProof,
	pub hardfork_oak: HardforkOak,
	pub hardfork_asic: HardforkASIC,
	pub hardfork_foundation: HardforkFoundation,
}

pub struct State {
	pub network: Network,

	pub index: ChainIndex,
	pub depth: [u8;32],
	pub child_target: [u8;32],
	pub siafund_pool: Currency,

	pub oak_time: time::Duration,
	pub oak_target: [u8;32],

	pub foundation_primary_address: Address,
	pub foundation_failsafe_address: Address,
}

impl State {
	fn child_height(&self) -> u64 {
		self.index.height + 1
	}

	fn replay_prefix(&self) -> &[u8] {
		if self.index.height >= self.network.hardfork_foundation.height {
			return &[1]
		} else if self.index.height >= self.network.hardfork_asic.height {
			return &[0]
		}
		return &[]
	}

	pub fn block_reward(&self) -> Currency {
		let sub = Currency::siacoins(self.child_height());
		if self.network.initial_coinbase <= sub {
			return self.network.minimum_coinbase
		}

		let delta = self.network.initial_coinbase - sub;
		if delta <= self.network.minimum_coinbase {
			return self.network.minimum_coinbase
		}
		return delta
	}

	pub fn maturity_height(&self) -> u64 {
		self.child_height() + 144
	}

	pub fn siafund_count() -> u64 {
		10_000
	}

	pub fn whole_sig_hash(&self, txn: &Transaction, parent_id: &[u8;32], public_key_index: u64, timelock: u64, covered_sigs: Vec<u64>) -> [u8;32] {
		let mut state = Params::new()
			.hash_length(32)
			.to_state();

		let mut buf = Vec::new();
		state.update(&txn.siacoin_inputs.len().to_le_bytes());
		for input in txn.siacoin_inputs.iter() {
			buf.clear();
			state.update(self.replay_prefix());
			input.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&txn.siacoin_outputs.len().to_le_bytes());
		for output in txn.siacoin_outputs.iter() {
			buf.clear();
			output.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&txn.file_contracts.len().to_le_bytes());
		for file_contract in txn.file_contracts.iter() {
			buf.clear();
			file_contract.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&txn.file_contract_revisions.len().to_le_bytes());
		for file_contract_revision in txn.file_contract_revisions.iter() {
			buf.clear();
			file_contract_revision.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&txn.storage_proofs.len().to_le_bytes());
		for storage_proof in txn.storage_proofs.iter() {
			buf.clear();
			storage_proof.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&txn.siafund_inputs.len().to_le_bytes());
		for input in txn.siafund_inputs.iter() {
			buf.clear();
			state.update(self.replay_prefix());
			input.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&txn.siafund_outputs.len().to_le_bytes());
		for output in txn.siafund_outputs.iter() {
			buf.clear();
			output.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&txn.miner_fees.len().to_le_bytes());
		for fee in txn.miner_fees.iter() {
			buf.clear();
			fee.encode(&mut buf);
			state.update(&buf);
		}

		state.update(&txn.arbitrary_data.len().to_le_bytes());
		for data in txn.arbitrary_data.iter() {
			state.update(&data.len().to_le_bytes());
			state.update(&data);
		}

		state.update(parent_id);
		state.update(&public_key_index.to_le_bytes());
		state.update(&timelock.to_le_bytes());

		for i in covered_sigs.into_iter() {
			buf.clear();
			txn.signatures[i as usize].encode(&mut buf);
			state.update(&buf);
		}

		state.finalize().as_bytes().try_into().unwrap()
	}

	pub fn partial_sig_hash(&self, txn: &Transaction, covered_fields: CoveredFields) -> [u8;32] {
		let mut state = Params::new()
			.hash_length(32)
			.to_state();

		let mut buf = Vec::new();
		for i in covered_fields.siacoin_inputs.into_iter() {
			buf.clear();
			txn.siacoin_inputs[i as usize].encode(&mut buf);
			state.update(self.replay_prefix());
			state.update(&buf);
		}

		for i in covered_fields.siacoin_outputs.into_iter() {
			buf.clear();
			txn.siacoin_outputs[i as usize].encode(&mut buf);
			state.update(&buf);
		}

		for i in covered_fields.file_contracts.into_iter() {
			buf.clear();
			txn.file_contracts[i as usize].encode(&mut buf);
			state.update(&buf);
		}

		for i in covered_fields.file_contract_revisions.into_iter() {
			buf.clear();
			txn.file_contract_revisions[i as usize].encode(&mut buf);
			state.update(&buf);
		}

		for i in covered_fields.storage_proofs.into_iter() {
			buf.clear();
			txn.storage_proofs[i as usize].encode(&mut buf);
			state.update(&buf);
		}

		for i in covered_fields.siafund_inputs.into_iter() {
			buf.clear();
			txn.siafund_inputs[i as usize].encode(&mut buf);
			state.update(self.replay_prefix());
			state.update(&buf);
		}

		for i in covered_fields.siafund_outputs.into_iter() {
			buf.clear();
			txn.siafund_outputs[i as usize].encode(&mut buf);
			state.update(self.replay_prefix());
			state.update(&buf);
		}

		for i in covered_fields.miner_fees.into_iter() {
			buf.clear();
			txn.miner_fees[i as usize].encode(&mut buf);
			state.update(&buf);
		}

		for i in covered_fields.arbitrary_data.into_iter() {
			state.update(&txn.arbitrary_data[i as usize].len().to_le_bytes());
			state.update(&txn.arbitrary_data[i as usize]);
		}

		state.finalize().as_bytes().try_into().unwrap()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_whole_sig_hash() {
		let state = State {
			network: Network {
				name: "test".to_string(),
				initial_coinbase: Currency::siacoins(100_000),
				minimum_coinbase: Currency::siacoins(30),
				initial_target: [0;32],
				hardfork_dev_address: HardforkDevAddress {
					height: 0,
					old_address: Address::parse_string("addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69").unwrap(),
					new_address: Address::parse_string("addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69").unwrap(),
				},
				hardfork_tax: HardforkTax{
					height: 2,
				},
				hardfork_storage_proof: HardforkStorageProof{
					height: 4,
				},
				hardfork_oak: HardforkOak{
					height: 6,
					fix_height: 8,
					genesis_timestamp: time::SystemTime::now(),
				},
				hardfork_asic: HardforkASIC{
					height: 10,
					oak_time: time::Duration::from_secs(12),
					oak_target: [0;32],
				},
				hardfork_foundation: HardforkFoundation{
					height: 12,
					primary_address: Address::parse_string("addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69").unwrap(),
					failsafe_address: Address::parse_string("addr:000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69").unwrap(),
				},
			},

			index: ChainIndex {
				height: 0,
				id: [0;32],
			},
			depth: [0;32],
			child_target: [0;32],
			siafund_pool: Currency::new(0),
			oak_time: time::Duration::from_secs(0),
			oak_target: [0;32],
			foundation_primary_address: Address::parse_string("000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69").unwrap(),
			foundation_failsafe_address: Address::parse_string("000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69").unwrap(),
		};

		let txn = Transaction {
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

		let h = state.whole_sig_hash(&txn, &[0;32], 0, 0, vec![]);
		assert_eq!(hex::encode(h), "b3633a1370a72002ae2a956d21e8d481c3a69e146633470cf625ecd83fdeaa24")
	}
}