use crate::{
    encoding::SerializeError,
    signing::SigningState,
    transactions::{CoveredFields, SiacoinOutput},
    Address, Currency, Hash256,
};
use thiserror::Error;

use crate::{
    signing::PrivateKey,
    transactions::{SiacoinInput, SiacoinOutputID, Transaction},
    unlock_conditions::{UnlockConditions, UnlockKey},
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Transaction serialization error: {0}")]
    Serialize(#[from] SerializeError),
}

#[derive(Debug, PartialEq)]
pub struct TransactionBuilder {
    transaction: Transaction,
}

// NOTE: instead of using the builder pattern, we could also return a ToSign
// when we add inputs and leave it to the caller to track the ToSign instances
// they want to use for signing later.
pub struct ToSign {
    parent_id: Hash256,
    public_key_index: u64,
}

/// TODO: Missing features
/// - Add change output
/// - Add FileContract
/// - Add FileContractdRevision
/// - Add StorageProof
/// - Add SiafundInput
/// - Add SiafundOutput
/// - Add MinerFee
/// - Add ArbitraryData
/// - Add Signature

impl TransactionBuilder {
    /// Creates a new transaction builder
    pub fn new() -> TransactionBuilder {
        TransactionBuilder {
            transaction: Default::default(),
        }
    }

    pub fn add_change_address(self, _address: Address) -> Self {
        unimplemented!(
            "if inputs exceed outputs, add an output that send the change to the provided address"
        )
    }

    pub fn add_miner_fee(mut self, fee: Currency) -> Self {
        self.transaction.miner_fees.push(fee);
        self
    }

    /// Adds a siacoin input with a simple 'spendable by public key' unlock
    /// condition
    pub fn add_siacoin_input(mut self, parent_id: SiacoinOutputID, public_key: UnlockKey) -> Self {
        self.transaction.siacoin_inputs.push(SiacoinInput {
            parent_id: parent_id,
            unlock_conditions: UnlockConditions {
                public_keys: vec![public_key],
                timelock: 0,
                signatures_required: 1,
            },
        });
        self
    }

    /// Adds a siacoin output with the given value to the transaction
    pub fn add_siacoin_output(mut self, address: Address, value: Currency) -> Self {
        self.transaction.siacoin_outputs.push(SiacoinOutput {
            address: address,
            value: value,
        });
        self
    }

    /// Finalizes the transaction, consuming the builder.
    pub fn finalize(self) -> Transaction {
        self.transaction
    }

    /// Signs the whole transaction with the provided private key for each input
    /// in to_sign. The public_key_index is the index of the public key within
    /// the unlock conditions of the input that we sign for.
    pub fn sign(
        mut self,
        state: &SigningState,
        to_sign: &[ToSign],
        timelock: u64,
        private_key: &PrivateKey,
    ) -> Result<Self, Error> {
        // cover everything
        let mut covered_fields = CoveredFields::default();
        for i in 0..self.transaction.siacoin_inputs.len() {
            covered_fields.siacoin_inputs.push(i);
        }
        for i in 0..self.transaction.siacoin_outputs.len() {
            covered_fields.siacoin_outputs.push(i);
        }
        for i in 0..self.transaction.file_contracts.len() {
            covered_fields.file_contracts.push(i);
        }
        for i in 0..self.transaction.file_contract_revisions.len() {
            covered_fields.file_contract_revisions.push(i);
        }
        for i in 0..self.transaction.storage_proofs.len() {
            covered_fields.storage_proofs.push(i);
        }
        for i in 0..self.transaction.siafund_inputs.len() {
            covered_fields.siafund_inputs.push(i);
        }
        for i in 0..self.transaction.siafund_outputs.len() {
            covered_fields.siafund_outputs.push(i);
        }
        for i in 0..self.transaction.miner_fees.len() {
            covered_fields.miner_fees.push(i);
        }
        for i in 0..self.transaction.arbitrary_data.len() {
            covered_fields.arbitrary_data.push(i);
        }
        for i in 0..self.transaction.signatures.len() {
            covered_fields.signatures.push(i);
        }
        for ts in to_sign {
            let signature = self.transaction.sign(
                state,
                &covered_fields,
                ts.parent_id,
                ts.public_key_index,
                timelock,
                private_key,
            )?;
            self.transaction.signatures.push(signature);
        }
        Ok(self)
    }
}
