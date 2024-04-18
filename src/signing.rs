use core::fmt;
use std::io::{Error, Write};
use std::time::SystemTime;

use crate::consensus::ChainIndex;
use crate::encoding::to_writer;
use crate::transactions::{CoveredFields, Transaction};
use crate::{Algorithm, HexParseError, SiaEncodable};
use blake2b_simd::Params;
use ed25519_dalek::{Signature as ED25519Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// An ed25519 public key that can be used to verify a signature
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct PublicKey([u8; 32]);

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

    pub fn sign_hash(&self, hash: &[u8; 32]) -> Signature {
        let sk = SigningKey::from_bytes(&self.0[..32].try_into().unwrap());
        Signature::new(sk.sign(hash).to_bytes())
    }
}

impl AsRef<[u8; 64]> for PrivateKey {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<PrivateKey> for UnlockKey {
    fn from(val: PrivateKey) -> Self {
        UnlockKey::new(Algorithm::ED25519, val.public_key())
    }
}

/// A generic public key that can be used to spend a utxo or revise a file
///  contract
///
/// Currently only supports ed25519 keys
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct UnlockKey {
    algorithm: Algorithm,
    public_key: PublicKey,
}

impl UnlockKey {
    /// Creates a new UnlockKey
    pub fn new(algorithm: Algorithm, public_key: PublicKey) -> UnlockKey {
        UnlockKey {
            algorithm,
            public_key,
        }
    }

    /// Parses an UnlockKey from a string
    /// The string should be in the format "algorithm:public_key"
    pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
        let (prefix, key_str) = s.split_once(':').ok_or(HexParseError::MissingPrefix)?;
        let algorithm = match prefix {
            "ed25519" => Algorithm::ED25519,
            _ => return Err(HexParseError::InvalidPrefix),
        };

        let mut data = [0u8; 32];
        hex::decode_to_slice(key_str, &mut data).map_err(HexParseError::HexError)?;
        Ok(UnlockKey {
            algorithm,
            public_key: PublicKey::new(data),
        })
    }

    // Returns the public key of the UnlockKey
    pub fn public_key(&self) -> PublicKey {
        self.public_key
    }
}

impl fmt::Display for UnlockKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}:{}",
            self.algorithm,
            hex::encode(self.public_key.as_ref())
        )
    }
}

impl SiaEncodable for UnlockKey {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        to_writer(w, &self.algorithm).unwrap(); // TODO: handle error
        w.write_all(&32_u64.to_le_bytes())?;
        w.write_all(self.public_key.as_ref())
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

#[derive(Default, Debug, Clone, Copy)]
pub struct NetworkHardforks {
    pub asic_height: u64,

    pub foundation_height: u64,

    pub v2_allow_height: u64,
    pub v2_require_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
            median_timestamp: SystemTime::now(),
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
