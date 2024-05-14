use crate::encoding::to_writer;
use crate::signing::{PublicKey, Signature, SigningState};
#[allow(deprecated)]
use crate::unlock_conditions::UnlockConditions;
use crate::{Address, Hash256};
use blake2b_simd::Params;
use core::{fmt, slice::Iter};
use serde::ser::SerializeTuple;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{self, SystemTime};
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum ValidationError {
    #[error("opaque policy")]
    OpaquePolicy,
    #[error("invalid policy")]
    InvalidPolicy,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid preimage")]
    InvalidPreimage,
    #[error("invalid height")]
    InvalidHeight,
    #[error("invalid timestamp")]
    InvalidTimestamp,
    #[error("missing signature")]
    MissingSignature,
    #[error("missing preimage")]
    MissingPreimage,
    #[error("threshold not met")]
    ThresholdNotMet,
}

/// A spend policy is a condition or set of conditions that must be met in
/// order to spend a UTXO.
#[derive(Debug, PartialEq, Clone)]
pub enum SpendPolicy {
    /// A policy that is only valid after a block height
    Above(u64),
    /// A policy that is only valid after a timestamp
    After(SystemTime),
    /// A policy that requires a valid signature from an ed25519 key pair
    PublicKey(PublicKey),
    /// A policy that requires a valid SHA256 hash preimage
    Hash([u8; 32]),
    /// A threshold policy that requires n-of-m sub-policies to be met
    Threshold(u8, Vec<SpendPolicy>),
    /// An opaque policy that is not directly spendable
    Opaque(Address),

    /// A set of v1 unlock conditions for compatibility with v1 transactions
    #[deprecated]
    UnlockConditions(UnlockConditions),
}

impl SpendPolicy {
    fn type_prefix(&self) -> u8 {
        match self {
            SpendPolicy::Above(_) => 1,
            SpendPolicy::After(_) => 2,
            SpendPolicy::PublicKey(_) => 3,
            SpendPolicy::Hash(_) => 4,
            SpendPolicy::Threshold(_, _) => 5,
            SpendPolicy::Opaque(_) => 6,
            #[allow(deprecated)]
            SpendPolicy::UnlockConditions(_) => 7,
        }
    }

    /// Create a policy that is only valid after a certain block height
    pub fn above(height: u64) -> Self {
        Self::Above(height)
    }

    /// Create a policy that is only valid after a certain timestamp
    pub fn after(timestamp: SystemTime) -> Self {
        Self::After(timestamp)
    }

    /// Create a policy that requires a valid signature from a public key
    pub fn public_key(pk: PublicKey) -> Self {
        Self::PublicKey(pk)
    }

    /// Create a policy that requires a hash preimage
    pub fn hash(hash: [u8; 32]) -> Self {
        Self::Hash(hash)
    }

    /// Create a threshold policy with n-of-m sub-policies
    pub fn threshold(n: u8, policies: Vec<SpendPolicy>) -> Self {
        for policy in policies.iter() {
            #[allow(deprecated)]
            if let SpendPolicy::UnlockConditions(_) = policy {
                panic!("UnlockConditions are not allowed in a threshold policy");
            }
        }
        Self::Threshold(n, policies)
    }

    /// Create a v1 unlock conditions policy for compatibility with v1
    /// transactions.
    #[deprecated]
    pub fn unlock_conditions(uc: UnlockConditions) -> Self {
        #[allow(deprecated)]
        Self::UnlockConditions(uc)
    }

    /// Returns the address of the policy. This is a hash of the policy that
    /// can be used to receive funds.
    pub fn address(&self) -> Address {
        #[allow(deprecated)]
        if let SpendPolicy::UnlockConditions(uc) = self {
            return uc.address();
        } else if let SpendPolicy::Opaque(addr) = self {
            return addr.clone();
        }

        let mut state = Params::new().hash_length(32).to_state();

        state.update("sia/address|".as_bytes());

        if let SpendPolicy::Threshold(n, of) = self {
            let mut opaque = Vec::with_capacity(of.len());
            for policy in of {
                opaque.push(SpendPolicy::Opaque(policy.address()))
            }
            to_writer(&mut state, &SpendPolicy::Threshold(*n, opaque)).unwrap();
        } else {
            to_writer(&mut state, self).unwrap();
        }
        Address::from(state.finalize().as_bytes())
    }

    /// Verify that the policy is satisfied by the given parameters.
    pub fn verify(
        &self,
        signing_state: &SigningState,
        hash: &Hash256,
        signatures: &mut Iter<'_, Signature>,
        preimages: &mut Iter<'_, Vec<u8>>,
    ) -> Result<(), ValidationError> {
        match self {
            SpendPolicy::Above(height) => {
                if *height > signing_state.index.height {
                    Err(ValidationError::InvalidHeight)
                } else {
                    Ok(())
                }
            }
            SpendPolicy::After(time) => {
                if *time > signing_state.median_timestamp {
                    Err(ValidationError::InvalidTimestamp)
                } else {
                    Ok(())
                }
            }
            SpendPolicy::PublicKey(pk) => signatures
                .next()
                .ok_or(ValidationError::MissingSignature)
                .and_then(|sig| {
                    pk.verify(hash.as_bytes(), sig)
                        .then_some(())
                        .ok_or(ValidationError::InvalidSignature)
                }),
            SpendPolicy::Hash(hash) => {
                let preimage = preimages.next().ok_or(ValidationError::MissingPreimage)?;

                let mut hasher = Sha256::new();
                hasher.update(preimage);

                let res: [u8; 32] = hasher.finalize().into();
                if res == *hash {
                    Ok(())
                } else {
                    Err(ValidationError::InvalidPreimage)
                }
            }
            SpendPolicy::Threshold(n, ref policies) => {
                let mut remaining = *n;
                for policy in policies {
                    #[allow(deprecated)]
                    if let SpendPolicy::UnlockConditions(_) = policy {
                        return Err(ValidationError::InvalidPolicy);
                    }

                    if policy
                        .verify(signing_state, hash, signatures, preimages)
                        .is_err()
                    {
                        continue;
                    }

                    remaining -= 1;
                    if remaining == 0 {
                        break;
                    }
                }
                if remaining == 0 {
                    Ok(())
                } else {
                    Err(ValidationError::ThresholdNotMet)
                }
            }
            #[allow(deprecated)]
            SpendPolicy::UnlockConditions(uc) => {
                if uc.timelock > signing_state.index.height {
                    return Err(ValidationError::InvalidHeight);
                } else if uc.required_signatures > 255 {
                    return Err(ValidationError::InvalidPolicy);
                }

                let mut remaining = uc.required_signatures;
                for pk in uc.public_keys.iter() {
                    let sig = signatures.next().ok_or(ValidationError::MissingSignature)?;
                    if pk.public_key().verify(hash.as_bytes(), sig) {
                        remaining -= 1;
                        if remaining == 0 {
                            break;
                        }
                    } else {
                        return Err(ValidationError::InvalidSignature);
                    }
                }

                if remaining == 0 {
                    return Ok(());
                }
                Err(ValidationError::ThresholdNotMet)
            }
            SpendPolicy::Opaque(_) => Err(ValidationError::OpaquePolicy),
        }
    }

    /// Encode the policy to a writer. This is used to handle recursive
    /// threshold policies. The version byte is only written for the top-level
    /// policy.
    fn serialize_policy<S: serde::ser::SerializeTuple>(&self, s: &mut S) -> Result<(), S::Error> {
        s.serialize_element(&self.type_prefix())?; // type prefix
        match self {
            SpendPolicy::Above(height) => s.serialize_element(height),
            SpendPolicy::After(time) => {
                s.serialize_element(&time.duration_since(time::UNIX_EPOCH).unwrap().as_secs())
            }
            SpendPolicy::PublicKey(pk) => {
                let mut arr: [u8; 32] = [0; 32];
                arr.copy_from_slice(pk.as_ref());
                s.serialize_element(&arr)
            }
            SpendPolicy::Hash(hash) => s.serialize_element(hash),
            SpendPolicy::Threshold(n, policies) => {
                let prefix = [*n, policies.len() as u8];
                s.serialize_element(&prefix)?;
                for policy in policies {
                    policy.serialize_policy(s)?;
                }
                Ok(())
            }
            SpendPolicy::Opaque(addr) => s.serialize_element(addr),
            #[allow(deprecated)]
            SpendPolicy::UnlockConditions(uc) => s.serialize_element(uc),
        }
    }
}

impl Serialize for SpendPolicy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_string())
        } else {
            // unknown length since policie are recursive and need custom
            // serialize/deserialize implementations anyway.
            let mut s = serializer.serialize_tuple(0)?;
            s.serialize_element(&1u8)?; // version
            self.serialize_policy(&mut s)?;
            s.end()
        }
    }
}

impl fmt::Display for SpendPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SpendPolicy::Above(height) => write!(f, "above({})", height),
            SpendPolicy::After(time) => {
                let duration = time
                    .duration_since(time::UNIX_EPOCH)
                    .map_err(|_| fmt::Error)?;
                write!(f, "after({})", duration.as_secs())
            }
            SpendPolicy::PublicKey(pk) => write!(f, "pk(0x{})", hex::encode(pk.as_ref())),
            SpendPolicy::Hash(hash) => write!(f, "h(0x{})", hex::encode(hash)),
            SpendPolicy::Threshold(n, policies) => {
                write!(f, "thresh({},[", n)?;
                for (i, policy) in policies.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", policy)?;
                }
                write!(f, "])")
            }
            SpendPolicy::Opaque(addr) => write!(f, "opaque(0x{})", hex::encode(addr)),
            #[allow(deprecated)]
            SpendPolicy::UnlockConditions(uc) => {
                write!(f, "uc({},{},[", uc.timelock, uc.required_signatures)?;
                for (i, pk) in uc.public_keys.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "0x{}", hex::encode(pk.public_key().as_ref()))?;
                }
                write!(f, "])")
            }
        }
    }
}

/// A policy that has been satisfied by a set of preimages and signatures.
pub struct SatisfiedPolicy {
    pub policy: SpendPolicy,
    pub preimages: Vec<Vec<u8>>,
    pub signatures: Vec<Signature>,
}

impl SatisfiedPolicy {
    /// Create a new satisfied policy from a policy, preimages, and signatures.
    pub fn new(policy: SpendPolicy, preimages: Vec<Vec<u8>>, signatures: Vec<Signature>) -> Self {
        Self {
            policy,
            preimages,
            signatures,
        }
    }

    /// Verify that the policy is satisfied by the given parameters.
    /// This is a convenience method that calls `verify` on the policy.
    pub fn verify(&self, state: &SigningState, sig_hash: &Hash256) -> Result<(), ValidationError> {
        self.policy.verify(
            state,
            sig_hash,
            &mut self.signatures.iter(),
            &mut self.preimages.iter(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{NetworkHardforks, PrivateKey};
    use crate::ChainIndex;
    use rand::prelude::*;
    use std::time::Duration;

    #[test]
    fn test_address() {
        let test_cases = vec![
            (
                SpendPolicy::PublicKey(PublicKey::new([
                    1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ])),
                "addr:55a7793237722c6df8222fd512063cb74228085ef1805c5184713648c159b919ac792fbad0e1",
            ),
            (
                SpendPolicy::Above(100),
                "addr:c2fba9b9607c800e80d9284ed0fb9a55737ba1bbd67311d0d9242dd6376bed0c6ee355e814fa",
            ),
            (
                SpendPolicy::After(time::UNIX_EPOCH + Duration::from_secs(1433600000)),
                "addr:5bdb96e33ffdf72619ad38bee57ad4db9eb242aeb2ee32020ba16179af5d46d501bd2011806b",
            ),
            (
                SpendPolicy::Hash([
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
                "addr:1cc0fc4cde659333cf7e61971cc5025c5a6b4759c9d1c1d438227c3eb57d841512d4cd4ce620",
            ),
            (
                SpendPolicy::Threshold(
                    2,
                    vec![
                        SpendPolicy::PublicKey(PublicKey::new([
                            1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0,
                        ])),
                        SpendPolicy::Above(100),
                        SpendPolicy::Threshold(
                            2,
                            vec![
                                SpendPolicy::PublicKey(PublicKey::new([0; 32])),
                                SpendPolicy::After(
                                    time::UNIX_EPOCH + Duration::from_secs(1433600000),
                                ),
                            ],
                        ),
                    ],
                ),
                "addr:30f516630280059c25ae92f3bf3c451be258ecd3249c43906e3d9dd9e86f2dc00ef5eeffc2c4",
            ),
        ];

        for (policy, expected) in test_cases {
            assert_eq!(policy.address().to_string(), expected);
        }
    }

    #[test]
    fn test_verify() {
        struct PolicyTest {
            policy: SpendPolicy,
            state: SigningState,
            hash: Hash256,
            signatures: Vec<Signature>,
            preimages: Vec<Vec<u8>>,
            result: Result<(), ValidationError>,
        }
        let test_cases = vec![
            PolicyTest {
                policy: SpendPolicy::Above(100),
                state: SigningState {
                    index: ChainIndex {
                        height: 99,
                        id: [0; 32],
                    },
                    median_timestamp: time::UNIX_EPOCH + Duration::from_secs(99),
                    hardforks: NetworkHardforks::default(),
                },
                hash: Hash256::default(),
                signatures: vec![],
                preimages: vec![],
                result: Err(ValidationError::InvalidHeight),
            },
            PolicyTest {
                policy: SpendPolicy::Above(100),
                state: SigningState {
                    index: ChainIndex {
                        height: 100,
                        id: [0; 32],
                    },
                    median_timestamp: time::UNIX_EPOCH + Duration::from_secs(99),
                    hardforks: NetworkHardforks::default(),
                },
                hash: Hash256::default(),
                signatures: vec![],
                preimages: vec![],
                result: Ok(()),
            },
            PolicyTest {
                policy: SpendPolicy::After(time::UNIX_EPOCH + Duration::from_secs(100)),
                state: SigningState {
                    index: ChainIndex {
                        height: 100,
                        id: [0; 32],
                    },
                    median_timestamp: time::UNIX_EPOCH + Duration::from_secs(99),
                    hardforks: NetworkHardforks::default(),
                },
                hash: Hash256::default(),
                signatures: vec![],
                preimages: vec![],
                result: Err(ValidationError::InvalidTimestamp),
            },
            PolicyTest {
                policy: SpendPolicy::After(time::UNIX_EPOCH + Duration::from_secs(100)),
                state: SigningState {
                    index: ChainIndex {
                        height: 100,
                        id: [0; 32],
                    },
                    median_timestamp: time::UNIX_EPOCH + Duration::from_secs(100),
                    hardforks: NetworkHardforks::default(),
                },
                hash: Hash256::default(),
                signatures: vec![],
                preimages: vec![],
                result: Ok(()),
            },
            PolicyTest {
                policy: SpendPolicy::PublicKey(PublicKey::new([0; 32])),
                state: SigningState {
                    index: ChainIndex {
                        height: 100,
                        id: [0; 32],
                    },
                    median_timestamp: time::UNIX_EPOCH + Duration::from_secs(100),
                    hardforks: NetworkHardforks::default(),
                },
                hash: Hash256::default(),
                signatures: vec![],
                preimages: vec![],
                result: Err(ValidationError::MissingSignature),
            },
            PolicyTest {
                policy: SpendPolicy::PublicKey(PublicKey::new([0; 32])),
                state: SigningState {
                    index: ChainIndex {
                        height: 100,
                        id: [0; 32],
                    },
                    median_timestamp: time::UNIX_EPOCH + Duration::from_secs(100),
                    hardforks: NetworkHardforks::default(),
                },
                hash: Hash256::default(),
                signatures: vec![Signature::new([0; 64])],
                preimages: vec![],
                result: Err(ValidationError::InvalidSignature),
            },
            {
                let pk = PrivateKey::from_seed(&random());
                let sig_hash = Hash256::new(random());

                PolicyTest {
                    policy: SpendPolicy::PublicKey(pk.public_key()),
                    state: SigningState {
                        index: ChainIndex {
                            height: 100,
                            id: [0; 32],
                        },
                        median_timestamp: time::UNIX_EPOCH + Duration::from_secs(100),
                        hardforks: NetworkHardforks::default(),
                    },
                    hash: sig_hash,
                    signatures: vec![pk.sign(sig_hash.as_bytes())],
                    preimages: vec![],
                    result: Ok(()),
                }
            },
            {
                let pk = PrivateKey::from_seed(&random());
                let sig_hash = Hash256::new(random());

                PolicyTest {
                    policy: SpendPolicy::Threshold(
                        2,
                        vec![
                            SpendPolicy::PublicKey(pk.public_key()),
                            SpendPolicy::Above(100),
                        ],
                    ),
                    state: SigningState {
                        index: ChainIndex {
                            height: 99,
                            id: [0; 32],
                        },
                        median_timestamp: time::UNIX_EPOCH + Duration::from_secs(100),
                        hardforks: NetworkHardforks::default(),
                    },
                    hash: sig_hash,
                    signatures: vec![pk.sign(sig_hash.as_bytes())],
                    preimages: vec![],
                    result: Err(ValidationError::ThresholdNotMet),
                }
            },
            {
                let pk = PrivateKey::from_seed(&random());
                let sig_hash = Hash256::new(random());

                PolicyTest {
                    policy: SpendPolicy::Threshold(
                        2,
                        vec![
                            SpendPolicy::PublicKey(pk.public_key()),
                            SpendPolicy::Above(100),
                        ],
                    ),
                    state: SigningState {
                        index: ChainIndex {
                            height: 100,
                            id: [0; 32],
                        },
                        median_timestamp: time::UNIX_EPOCH + Duration::from_secs(100),
                        hardforks: NetworkHardforks::default(),
                    },
                    hash: sig_hash,
                    signatures: vec![Signature::new([0; 64])],
                    preimages: vec![],
                    result: Err(ValidationError::ThresholdNotMet),
                }
            },
            {
                let pk = PrivateKey::from_seed(&random());
                let sig_hash = Hash256::new(random());

                PolicyTest {
                    policy: SpendPolicy::Threshold(
                        2,
                        vec![
                            SpendPolicy::PublicKey(pk.public_key()),
                            SpendPolicy::Above(100),
                        ],
                    ),
                    state: SigningState {
                        index: ChainIndex {
                            height: 100,
                            id: [0; 32],
                        },
                        median_timestamp: time::UNIX_EPOCH + Duration::from_secs(100),
                        hardforks: NetworkHardforks::default(),
                    },
                    hash: sig_hash,
                    signatures: vec![pk.sign(sig_hash.as_bytes())],
                    preimages: vec![],
                    result: Ok(()),
                }
            },
            {
                let pk = PrivateKey::from_seed(&random());
                let sig_hash = Hash256::new(random());

                PolicyTest {
                    policy: SpendPolicy::Threshold(
                        1,
                        vec![
                            SpendPolicy::PublicKey(pk.public_key()),
                            SpendPolicy::Opaque(Address::new([0; 32])),
                        ],
                    ),
                    state: SigningState {
                        index: ChainIndex {
                            height: 100,
                            id: [0; 32],
                        },
                        median_timestamp: time::UNIX_EPOCH + Duration::from_secs(100),
                        hardforks: NetworkHardforks::default(),
                    },
                    hash: sig_hash,
                    signatures: vec![pk.sign(sig_hash.as_ref())],
                    preimages: vec![],
                    result: Ok(()),
                }
            },
            {
                let pk = PrivateKey::from_seed(&random());
                let sig_hash = Hash256::new(random());

                PolicyTest {
                    policy: SpendPolicy::Threshold(
                        1,
                        vec![
                            SpendPolicy::PublicKey(pk.public_key()),
                            SpendPolicy::Opaque(Address::new([0; 32])),
                        ],
                    ),
                    state: SigningState {
                        index: ChainIndex {
                            height: 100,
                            id: [0; 32],
                        },
                        median_timestamp: time::UNIX_EPOCH + Duration::from_secs(100),
                        hardforks: NetworkHardforks::default(),
                    },
                    hash: sig_hash,
                    signatures: vec![],
                    preimages: vec![],
                    result: Err(ValidationError::ThresholdNotMet),
                }
            },
            {
                let mut preimage = [0; 64];
                thread_rng().fill(&mut preimage);

                let mut hasher = Sha256::new();
                hasher.update(preimage);
                let h: [u8; 32] = hasher.finalize().into();

                PolicyTest {
                    policy: SpendPolicy::Hash(h),
                    state: SigningState {
                        index: ChainIndex {
                            height: 100,
                            id: [0; 32],
                        },
                        median_timestamp: time::UNIX_EPOCH + Duration::from_secs(100),
                        hardforks: NetworkHardforks::default(),
                    },
                    hash: Hash256::default(),
                    signatures: vec![],
                    preimages: vec![],
                    result: Err(ValidationError::MissingPreimage),
                }
            },
            {
                let mut preimage = [0; 64];
                thread_rng().fill(&mut preimage);

                let mut hasher = Sha256::new();
                hasher.update(preimage);
                let h: [u8; 32] = hasher.finalize().into();

                PolicyTest {
                    policy: SpendPolicy::Hash(h),
                    state: SigningState {
                        index: ChainIndex {
                            height: 100,
                            id: [0; 32],
                        },
                        median_timestamp: time::UNIX_EPOCH + Duration::from_secs(100),
                        hardforks: NetworkHardforks::default(),
                    },
                    hash: Hash256::default(),
                    signatures: vec![],
                    preimages: vec![[0; 64].to_vec()],
                    result: Err(ValidationError::InvalidPreimage),
                }
            },
            {
                let mut preimage = [0; 64];
                thread_rng().fill(&mut preimage);

                let mut hasher = Sha256::new();
                hasher.update(preimage);
                let h: [u8; 32] = hasher.finalize().into();

                PolicyTest {
                    policy: SpendPolicy::Hash(h),
                    state: SigningState {
                        index: ChainIndex {
                            height: 100,
                            id: [0; 32],
                        },
                        median_timestamp: time::UNIX_EPOCH + Duration::from_secs(100),
                        hardforks: NetworkHardforks::default(),
                    },
                    hash: Hash256::default(),
                    signatures: vec![],
                    preimages: vec![preimage.to_vec()],
                    result: Ok(()),
                }
            },
        ];

        for test in test_cases {
            let result = test.policy.verify(
                &test.state,
                &test.hash,
                &mut test.signatures.iter(),
                &mut test.preimages.iter(),
            );
            assert_eq!(result, test.result, "{}", test.policy);
        }
    }

    #[test]
    fn test_opaque_policy() {
        let test_cases = vec![
            SpendPolicy::above(100),
            SpendPolicy::after(time::UNIX_EPOCH + Duration::from_secs(100)),
            SpendPolicy::public_key(PublicKey::new([0; 32])),
            SpendPolicy::hash([0; 32]),
            SpendPolicy::threshold(
                2,
                vec![
                    SpendPolicy::public_key(PublicKey::new([0; 32])),
                    SpendPolicy::above(100),
                ],
            ),
            SpendPolicy::threshold(
                2,
                vec![
                    SpendPolicy::public_key(PublicKey::new([0; 32])),
                    SpendPolicy::above(100),
                    SpendPolicy::threshold(
                        2,
                        vec![
                            SpendPolicy::public_key(PublicKey::new([0; 32])),
                            SpendPolicy::after(time::UNIX_EPOCH + Duration::from_secs(100)),
                        ],
                    ),
                    SpendPolicy::PublicKey(PublicKey::new([1; 32])),
                ],
            ),
        ];

        for (i, policy) in test_cases.into_iter().enumerate() {
            let policy = policy.clone();
            let address = policy.address();
            let expected_address = address.to_string();
            let opaque = SpendPolicy::Opaque(address);
            assert_eq!(
                opaque.address().to_string(),
                expected_address,
                "test case {}",
                i
            );

            if let SpendPolicy::Threshold(n, of) = policy {
                // test that the address of opaque threshold policies is the
                // same as the address of normal threshold policies
                for j in 0..of.len() {
                    let mut of = of.clone();
                    of[j] = SpendPolicy::Opaque(of[j].address());
                    let opaque_policy = SpendPolicy::threshold(n, of);

                    assert_eq!(
                        opaque_policy.address().to_string(),
                        expected_address,
                        "test case {}-{}",
                        i,
                        j
                    );
                }
            }
        }
    }
}
