use blake2b_simd::Params;
use core::{fmt, slice::Iter};
use sha2::{Digest, Sha256};
use std::{
    io::{Error, Write},
    time::{self, SystemTime},
};

use crate::{Address, Hash256, PublicKey, SiaEncodable, Signature, UnlockConditions};

#[derive(Debug, PartialEq)]
pub enum PolicyValidationError {
    OpaquePolicy,
    InvalidPolicy,
    InvalidSignature,
    InvalidPreimage,
    InvalidHeight,
    InvalidTimestamp,
    MissingSignature,
    MissingPreimage,
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
            return *addr;
        }

        let mut state = Params::new().hash_length(32).to_state();

        state.update("sia/address|".as_bytes());

        if let SpendPolicy::Threshold(n, of) = self {
            let mut opaque = Vec::with_capacity(of.len());
            for policy in of {
                opaque.push(SpendPolicy::Opaque(policy.address()))
            }
            SpendPolicy::Threshold(*n, opaque)
                .encode(&mut state)
                .unwrap();
        } else {
            self.encode(&mut state).unwrap();
        }
        Address::new(state.finalize().as_bytes().try_into().unwrap())
    }

    /// Verify that the policy is satisfied by the given parameters.
    pub fn verify(
        &self,
        current_height: u64,
        current_timestamp: SystemTime,
        hash: &Hash256,
        signatures: &mut Iter<'_, Signature>,
        preimages: &mut Iter<'_, Vec<u8>>,
    ) -> Result<(), PolicyValidationError> {
        match self {
            SpendPolicy::Above(height) => {
                if current_height >= *height {
                    return Ok(());
                }
                Err(PolicyValidationError::InvalidHeight)
            }
            SpendPolicy::After(time) => {
                if current_timestamp >= *time {
                    return Ok(());
                }
                Err(PolicyValidationError::InvalidTimestamp)
            }
            SpendPolicy::PublicKey(pk) => {
                let sig = signatures
                    .next()
                    .ok_or(PolicyValidationError::MissingSignature)?;
                if pk.verify(hash.as_ref(), sig) {
                    Ok(())
                } else {
                    Err(PolicyValidationError::InvalidSignature)
                }
            }
            SpendPolicy::Hash(hash) => {
                let preimage = preimages
                    .next()
                    .ok_or(PolicyValidationError::MissingPreimage)?;

                let mut hasher = Sha256::new();
                hasher.update(preimage);

                let res: [u8; 32] = hasher.finalize().into();
                if res == *hash {
                    Ok(())
                } else {
                    Err(PolicyValidationError::InvalidPreimage)
                }
            }
            SpendPolicy::Threshold(n, ref policies) => {
                let mut remaining = *n;
                for policy in policies {
                    #[allow(deprecated)]
                    if let SpendPolicy::UnlockConditions(_) = policy {
                        return Err(PolicyValidationError::InvalidPolicy);
                    }

                    if policy
                        .verify(
                            current_height,
                            current_timestamp,
                            hash,
                            signatures,
                            preimages,
                        )
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
                    Err(PolicyValidationError::ThresholdNotMet)
                }
            }
            #[allow(deprecated)]
            SpendPolicy::UnlockConditions(uc) => {
                if uc.timelock > current_height {
                    return Err(PolicyValidationError::InvalidHeight);
                } else if uc.required_signatures > 255 {
                    return Err(PolicyValidationError::InvalidPolicy);
                }

                let mut remaining = uc.required_signatures;
                for pk in uc.public_keys.iter() {
                    let sig = signatures
                        .next()
                        .ok_or(PolicyValidationError::MissingSignature)?;
                    if pk.public_key().verify(hash.as_ref(), sig) {
                        remaining -= 1;
                        if remaining == 0 {
                            break;
                        }
                    } else {
                        return Err(PolicyValidationError::InvalidSignature);
                    }
                }

                if remaining == 0 {
                    return Ok(());
                }
                Err(PolicyValidationError::ThresholdNotMet)
            }
            SpendPolicy::Opaque(_) => Err(PolicyValidationError::OpaquePolicy),
        }
    }

    /// Encode the policy to a writer. This is used by the SiaEncodable trait to
    /// handle recursive threshold policies. The version byte is only written
    /// for the top-level policy.
    fn encode_policy<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&[self.type_prefix()])?; // type prefix
        match self {
            SpendPolicy::Above(height) => w.write_all(&height.to_le_bytes()),
            SpendPolicy::After(time) => w.write_all(
                &time
                    .duration_since(time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .to_le_bytes(),
            ),
            SpendPolicy::PublicKey(pk) => w.write_all(pk.as_ref()),
            SpendPolicy::Hash(hash) => w.write_all(hash),
            SpendPolicy::Threshold(n, policies) => {
                w.write_all(&[*n, policies.len() as u8])?;
                for policy in policies {
                    policy.encode_policy(w)?;
                }
                Ok(())
            }
            SpendPolicy::Opaque(addr) => w.write_all(addr.as_ref()),
            #[allow(deprecated)]
            SpendPolicy::UnlockConditions(uc) => uc.encode(w),
        }
    }
}

impl SiaEncodable for SpendPolicy {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&[1])?; // version
        self.encode_policy(w)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PrivateKey;
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
            height: u64,
            timestamp: SystemTime,
            hash: Hash256,
            signatures: Vec<Signature>,
            preimages: Vec<Vec<u8>>,
            result: Result<(), PolicyValidationError>,
        }
        let test_cases = vec![
            PolicyTest {
                policy: SpendPolicy::Above(100),
                height: 99,
                timestamp: SystemTime::now(),
                hash: Hash256([0; 32]),
                signatures: vec![],
                preimages: vec![],
                result: Err(PolicyValidationError::InvalidHeight),
            },
            PolicyTest {
                policy: SpendPolicy::Above(100),
                height: 100,
                timestamp: SystemTime::now(),
                hash: Hash256([0; 32]),
                signatures: vec![],
                preimages: vec![],
                result: Ok(()),
            },
            PolicyTest {
                policy: SpendPolicy::After(time::UNIX_EPOCH + Duration::from_secs(100)),
                height: 0,
                timestamp: time::UNIX_EPOCH + Duration::from_secs(99),
                hash: Hash256([0; 32]),
                signatures: vec![],
                preimages: vec![],
                result: Err(PolicyValidationError::InvalidTimestamp),
            },
            PolicyTest {
                policy: SpendPolicy::After(time::UNIX_EPOCH + Duration::from_secs(100)),
                height: 0,
                timestamp: SystemTime::now(),
                hash: Hash256([0; 32]),
                signatures: vec![],
                preimages: vec![],
                result: Ok(()),
            },
            PolicyTest {
                policy: SpendPolicy::PublicKey(PublicKey::new([0; 32])),
                height: 0,
                timestamp: SystemTime::now(),
                hash: Hash256([0; 32]),
                signatures: vec![],
                preimages: vec![],
                result: Err(PolicyValidationError::MissingSignature),
            },
            PolicyTest {
                policy: SpendPolicy::PublicKey(PublicKey::new([0; 32])),
                height: 0,
                timestamp: SystemTime::now(),
                hash: Hash256([0; 32]),
                signatures: vec![Signature::new([0; 64])],
                preimages: vec![],
                result: Err(PolicyValidationError::InvalidSignature),
            },
            {
                let mut seed = [0; 32];
                thread_rng().fill(&mut seed);
                let pk = PrivateKey::from_seed(&seed);
                let mut sig_hash = [0; 32];
                thread_rng().fill(&mut sig_hash);

                PolicyTest {
                    policy: SpendPolicy::PublicKey(pk.public_key()),
                    height: 0,
                    timestamp: SystemTime::now(),
                    hash: Hash256(sig_hash),
                    signatures: vec![pk.sign_hash(&sig_hash)],
                    preimages: vec![],
                    result: Ok(()),
                }
            },
            {
                let mut seed = [0; 32];
                thread_rng().fill(&mut seed);
                let pk = PrivateKey::from_seed(&seed);
                let mut sig_hash = [0; 32];
                thread_rng().fill(&mut sig_hash);

                PolicyTest {
                    policy: SpendPolicy::Threshold(
                        2,
                        vec![
                            SpendPolicy::PublicKey(pk.public_key()),
                            SpendPolicy::Above(100),
                        ],
                    ),
                    height: 0,
                    timestamp: SystemTime::now(),
                    hash: Hash256(sig_hash),
                    signatures: vec![pk.sign_hash(&sig_hash)],
                    preimages: vec![],
                    result: Err(PolicyValidationError::ThresholdNotMet),
                }
            },
            {
                let mut seed = [0; 32];
                thread_rng().fill(&mut seed);
                let pk = PrivateKey::from_seed(&seed);
                let mut sig_hash = [0; 32];
                thread_rng().fill(&mut sig_hash);

                PolicyTest {
                    policy: SpendPolicy::Threshold(
                        2,
                        vec![
                            SpendPolicy::PublicKey(pk.public_key()),
                            SpendPolicy::Above(100),
                        ],
                    ),
                    height: 100,
                    timestamp: SystemTime::now(),
                    hash: Hash256(sig_hash),
                    signatures: vec![Signature::new([0; 64])],
                    preimages: vec![],
                    result: Err(PolicyValidationError::ThresholdNotMet),
                }
            },
            {
                let mut seed = [0; 32];
                thread_rng().fill(&mut seed);
                let pk = PrivateKey::from_seed(&seed);
                let mut sig_hash = [0; 32];
                thread_rng().fill(&mut sig_hash);

                PolicyTest {
                    policy: SpendPolicy::Threshold(
                        2,
                        vec![
                            SpendPolicy::PublicKey(pk.public_key()),
                            SpendPolicy::Above(100),
                        ],
                    ),
                    height: 100,
                    timestamp: SystemTime::now(),
                    hash: Hash256(sig_hash),
                    signatures: vec![pk.sign_hash(&sig_hash)],
                    preimages: vec![],
                    result: Ok(()),
                }
            },
            {
                let mut seed = [0; 32];
                thread_rng().fill(&mut seed);
                let pk = PrivateKey::from_seed(&seed);
                let mut sig_hash = [0; 32];
                thread_rng().fill(&mut sig_hash);

                PolicyTest {
                    policy: SpendPolicy::Threshold(
                        1,
                        vec![
                            SpendPolicy::PublicKey(pk.public_key()),
                            SpendPolicy::Opaque(Address::new([0; 32])),
                        ],
                    ),
                    height: 100,
                    timestamp: SystemTime::now(),
                    hash: Hash256(sig_hash),
                    signatures: vec![pk.sign_hash(&sig_hash)],
                    preimages: vec![],
                    result: Ok(()),
                }
            },
            {
                let mut seed = [0; 32];
                thread_rng().fill(&mut seed);
                let pk = PrivateKey::from_seed(&seed);
                let mut sig_hash = [0; 32];
                thread_rng().fill(&mut sig_hash);

                PolicyTest {
                    policy: SpendPolicy::Threshold(
                        1,
                        vec![
                            SpendPolicy::PublicKey(pk.public_key()),
                            SpendPolicy::Opaque(Address::new([0; 32])),
                        ],
                    ),
                    height: 100,
                    timestamp: SystemTime::now(),
                    hash: Hash256(sig_hash),
                    signatures: vec![],
                    preimages: vec![],
                    result: Err(PolicyValidationError::ThresholdNotMet),
                }
            },
        ];

        for test in test_cases {
            let result = test.policy.verify(
                test.height,
                test.timestamp,
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
            let opaque = SpendPolicy::Opaque(address);
            assert_eq!(
                opaque.address().to_string(),
                address.to_string(),
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
                        address.to_string(),
                        opaque_policy.address().to_string(),
                        "test case {}-{}",
                        i,
                        j
                    );
                }
            }
        }
    }
}
