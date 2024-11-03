use crate::encoding::to_writer;
use crate::signing::{PublicKey, Signature};
#[allow(deprecated)]
use crate::unlock_conditions::UnlockConditions;
use crate::{Address, Hash256};
use blake2b_simd::Params;
use chrono::{DateTime, Utc};
use core::fmt;
use serde::ser::{SerializeStruct, SerializeTuple};
use serde::Serialize;
use serde_json::json;
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
    After(DateTime<Utc>),
    /// A policy that requires a valid signature from an ed25519 key pair
    PublicKey(PublicKey),
    /// A policy that requires a valid SHA256 hash preimage
    Hash(Hash256),
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

    fn type_str(&self) -> &str {
        match self {
            SpendPolicy::Above(_) => "above",
            SpendPolicy::After(_) => "after",
            SpendPolicy::PublicKey(_) => "pk",
            SpendPolicy::Hash(_) => "h",
            SpendPolicy::Threshold(_, _) => "thresh",
            SpendPolicy::Opaque(_) => "opaque",
            #[allow(deprecated)]
            SpendPolicy::UnlockConditions(_) => "uc",
        }
    }

    /// Create a policy that is only valid after a certain block height
    pub fn above(height: u64) -> Self {
        Self::Above(height)
    }

    /// Create a policy that is only valid after a certain timestamp
    pub fn after(timestamp: DateTime<Utc>) -> Self {
        Self::After(timestamp)
    }

    /// Create a policy that requires a valid signature from a public key
    pub fn public_key(pk: PublicKey) -> Self {
        Self::PublicKey(pk)
    }

    /// Create a policy that requires a hash preimage
    pub fn hash(hash: Hash256) -> Self {
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

    /// Encode the policy to a writer. This is used to handle recursive
    /// threshold policies. The version byte is only written for the top-level
    /// policy.
    fn serialize_policy<S: serde::ser::SerializeTuple>(&self, s: &mut S) -> Result<(), S::Error> {
        s.serialize_element(&self.type_prefix())?; // type prefix
        match self {
            SpendPolicy::Above(height) => s.serialize_element(height),
            SpendPolicy::After(time) => {
                let ts = time.timestamp() as u64;
                s.serialize_element(&ts)
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
        if !serializer.is_human_readable() {
            let mut s = serializer.serialize_tuple(0)?;
            s.serialize_element(&1u8)?; // version
            self.serialize_policy(&mut s)?;
            return s.end();
        }

        let mut state = serializer.serialize_struct("SpendPolicy", 2)?;
        state.serialize_field("type", self.type_str())?;
        match self {
            SpendPolicy::Above(height) => {
                state.serialize_field("policy", height)?;
            }
            SpendPolicy::After(time) => {
                let ts = time.timestamp() as u64;
                state.serialize_field("policy", &ts)?;
            }
            SpendPolicy::PublicKey(pk) => {
                state.serialize_field("policy", &pk)?;
            }
            SpendPolicy::Hash(hash) => {
                state.serialize_field("policy", &hash)?;
            }
            SpendPolicy::Threshold(n, policies) => {
                state.serialize_field(
                    "policy",
                    &json!({
                        "n": n,
                        "of": policies,
                    }),
                )?;
            }
            SpendPolicy::Opaque(addr) => {
                state.serialize_field("policy", addr)?;
            }
            #[allow(deprecated)]
            SpendPolicy::UnlockConditions(uc) => {
                state.serialize_field("policy", uc)?;
            }
        }
        state.end()
    }
}

impl fmt::Display for SpendPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SpendPolicy::Above(height) => write!(f, "above({})", height),
            SpendPolicy::After(time) => {
                write!(f, "after({})", time.timestamp() as u64)
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
                write!(f, "uc({},{},[", uc.timelock, uc.signatures_required)?;
                for (i, uk) in uc.public_keys.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{}", uk)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_address() {
        let test_cases = vec![
            (
                SpendPolicy::PublicKey(PublicKey::new([
                    1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ])),
                "55a7793237722c6df8222fd512063cb74228085ef1805c5184713648c159b919ac792fbad0e1",
            ),
            (
                SpendPolicy::Above(100),
                "c2fba9b9607c800e80d9284ed0fb9a55737ba1bbd67311d0d9242dd6376bed0c6ee355e814fa",
            ),
            (
                SpendPolicy::After(Utc.timestamp_opt(1433600000, 0).unwrap()),
                "5bdb96e33ffdf72619ad38bee57ad4db9eb242aeb2ee32020ba16179af5d46d501bd2011806b",
            ),
            (
                SpendPolicy::Hash(Hash256::from([
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ])),
                "1cc0fc4cde659333cf7e61971cc5025c5a6b4759c9d1c1d438227c3eb57d841512d4cd4ce620",
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
                                SpendPolicy::After(Utc.timestamp_opt(1433600000, 0).unwrap()),
                            ],
                        ),
                    ],
                ),
                "30f516630280059c25ae92f3bf3c451be258ecd3249c43906e3d9dd9e86f2dc00ef5eeffc2c4",
            ),
        ];

        for (policy, expected) in test_cases {
            assert_eq!(policy.address().to_string(), expected);
        }
    }

    #[test]
    fn test_opaque_policy() {
        let test_cases = vec![
            SpendPolicy::above(100),
            SpendPolicy::after(Utc.timestamp_opt(100, 0).unwrap()),
            SpendPolicy::public_key(PublicKey::new([0; 32])),
            SpendPolicy::hash(Hash256::from([0; 32])),
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
                            SpendPolicy::after(Utc.timestamp_opt(100, 0).unwrap()),
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

    #[test]
    fn test_policy_json() {
        let test_cases = vec![
            (SpendPolicy::above(100), "{\"type\":\"above\",\"policy\":100}"),
            ( SpendPolicy::after(Utc.timestamp_opt(100, 0).unwrap()), "{\"type\":\"after\",\"policy\":100}"),
            ( SpendPolicy::public_key(PublicKey::new([1; 32])), "{\"type\":\"pk\",\"policy\":\"ed25519:0101010101010101010101010101010101010101010101010101010101010101\"}"),
            ( SpendPolicy::hash(Hash256::from([0; 32])), "{\"type\":\"h\",\"policy\":\"0000000000000000000000000000000000000000000000000000000000000000\"}"),
            (
				SpendPolicy::threshold(
					2,
					vec![
						SpendPolicy::public_key(PublicKey::new([0; 32])),
						SpendPolicy::above(100),
					],
				),
				"{\"type\":\"thresh\",\"policy\":{\"n\":2,\"of\":[{\"policy\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"type\":\"pk\"},{\"policy\":100,\"type\":\"above\"}]}}",
			),
            (
				SpendPolicy::threshold(
					2,
					vec![
						SpendPolicy::public_key(PublicKey::new([0; 32])),
						SpendPolicy::above(100),
						SpendPolicy::threshold(
							2,
							vec![
								SpendPolicy::public_key(PublicKey::new([0; 32])),
								SpendPolicy::after(Utc.timestamp_opt(100, 0).unwrap()),
							],
						),
						SpendPolicy::PublicKey(PublicKey::new([0; 32])),
					],
				),
				"{\"type\":\"thresh\",\"policy\":{\"n\":2,\"of\":[{\"policy\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"type\":\"pk\"},{\"policy\":100,\"type\":\"above\"},{\"policy\":{\"n\":2,\"of\":[{\"policy\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"type\":\"pk\"},{\"policy\":100,\"type\":\"after\"}]},\"type\":\"thresh\"},{\"policy\":\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"type\":\"pk\"}]}}"
			),
			(
				#[allow(deprecated)]
				SpendPolicy::UnlockConditions(UnlockConditions {
					timelock: 100,
					signatures_required: 2,
					public_keys: vec![
						PublicKey::new([0; 32]).into(),
						PublicKey::new([1; 32]).into(),
					],
				}),
				"{\"type\":\"uc\",\"policy\":{\"timelock\":100,\"publicKeys\":[\"ed25519:0000000000000000000000000000000000000000000000000000000000000000\",\"ed25519:0101010101010101010101010101010101010101010101010101010101010101\"],\"signaturesRequired\":2}}",
			)
        ];

        for (policy, expected) in test_cases {
            let json = serde_json::to_string(&policy).unwrap();
            assert_eq!(json, expected);
        }
    }
}
