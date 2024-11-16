use crate::address;
use serde::{Deserialize, Serialize};
use sia_derive::{SiaDecode, SiaEncode};
use time::{Duration, OffsetDateTime};

use crate::encoding::{self, SiaDecodable, SiaEncodable};
use crate::types::{Address, BlockID, ChainIndex, Currency, Hash256, SiacoinOutput, Work};

/// HardforkDevAddr contains the parameters for a hardfork that changed
/// the developer address.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardforkDevAddr {
    pub height: u64,
    pub old_address: Address,
    pub new_address: Address,
}

/// HardforkTax contains the parameters for a hardfork that changed the
/// SiaFund file contract tax calculation.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardforkTax {
    pub height: u64,
}

/// HardforkStorageProof contains the parameters for a hardfork that changed
/// the leaf selection algorithm for storage proofs.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardforkStorageProof {
    pub height: u64,
}

/// HardforkBlockSubsidy contains the parameters for a hardfork that changed
/// the difficulty adjustment algorithm.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardforkOak {
    pub height: u64,
    pub fix_height: u64,
    #[serde(with = "time::serde::rfc3339")]
    pub genesis_timestamp: OffsetDateTime,
}

/// HardforkASIC contains the parameters for a hardfork that changed the mining algorithm
/// to Blake2B-Sia
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardforkASIC {
    pub height: u64,
    #[serde(with = "crate::types::utils::nano_second_duration")]
    pub oak_time: Duration,
    pub oak_target: BlockID,
}

/// HardforkFoundation contains the parameters for a hardfork that introduced the Foundation
/// subsidy.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardforkFoundation {
    pub height: u64,
    pub primary_address: Address,
    pub failsafe_address: Address,
}

/// HardforkV2 contains the parameters for the v2 consensus hardfork.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HardforkV2 {
    pub allow_height: u64,
    pub require_height: u64,
}

/// Network contains consensus parameters that are network-specific.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Network {
    pub name: String,

    pub initial_coinbase: Currency,
    pub minimum_coinbase: Currency,
    pub initial_target: BlockID,
    #[serde(with = "crate::types::utils::nano_second_duration")]
    pub block_interval: Duration,
    pub maturity_delay: u64,

    pub hardfork_dev_addr: HardforkDevAddr,
    pub hardfork_tax: HardforkTax,
    pub hardfork_storage_proof: HardforkStorageProof,
    pub hardfork_oak: HardforkOak,
    #[serde(rename = "hardforkASIC")]
    pub hardfork_asic: HardforkASIC,
    pub hardfork_foundation: HardforkFoundation,
    pub hardfork_v2: HardforkV2,
}

const fn unix_timestamp(secs: i64) -> OffsetDateTime {
    match OffsetDateTime::from_unix_timestamp(secs) {
        Ok(t) => t,
        Err(_) => panic!("invalid timestamp"),
    }
}

impl Network {
    pub fn mainnet() -> Self {
        Network {
            name: "mainnet".to_string(),
            initial_coinbase: Currency::siacoins(300_000),
            minimum_coinbase: Currency::siacoins(30_000),
            initial_target: BlockID::new([
                0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0,
            ]),
            block_interval: Duration::minutes(10),
            maturity_delay: 144,

            hardfork_dev_addr: HardforkDevAddr {
                height: 10000,
                old_address: address!(
                    "7d0c44f7664e2d34e53efde0661a6f628ec9264785ae8e3cd7c973e8d190c3c97b5e3ecbc567"
                ),
                new_address: address!(
                    "f371c70bce9eb8979cd5099f599ec4e4fcb14e0afcf31f9791e03e6496a4c0b358c98279730b"
                ),
            },
            hardfork_tax: HardforkTax { height: 21000 },
            hardfork_storage_proof: HardforkStorageProof { height: 100000 },
            hardfork_oak: HardforkOak {
                height: 135000,
                fix_height: 139000,
                genesis_timestamp: unix_timestamp(1433600000), // June 6th, 2015 @ 2:13pm UTC
            },
            hardfork_asic: HardforkASIC {
                height: 179000,
                oak_time: Duration::seconds(120000),
                oak_target: BlockID::new([
                    0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
            },
            hardfork_foundation: HardforkFoundation {
                height: 298000,
                primary_address: address!(
                    "053b2def3cbdd078c19d62ce2b4f0b1a3c5e0ffbeeff01280efb1f8969b2f5bb4fdc680f0807"
                ),
                failsafe_address: address!(
                    "27c22a6c6e6645802a3b8fa0e5374657438ef12716d2205d3e866272de1b644dbabd53d6d560"
                ),
            },
            hardfork_v2: HardforkV2 {
                allow_height: 1000000,
                require_height: 1025000,
            },
        }
    }

    pub fn zen() -> Self {
        Network {
            name: "zen".to_string(),
            initial_coinbase: Currency::siacoins(300_000),
            minimum_coinbase: Currency::siacoins(300_000),
            initial_target: BlockID::new([
                0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            block_interval: Duration::minutes(10),
            maturity_delay: 144,

            hardfork_dev_addr: HardforkDevAddr {
                height: 1,
                old_address: Address::new([0u8; 32]),
                new_address: Address::new([0u8; 32]),
            },
            hardfork_tax: HardforkTax { height: 2 },
            hardfork_storage_proof: HardforkStorageProof { height: 5 },
            hardfork_oak: HardforkOak {
                height: 10,
                fix_height: 12,
                genesis_timestamp: unix_timestamp(1673600000), // January 13, 2023 @ 08:53 GMT
            },
            hardfork_asic: HardforkASIC {
                height: 20,
                oak_time: Duration::seconds(10000),
                oak_target: BlockID::new([
                    0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
            },
            hardfork_foundation: HardforkFoundation {
                height: 30,
                primary_address: address!(
                    "053b2def3cbdd078c19d62ce2b4f0b1a3c5e0ffbeeff01280efb1f8969b2f5bb4fdc680f0807"
                ),
                failsafe_address: Address::new([0u8; 32]),
            },
            hardfork_v2: HardforkV2 {
                allow_height: 100000,
                require_height: 102000,
            },
        }
    }

    pub fn anagami() -> Self {
        Network {
            name: "anagami".to_string(),
            initial_coinbase: Currency::siacoins(300_000),
            minimum_coinbase: Currency::siacoins(300_000),
            initial_target: BlockID::new([
                0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ]),
            block_interval: Duration::minutes(10),
            maturity_delay: 144,

            hardfork_dev_addr: HardforkDevAddr {
                height: 1,
                old_address: Address::new([0u8; 32]),
                new_address: Address::new([0u8; 32]),
            },
            hardfork_tax: HardforkTax { height: 2 },
            hardfork_storage_proof: HardforkStorageProof { height: 5 },
            hardfork_oak: HardforkOak {
                height: 10,
                fix_height: 12,
                genesis_timestamp: unix_timestamp(1724284800), // August 22, 2024 @ 0:00 UTC
            },
            hardfork_asic: HardforkASIC {
                height: 20,
                oak_time: Duration::seconds(10000),
                oak_target: BlockID::new([
                    0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ]),
            },
            hardfork_foundation: HardforkFoundation {
                height: 30,
                primary_address: address!(
                    "241352c83da002e61f57e96b14f3a5f8b5de22156ce83b753ea495e64f1affebae88736b2347"
                ),
                failsafe_address: Address::new([0u8; 32]),
            },
            hardfork_v2: HardforkV2 {
                allow_height: 2016,
                require_height: 2016 + 288,
            },
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, SiaEncode, SiaDecode)]
#[serde(rename_all = "camelCase")]
pub struct Elements {
    pub num_leaves: u64,
    pub trees: Vec<Hash256>, // note: this is not technically correct, but it will work for now
}

/// State represents the state of the chain as of a particular block.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct State {
    pub index: ChainIndex,
    #[serde(with = "crate::types::utils::timestamp_array")]
    pub prev_timestamps: [OffsetDateTime; 11],
    pub depth: BlockID,
    pub child_target: BlockID,
    pub siafund_pool: Currency,

    // Oak hardfork state
    #[serde(with = "crate::types::utils::nano_second_duration")]
    pub oak_time: Duration,
    pub oak_target: BlockID,

    // Foundation hardfork state
    pub foundation_primary_address: Address,
    pub foundation_failsafe_address: Address,
    // v2 hardfork state
    pub total_work: Work,
    pub difficulty: Work,
    pub oak_work: Work,
    pub elements: Elements,
    pub attestations: u64,
}

impl SiaEncodable for State {
    fn encode<W: std::io::Write>(&self, w: &mut W) -> crate::encoding::Result<()> {
        self.index.encode(w)?;
        let timestamps_count = if self.index.height + 1 < 11 {
            (self.index.height + 1) as usize
        } else {
            11
        };
        self.prev_timestamps
            .iter()
            .take(timestamps_count)
            .for_each(|ts| ts.encode(w).unwrap());
        self.depth.encode(w)?;
        self.child_target.encode(w)?;
        self.siafund_pool.encode(w)?;
        self.oak_time.encode(w)?;
        self.oak_target.encode(w)?;
        self.foundation_primary_address.encode(w)?;
        self.foundation_failsafe_address.encode(w)?;
        self.total_work.encode(w)?;
        self.difficulty.encode(w)?;
        self.oak_work.encode(w)?;
        self.elements.encode(w)?;
        self.attestations.encode(w)?;
        Ok(())
    }
}

impl SiaDecodable for State {
    fn decode<R: std::io::Read>(r: &mut R) -> crate::encoding::Result<Self> {
        let index = ChainIndex::decode(r)?;
        let timestamps_count = if index.height < 11 {
            index.height as usize
        } else {
            11
        };
        let mut prev_timestamps = [OffsetDateTime::UNIX_EPOCH; 11];
        prev_timestamps[..timestamps_count]
            .iter_mut()
            .try_for_each(|ts| -> encoding::Result<()> {
                *ts = OffsetDateTime::decode(r)?;
                Ok(())
            })?;
        Ok(State {
            index,
            prev_timestamps,
            depth: BlockID::decode(r)?,
            child_target: BlockID::decode(r)?,
            siafund_pool: Currency::decode(r)?,
            oak_time: Duration::decode(r)?,
            oak_target: BlockID::decode(r)?,
            foundation_primary_address: Address::decode(r)?,
            foundation_failsafe_address: Address::decode(r)?,
            total_work: Work::zero(),
            difficulty: Work::zero(),
            oak_work: Work::zero(),
            elements: Elements {
                num_leaves: 0,
                trees: vec![],
            },
            attestations: 0,
        })
    }
}

/// ChainState contains the network parameters and the state of the chain.
/// It is used to determine the consensus rules in effect for a particular block.
#[derive(PartialEq, Debug)]
pub struct ChainState {
    pub network: Network,
    pub state: State,
}

impl ChainState {
    /// child_height returns the height of the next block
    pub fn child_height(&self) -> u64 {
        self.state.index.height + 1
    }

    /// block_reward returns the reward for mining a child block
    pub fn block_reward(&self) -> Currency {
        let reward = self
            .network
            .initial_coinbase
            .checked_sub(Currency::siacoins(self.child_height()));

        match reward {
            Some(reward) if reward >= self.network.minimum_coinbase => reward,
            _ => self.network.minimum_coinbase,
        }
    }

    /// maturity_height is the height at which outputs created by the child block will "mature" (become spendable).
    pub fn maturity_height(&self) -> u64 {
        self.child_height() + self.network.maturity_delay
    }

    /// siafund_count is the number of siafunds in existence
    pub fn siafund_count(&self) -> u64 {
        10000
    }

    /// ancestor_depth is used to determine the target timestamp in the pre-Oak difficulty adjustment algorithm
    pub fn ancestor_depth(&self) -> u64 {
        1000
    }

    // blocks_per_month estimates the number of blocks expected in a calendar month
    pub fn blocks_per_month(&self) -> u64 {
        (Duration::days(365).whole_nanoseconds()
            / 12
            / self.network.block_interval.whole_nanoseconds()) as u64
    }

    /// foundation_subsidy returns the Foundation subsidy output for the child block.
    /// If no subsidy is due, returns None.
    pub fn foundation_subsidy(&self) -> Option<SiacoinOutput> {
        if self.child_height() < self.network.hardfork_foundation.height {
            return None;
        }
        let blocks_per_month = self.blocks_per_month();
        if (self.child_height() - self.network.hardfork_foundation.height) % blocks_per_month != 0 {
            return None;
        }

        let subsidy_per_block = Currency::siacoins(30000);
        Some(SiacoinOutput {
            value: if self.child_height() == self.network.hardfork_foundation.height {
                subsidy_per_block * Currency::new(12)
            } else {
                subsidy_per_block
            },
            address: self.network.hardfork_foundation.primary_address.clone(),
        })
    }

    pub fn replay_prefix(&self) -> &[u8] {
        if self.state.index.height >= self.network.hardfork_v2.allow_height {
            return &[2];
        } else if self.state.index.height >= self.network.hardfork_foundation.height {
            return &[1];
        } else if self.state.index.height >= self.network.hardfork_asic.height {
            return &[0];
        }
        &[]
    }

    pub fn nonce_factor(&self) -> u64 {
        if self.child_height() < self.network.hardfork_asic.height {
            return 1;
        }
        1009
    }

    pub fn max_block_weight() -> u64 {
        2_000_000
    }
}

#[cfg(test)]
mod tests {
    
    

    use super::*;
    use serde_json;

    #[test]
    fn test_serialize_network() {
        let test_cases = vec![
            (
                Network::anagami(),
                "{\"name\":\"anagami\",\"initialCoinbase\":\"300000000000000000000000000000\",\"minimumCoinbase\":\"300000000000000000000000000000\",\"initialTarget\":\"0000000100000000000000000000000000000000000000000000000000000000\",\"blockInterval\":600000000000,\"maturityDelay\":144,\"hardforkDevAddr\":{\"height\":1,\"oldAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"newAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hardforkTax\":{\"height\":2},\"hardforkStorageProof\":{\"height\":5},\"hardforkOak\":{\"height\":10,\"fixHeight\":12,\"genesisTimestamp\":\"2024-08-22T00:00:00Z\"},\"hardforkASIC\":{\"height\":20,\"oakTime\":10000000000000,\"oakTarget\":\"0000000100000000000000000000000000000000000000000000000000000000\"},\"hardforkFoundation\":{\"height\":30,\"primaryAddress\":\"241352c83da002e61f57e96b14f3a5f8b5de22156ce83b753ea495e64f1affebae88736b2347\",\"failsafeAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hardforkV2\":{\"allowHeight\":2016,\"requireHeight\":2304}}",

            ),
            (
                Network::mainnet(),
                "{\"name\":\"mainnet\",\"initialCoinbase\":\"300000000000000000000000000000\",\"minimumCoinbase\":\"30000000000000000000000000000\",\"initialTarget\":\"0000000020000000000000000000000000000000000000000000000000000000\",\"blockInterval\":600000000000,\"maturityDelay\":144,\"hardforkDevAddr\":{\"height\":10000,\"oldAddress\":\"7d0c44f7664e2d34e53efde0661a6f628ec9264785ae8e3cd7c973e8d190c3c97b5e3ecbc567\",\"newAddress\":\"f371c70bce9eb8979cd5099f599ec4e4fcb14e0afcf31f9791e03e6496a4c0b358c98279730b\"},\"hardforkTax\":{\"height\":21000},\"hardforkStorageProof\":{\"height\":100000},\"hardforkOak\":{\"height\":135000,\"fixHeight\":139000,\"genesisTimestamp\":\"2015-06-06T14:13:20Z\"},\"hardforkASIC\":{\"height\":179000,\"oakTime\":120000000000000,\"oakTarget\":\"0000000000000000200000000000000000000000000000000000000000000000\"},\"hardforkFoundation\":{\"height\":298000,\"primaryAddress\":\"053b2def3cbdd078c19d62ce2b4f0b1a3c5e0ffbeeff01280efb1f8969b2f5bb4fdc680f0807\",\"failsafeAddress\":\"27c22a6c6e6645802a3b8fa0e5374657438ef12716d2205d3e866272de1b644dbabd53d6d560\"},\"hardforkV2\":{\"allowHeight\":1000000,\"requireHeight\":1025000}}"
            ),
            (
                Network::zen(),
                "{\"name\":\"zen\",\"initialCoinbase\":\"300000000000000000000000000000\",\"minimumCoinbase\":\"300000000000000000000000000000\",\"initialTarget\":\"0000000100000000000000000000000000000000000000000000000000000000\",\"blockInterval\":600000000000,\"maturityDelay\":144,\"hardforkDevAddr\":{\"height\":1,\"oldAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"newAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hardforkTax\":{\"height\":2},\"hardforkStorageProof\":{\"height\":5},\"hardforkOak\":{\"height\":10,\"fixHeight\":12,\"genesisTimestamp\":\"2023-01-13T08:53:20Z\"},\"hardforkASIC\":{\"height\":20,\"oakTime\":10000000000000,\"oakTarget\":\"0000000100000000000000000000000000000000000000000000000000000000\"},\"hardforkFoundation\":{\"height\":30,\"primaryAddress\":\"053b2def3cbdd078c19d62ce2b4f0b1a3c5e0ffbeeff01280efb1f8969b2f5bb4fdc680f0807\",\"failsafeAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\"},\"hardforkV2\":{\"allowHeight\":100000,\"requireHeight\":102000}}"
            )
        ];

        for (network, expected) in test_cases {
            let serialized = serde_json::to_string(&network).unwrap();
            assert_eq!(expected, serialized, "{} failed", network.name);
            let deserialized: Network = serde_json::from_str(&serialized).unwrap();
            assert_eq!(network, deserialized, "{} failed", network.name);
        }
    }

    /*#[test]
    fn test_serialize_state() {
        let s = State {
            index: ChainIndex {
                height: 0,
                id: block_id!("0000000000000000000000000000000000000000000000000000000000000000"),
            },
            prev_timestamps: [OffsetDateTime::UNIX_EPOCH; 11],
            depth: block_id!("0000000000000000000000000000000000000000000000000000000000000000"),
            child_target: block_id!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ),
            siafund_pool: ZERO_SC,
            oak_time: Duration::ZERO,
            oak_target: block_id!(
                "0000000000000000000000000000000000000000000000000000000000000000"
            ),
            foundation_primary_address: address!(
                "000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
            ),
            foundation_failsafe_address: address!(
                "000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69"
            ),
            total_work: Work::from(123456),
            difficulty: Work::zero(),
            oak_work: Work::zero(),
            elements: Elements {
                num_leaves: 0,
                trees: vec![],
            },
            attestations: 0,
        };

        const JSON_STR: &'static str = "{\"index\":{\"height\":0,\"id\":\"0000000000000000000000000000000000000000000000000000000000000000\"},\"prevTimestamps\":[\"1970-01-01T00:00:00Z\",\"1970-01-01T00:00:00Z\",\"1970-01-01T00:00:00Z\",\"1970-01-01T00:00:00Z\",\"1970-01-01T00:00:00Z\",\"1970-01-01T00:00:00Z\",\"1970-01-01T00:00:00Z\",\"1970-01-01T00:00:00Z\",\"1970-01-01T00:00:00Z\",\"1970-01-01T00:00:00Z\",\"1970-01-01T00:00:00Z\"],\"depth\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"childTarget\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"siafundPool\":\"0\",\"oakTime\":0,\"oakTarget\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"foundationPrimaryAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"foundationFailsafeAddress\":\"000000000000000000000000000000000000000000000000000000000000000089eb0d6a8a69\",\"totalWork\":\"123456\",\"difficulty\":\"0\",\"oakWork\":\"0\",\"elements\":{\"numLeaves\":0,\"trees\":[]},\"attestations\":0}";

        let serialized = serde_json::to_string(&s).unwrap();
        assert_eq!(JSON_STR, serialized);
        let deserialized: State = serde_json::from_str(JSON_STR).unwrap();
        assert_eq!(s, deserialized);

        const BINARY_STR: &'static str = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000096e88f1ffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001e2400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        let mut serialized = Vec::new();
        s.encode(&mut serialized).unwrap();
        assert_eq!(BINARY_STR, hex::encode(serialized.clone()));
        let deserialized = State::decode(&mut &serialized[..]).unwrap();
        assert_eq!(s, deserialized);
    }*/
}
