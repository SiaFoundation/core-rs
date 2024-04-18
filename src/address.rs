use core::fmt;
use std::io::{Error, Write};

use crate::blake2b::{Accumulator, LEAF_HASH_PREFIX};
use crate::{specifier::Specifier, HexParseError, PublicKey, SiaEncodable, UnlockKey};
use blake2b_simd::Params;
use serde::Serialize;

/// An address that can be used to receive UTXOs
#[derive(Debug, PartialEq, Clone)]
pub struct Address([u8; 32]);

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            self.to_string().serialize(serializer)
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl Address {
    pub fn new(addr: [u8; 32]) -> Address {
        Address(addr)
    }

    pub fn parse_string(s: &str) -> Result<Self, HexParseError> {
        let s = match s.split_once(':') {
            Some((_prefix, suffix)) => suffix,
            None => s,
        };

        if s.len() != 76 {
            return Err(HexParseError::InvalidLength);
        }

        let mut data = [0u8; 38];
        hex::decode_to_slice(s, &mut data).map_err(HexParseError::HexError)?;

        let h = Params::new()
            .hash_length(32)
            .to_state()
            .update(&data[..32])
            .finalize();
        let checksum = h.as_bytes();

        if checksum[..6] != data[32..] {
            return Err(HexParseError::InvalidChecksum);
        }

        Ok(data[..32].into())
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<&[u8]> for Address {
    fn from(val: &[u8]) -> Self {
        let mut data = [0u8; 32];
        data.copy_from_slice(val);
        Address(data)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = [0u8; 32 + 6];
        buf[..32].copy_from_slice(&self.0);

        let h = Params::new()
            .hash_length(32)
            .to_state()
            .update(&self.0)
            .finalize();

        buf[32..].copy_from_slice(&h.as_bytes()[..6]);
        write!(f, "addr:{}", hex::encode(buf))
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Algorithm {
    ED25519,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Algorithm::ED25519 => write!(f, "ed25519"),
        }
    }
}

impl Serialize for Algorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let str = match self {
            Algorithm::ED25519 => "ed25519",
        };
        if serializer.is_human_readable() {
            serializer.serialize_str(str)
        } else {
            Specifier::from(str).serialize(serializer)
        }
    }
}

// specifies the conditions for spending an output or revising a file contract.
#[derive(Debug, PartialEq, Clone)]
pub struct UnlockConditions {
    pub timelock: u64,
    pub public_keys: Vec<UnlockKey>,
    pub required_signatures: u64,
}

impl SiaEncodable for UnlockConditions {
    fn encode<W: Write>(&self, w: &mut W) -> Result<(), Error> {
        w.write_all(&self.timelock.to_le_bytes())?;
        w.write_all(&(self.public_keys.len() as u64).to_le_bytes())?;
        for key in &self.public_keys {
            key.encode(w)?;
        }
        w.write_all(&self.required_signatures.to_le_bytes())
    }
}

impl UnlockConditions {
    pub fn new(
        timelock: u64,
        public_keys: Vec<UnlockKey>,
        required_signatures: u64,
    ) -> UnlockConditions {
        UnlockConditions {
            timelock,
            public_keys,
            required_signatures,
        }
    }

    pub fn standard_unlock_conditions(public_key: PublicKey) -> UnlockConditions {
        UnlockConditions {
            timelock: 0,
            public_keys: vec![UnlockKey::new(Algorithm::ED25519, public_key)],
            required_signatures: 1,
        }
    }

    pub fn address(&self) -> Address {
        let mut acc = Accumulator::new();

        let h = Params::new()
            .hash_length(32)
            .to_state()
            .update(LEAF_HASH_PREFIX)
            .update(&self.timelock.to_le_bytes())
            .finalize();

        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(h.as_bytes());
        acc.add_leaf(&leaf);

        for key in &self.public_keys {
            let mut state = Params::new().hash_length(32).to_state();
            state.update(LEAF_HASH_PREFIX);
            key.encode(&mut state).unwrap();

            let h = state.finalize();
            let mut leaf = [0u8; 32];
            leaf.copy_from_slice(h.as_bytes());
            acc.add_leaf(&leaf);
        }

        let h = Params::new()
            .hash_length(32)
            .to_state()
            .update(LEAF_HASH_PREFIX)
            .update(&self.required_signatures.to_le_bytes())
            .finalize();

        let mut leaf = [0u8; 32];
        leaf.copy_from_slice(h.as_bytes());
        acc.add_leaf(&leaf);

        Address(acc.root())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::to_bytes;
    use serde_json;

    #[test]
    fn test_sia_serialize_algorithm() {
        let algorithm = Algorithm::ED25519;
        let bytes = to_bytes(&algorithm).unwrap();
        let expected: [u8; 16] = [
            b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn test_json_serialize_algorithm() {
        assert_eq!(
            serde_json::to_string(&Algorithm::ED25519).unwrap(),
            "\"ed25519\""
        )
    }

    #[test]
    fn test_sia_serialize_address() {
        let address = Address::parse_string(
            "addr:8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0",
        )
        .unwrap();

        // note: the expected value is the same as the input value, but without the checksum
        assert_eq!(
            to_bytes(&address).unwrap(),
            hex::decode("8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8c")
                .unwrap()
        )
    }

    #[test]
    fn test_json_serialize_address() {
        let address = Address::parse_string(
            "addr:8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0",
        )
        .unwrap();

        assert_eq!(
            serde_json::to_string(&address).unwrap(),
            "\"addr:8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0\""
        )
    }

    #[test]
    fn test_standard_unlockhash() {
        let test_cases = vec![
            (
                "80f637df83a93a6916d1b5c8bdbb061f967fb9fe8fe51ef4d97eeec73c6bfc394771e4a04f42",
                hex::decode("ad08d551ab7116b8c2285de81ffa528ef3679f9e242c3f551b560a60ab9763db")
                    .unwrap(),
            ),
            (
                "99a27a168bdde2e9c59bc967f6c662e3db0b2cf13da26ddae26004fa19c61d3db017dca7d0d3",
                hex::decode("18ac9c05b0c5e7c62859812b943572429cda178aa3df92697569b8984c603b4c")
                    .unwrap(),
            ),
            (
                "128151658b256d0185f3f91504758349a96e73c1a68a39c7ff7bf9d0e416997c964d773858ce",
                hex::decode("2b36cc860796f2e8a1990b437f46a4b905840e6ba41ba5f68fe2b8ebe23626af")
                    .unwrap(),
            ),
            (
                "1f47d453cfd7369bce4034d3ab461feb2a4d073bf59c959225993d00e38d71a8fea7c57cd3f1",
                hex::decode("a3e3c2f3493a079d3dfe69681bf878c59337e3d1c79d17a34e3da81f062bbe21")
                    .unwrap(),
            ),
            (
                "e03c56f8d95894cea875711e2f909c68c07dd37142a8253813ad09abceb2b6e5dd89992c9638",
                hex::decode("a03d3b27db7e143cb8b39a1eb9234bffad59d6f50adf4f0ee916afd510a939a0")
                    .unwrap(),
            ),
            (
                "68b6dd2e50f12e2deef2efd6b7baa660d87950ea16c5a8402a6db5873e062bcdd5246940b44e",
                hex::decode("52e4438ca9b6eb2d33953f97255e410130d55749432094fe9963f4fc65167ce5")
                    .unwrap(),
            ),
            (
                "c766e0a5ef49b7bab6c2e9c6a0b699e87eb3580e08f3fe77648dd93b66795a8606787cc5e29e",
                hex::decode("4110f8b0ade1cca7aa40008a9b9911655393288eaacc3948fecd13edd3f092ec")
                    .unwrap(),
            ),
            (
                "b455cf3c22de0d84ab8599499b0c2056d4916ab4c642b6b716148487f83ca5a85ad199b7a454",
                hex::decode("861d50c4ee90b0a6a5544a3820978dad1fd9391c4813ede9e4963f0d6bec010a")
                    .unwrap(),
            ),
            (
                "5274e9f3db1acfe8bb2d67dbbb5b6f2cc20769a0b42c8a9187ae827bf637f06e62ecada30f9f",
                hex::decode("a5329c135951f3505d9a26d2833cb6c1aebb875fbada80f38b09bd3314f26802")
                    .unwrap(),
            ),
            (
                "1540f42840b0479b238ec0143984a784c58240a8ca5e21da4b66be89a2f54353c99739938947",
                hex::decode("e11589e1857b7a0d2fc3526fbdfdc4d4708dfbf251184be1118138df4ef2d47e")
                    .unwrap(),
            ),
            (
                "21592f041e6f6861f199d54a26fe6bdfc5d629bb5dda12058d3ce28549c4aeffdbbdb67c2b95",
                hex::decode("d57887af5b838ea2d20a582f659b3e36ca47d33b253364e3b774a1f4feb8415b")
                    .unwrap(),
            ),
            (
                "f34b1e0b74a695f8bc82a97bab3b9d1ebe420956cbb3f7611c349c9659ba13fa362a417b1fd2",
                hex::decode("5da4058d2f95e3c547aab8b5c70817ed3795856aa7988676f266cb429d75ce06")
                    .unwrap(),
            ),
            (
                "3549a1680fcc093347e2674f4e89c84200965e1b779e2b3c05e4b21645a0b2fd5ac86923ef7a",
                hex::decode("98ced26430f3be35b29ca76d3f65ea616f89e2510a3c1307856522e23057d958")
                    .unwrap(),
            ),
            (
                "86fc291f7f53def33f2f7566f5ff08763bf5ada158f97c87fc240d1dcb04aa2a7b289018e33e",
                hex::decode("e715d5dc3bd8edecb453c59f85998591d7c14fd08057a0605cb416f6751eaad9")
                    .unwrap(),
            ),
            (
                "46e60abc3acbff858e382783f0739a8b2f2ba4c51b26941d979e60cb5292f11df1112b7016c0",
                hex::decode("359eee8d1ef18ed647bbd63cb4b2be85061f8e3fd67318e13924ddbc1beb815f")
                    .unwrap(),
            ),
            (
                "015b4b0759b0adee6c01de051bdacefe1f30eb571c83fa6c37607008696a9fa7f85273061e72",
                hex::decode("cf5cd07f31ca3aa3b7d2947da7e92c42ec5f981eff80ff1b438e59fd456465fb")
                    .unwrap(),
            ),
            (
                "7435604655772ca5ff011127c83692e40945187954da3bc7c01102d59701c7351aadbdc9ac8b",
                hex::decode("7f6a73aeb6de28f1d3935941caa8cab286d13d8c74f2352b5b717c3d743db9c1")
                    .unwrap(),
            ),
            (
                "c554d56a2eaffd8426006fb6d987cc615fb4ec05b1b15e793ab9d9127d79cf323787817467e6",
                hex::decode("14b98855c4f22295fcf3e2ec5d5fdfbb877979639c963bf6e226a0fb71902baf")
                    .unwrap(),
            ),
            (
                "addr:c4850dbcddb9dfac6f44007ec58fe824bc58e3de2432de478f3e53f7965c2afd7ea651b6c2bf",
                hex::decode("6f5c23f8797f93d3d3c689fe1a3f5d9a1fbf326a7a6ea51fecbeaa9aba46f180")
                    .unwrap(),
            ),
            (
                "addr:6a8f4f1d5a7405aa24cb1fb2a3c1dcaae74175c712002627289b5cd9dd887088afe605460abd",
                hex::decode("45f12760f6005a93cece248f5ec78adf15f9d29dafe397c8c28fefc72781d6fb")
                    .unwrap(),
            ),
            (
                "addr:e464b9b1c9282d8edeed5832b95405761db6dacf6a156fc9119a396bdc8f8892815c7dce20fd",
                hex::decode("1c12d17a2a8b2c25950872f312d5d0758f07d8357c98897fc472565a44b3d1f1")
                    .unwrap(),
            ),
            (
                "addr:9ae839af434aa13de6e8baa280541716811dcbaa33165fea5e9bad0c33998c10f16fcac4f214",
                hex::decode("686d28bf7e4b4cadf759994caed1e52092e12c11cef257a265b50402dbd70c3b")
                    .unwrap(),
            ),
            (
                "addr:e92722d80103af9574f19a6cf72aab424335927eb7da022455f53314e3587dc8ece40d254981",
                hex::decode("b2e9ddef40897219a997ae7af277a5550cc10c54e793b6d2146de94df3bd552b")
                    .unwrap(),
            ),
            (
                "addr:e2a02510f242f35e46b8840d8da42c087ea906b09d8e454c734663650236977da0362dd2ab43",
                hex::decode("4f756e475a706cdcec8eb1c02b21a591e0c0450cc0408ae8aec82ae97f634ecf")
                    .unwrap(),
            ),
            (
                "addr:8fb49ccf17dfdcc9526dec6ee8a5cca20ff8247302053d3777410b9b0494ba8cdf32abee86f0",
                hex::decode("cd46b523d2ee92f205a00726d8544094bb4fe58142ecffd20ea32b37b6e6bfc3")
                    .unwrap(),
            ),
        ];

        for (expected_str, public_key) in test_cases {
            let expected = Address::parse_string(expected_str).unwrap();

            let public_key = PublicKey::new(public_key.as_slice().try_into().unwrap());
            let uc = UnlockConditions::standard_unlock_conditions(public_key);
            let addr = uc.address();

            assert_eq!(addr, expected);
            // test string round-trip
            if !expected_str.starts_with("addr:") {
                assert_eq!(addr.to_string(), "addr:".to_string() + expected_str)
            } else {
                assert_eq!(addr.to_string(), expected_str)
            }
        }
    }
}
