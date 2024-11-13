#[inline]
/// decode_hex_const is a helper func to parse a hex string intended to be used for compile-time literals
/// input length is not validated to support addresses.
pub(crate) const fn decode_hex_bytes<const N: usize>(input: &[u8]) -> [u8; N] {
    const fn decode_hex_char(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }

    const fn decode_hex_pair(hi: u8, lo: u8) -> Option<u8> {
        let hi = decode_hex_char(hi);
        let lo = decode_hex_char(lo);
        match (hi, lo) {
            (Some(hi), Some(lo)) => Some(hi << 4 | lo),
            _ => None,
        }
    }

    let mut result = [0u8; N];
    let mut i = 0;
    while i < N * 2 {
        match decode_hex_pair(input[i], input[i + 1]) {
            Some(byte) => result[i / 2] = byte,
            None => panic!("invalid hex char"),
        }
        i += 2;
    }
    result
}

#[allow(dead_code)] // I promise it's used
pub(crate) const fn valid_hex_bytes(input: &[u8]) -> bool {
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' => (),
            _ => return false,
        }
        i += 1;
    }
    true
}

/// address is a helper macro to create an Address from a string literal.
/// The string literal must be a valid 76-character hex-encoded string.
/// The checksum of the address is not validated.
macro_rules! address {
    ($text:literal) => {{
        const _VALIDATE: () = {
            assert!($text.len() == 76, "incorrect number of chars");
            assert!(
                $crate::types::valid_hex_bytes($text.as_bytes()),
                "invalid hex chars"
            );
        };
        Address::new($crate::types::decode_hex_bytes::<32>($text.as_bytes()))
    }};
    () => {
        compile_error!("unsupported address macro usage")
    };
}
pub(crate) use address;

// Macro to implement types used as identifiers which are 32 byte hashes and are
// serialized with a prefix
macro_rules! impl_hash_id {
    ($name:ident, $create_macro_name:ident) => {
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            $crate::encoding::SiaEncode,
            $crate::encoding::SiaDecode,
            $crate::encoding::V1SiaEncode,
            $crate::encoding::V1SiaDecode,
        )]
        pub struct $name([u8; 32]);

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if serializer.is_human_readable() {
                    String::serialize(&self.to_string(), serializer)
                } else {
                    <[u8; 32]>::serialize(&self.0, serializer)
                }
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                $name::parse_string(&s).map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
            }
        }

        impl $name {
            pub const fn new(b: [u8; 32]) -> Self {
                Self(b)
            }

            // Example method that might be used in serialization/deserialization
            pub fn parse_string(s: &str) -> Result<Self, $crate::types::HexParseError> {
                let s = match s.split_once(':') {
                    Some((_prefix, suffix)) => suffix,
                    None => s,
                };

                if s.len() != 64 {
                    return Err($crate::types::HexParseError::InvalidLength);
                }

                let mut data = [0u8; 32];
                hex::decode_to_slice(s, &mut data)
                    .map_err($crate::types::HexParseError::HexError)?;
                Ok($name(data))
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                write!(f, "{}", hex::encode(self.0))
            }
        }

        impl From<blake2b_simd::Hash> for $name {
            fn from(hash: blake2b_simd::Hash) -> Self {
                let mut h = [0; 32];
                h.copy_from_slice(&hash.as_bytes()[..32]);
                Self(h)
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(data: [u8; 32]) -> Self {
                $name(data)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(hash: $name) -> [u8; 32] {
                hash.0
            }
        }

        impl AsRef<[u8; 32]> for $name {
            fn as_ref(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name([0; 32])
            }
        }

        #[allow(unused_macros)]
        macro_rules! $create_macro_name {
            ($text:literal) => {{
                const _VALIDATE: () = {
                    assert!($text.len() == 64, "expected 64 characters");
                    assert!(
                        $crate::types::valid_hex_bytes($text.as_bytes()),
                        "invalid hex literal"
                    );
                };
                $name::new($crate::types::decode_hex_bytes::<32>($text.as_bytes()))
            }};
            () => {
                compile_error!("unsupported macro usage")
            };
        }
        #[allow(unused)]
        pub(crate) use $create_macro_name;
    };
}
pub(crate) use impl_hash_id;

/// helper module for base64 serialization
pub(crate) mod base64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let base64 = STANDARD.encode(v);
        s.serialize_str(&base64)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        STANDARD
            .decode(base64.as_bytes())
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

/// helper module for Vec<Vec<u8>> base64 serialization
pub(crate) mod vec_base64 {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(v: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: Vec<String> = v.iter().map(|bytes| STANDARD.encode(bytes)).collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded: Vec<String> = Vec::deserialize(deserializer)?;
        encoded
            .into_iter()
            .map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom))
            .collect()
    }
}
