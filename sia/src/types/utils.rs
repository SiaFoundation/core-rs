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

// Macro to implement types used as identifiers which are 32 byte hashes and are
// serialized with a prefix
macro_rules! impl_hash_id {
    ($name:ident) => {
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
    };
}
pub(crate) use impl_hash_id;

#[inline]
pub(crate) const fn decode_hex_char(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[inline]
#[doc(hidden)]
pub(crate) const fn decode_hex_pair(hi: u8, lo: u8) -> Option<u8> {
    let hi = decode_hex_char(hi);
    let lo = decode_hex_char(lo);
    match (hi, lo) {
        (Some(hi), Some(lo)) => Some(hi << 4 | lo),
        _ => None,
    }
}

#[inline]
#[doc(hidden)]
pub(crate) const fn decode_hex_256(input: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut i = 0;
    while i < 64 {
        match decode_hex_pair(input[i], input[i + 1]) {
            Some(byte) => result[i / 2] = byte,
            None => panic!("invalid hex char"),
        }
        i += 2;
    }
    result
}

/// A macro to create an Address from a literal hex string. The string must be 76 characters long.
///
/// The checksum is not verified.
#[macro_export]
macro_rules! address {
    ($text:literal) => {{
        if $text.len() != 76 {
            panic!("Address must be 76 characters");
        }
        $crate::types::Address::new($crate::types::decode_hex_256($text.as_bytes()))
    }};
}

/// A macro to create a Hash256 from a literal hex string. The string must be 64 characters long.
#[macro_export]
macro_rules! hash_256 {
    ($text:literal) => {{
        if $text.len() != 64 {
            panic!("Hash256 must be 64 characters");
        }
        $crate::types::Hash256::new($crate::types::decode_hex_256($text.as_bytes()))
    }};
}

/// A macro to create a SiacoinOutputID from a literal hex string. The string must be 64 characters long.
#[macro_export]
macro_rules! siacoin_id {
    ($text:literal) => {{
        if $text.len() != 64 {
            panic!("SiacoinOutputID must be 64 characters");
        }
        $crate::types::SiacoinOutputID::new($crate::types::decode_hex_256($text.as_bytes()))
    }};
}

/// A macro to create a SiafundOutputID from a literal hex string. The string must be 64 characters long.
#[macro_export]
macro_rules! siafund_id {
    ($text:literal) => {{
        if $text.len() != 64 {
            panic!("SiafundOutputID must be 64 characters");
        }
        $crate::types::SiafundOutputID::new($crate::types::decode_hex_256($text.as_bytes()))
    }};
}

/// A macro to create a FileContractID from a literal hex string. The string must be 64 characters long.
#[macro_export]
macro_rules! contract_id {
    ($text:literal) => {{
        if $text.len() != 64 {
            panic!("FileContractID must be 64 characters");
        }
        $crate::types::FileContractID::new($crate::types::decode_hex_256($text.as_bytes()))
    }};
}

/// A macro to create a TransactionID from a literal hex string. The string must be 64 characters long.
#[macro_export]
macro_rules! transaction_id {
    ($text:literal) => {{
        if $text.len() != 64 {
            panic!("TransactionID must be 64 characters");
        }
        $crate::types::TransactionID::new($crate::types::decode_hex_256($text.as_bytes()))
    }};
}

/// A macro to create a BlockID from a literal hex string. The string must be 64 characters long.
#[macro_export]
macro_rules! block_id {
    ($text:literal) => {{
        if $text.len() != 64 {
            panic!("BlockID must be 64 characters");
        }
        $crate::types::BlockID::new($crate::types::decode_hex_256($text.as_bytes()))
    }};
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_address_macro() {
        const ADDRESS: &str =
            "5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9e758b4f79b34";
        let s = address!(
            "5eb70f141387df1e2ecd434b22be50bff57a6e08484f3890fe4415a6d323b5e9e758b4f79b34"
        );
        assert_eq!(s.to_string(), ADDRESS);
    }
}
