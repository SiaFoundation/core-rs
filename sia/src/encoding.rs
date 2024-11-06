mod v1_encoding;
mod v2_encoding;

pub use sia_sdk_derive::{SiaDecode, SiaEncode};
pub use v2_encoding::{Error, Result, SiaDecodable, SiaEncodable};

pub use sia_sdk_derive::{V1SiaDecode, V1SiaEncode};
pub use v1_encoding::{V1SiaDecodable, V1SiaEncodable};
