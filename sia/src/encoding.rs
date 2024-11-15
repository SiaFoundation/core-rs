mod v1;
mod v2;

pub use macros::{SiaDecode, SiaEncode};
pub use v2::{Error, Result, SiaDecodable, SiaEncodable};

pub use macros::{V1SiaDecode, V1SiaEncode};
pub use v1::{V1SiaDecodable, V1SiaEncodable};
