mod v1;
mod v2;

pub use sia_derive::{SiaDecode, SiaEncode};
pub use v2::{Error, Result, SiaDecodable, SiaEncodable};

pub use sia_derive::{V1SiaDecode, V1SiaEncode};
pub use v1::{V1SiaDecodable, V1SiaEncodable};
