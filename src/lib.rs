use std::fmt;

pub trait SiaEncodable {
	fn encode(&self, buf : &mut Vec<u8>);
}

pub mod consensus;
pub mod currency;
pub mod seed;
pub mod address;
pub mod transactions;

pub(crate) mod blake2b;

pub use consensus::*;
pub use seed::*;
pub use currency::*;
pub use address::*;
pub use transactions::*;

pub struct Hash256([u8;32]);

impl Hash256 {
	pub fn from_slice(data: [u8;32]) -> Self {
		Hash256(data)
	}

	pub fn as_bytes(&self) -> [u8;32] {
		self.0
	}
}

impl fmt::Display for Hash256 {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "h:{}", hex::encode(&self.0))
	}
}

impl SiaEncodable for Hash256 {
	fn encode(&self, buf: &mut Vec<u8>) {
		buf.extend_from_slice(&self.0);
	}
}