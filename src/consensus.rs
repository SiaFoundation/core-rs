use std::fmt;

pub struct ChainIndex {
	pub height: u64,
	pub id: [u8; 32],
}

impl fmt::Display for ChainIndex {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}:{}", self.height, hex::encode(&self.id))
	}
}