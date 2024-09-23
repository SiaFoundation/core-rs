use crate::merkle::{Accumulator, LEAF_HASH_PREFIX};
use blake2b_simd::Params;

pub const SEGMENT_SIZE: usize = 64;
pub const SECTOR_SIZE: usize = 1 << 22;

pub fn sector_root(sector: &[u8; SECTOR_SIZE]) -> [u8; 32] {
    let mut params = Params::new();
    params.hash_length(32);

    let mut acc = Accumulator::new();
    for leaf in sector.chunks(SEGMENT_SIZE) {
        let h = params
            .to_state()
            .update(LEAF_HASH_PREFIX)
            .update(leaf)
            .finalize();
        acc.add_leaf(&h.as_bytes().try_into().unwrap());
    }
    acc.root()
}
