use crate::merkle::{sum_leaf, sum_node};
use crate::Hash256;
use blake2b_simd::Params;
use rayon::prelude::*;

pub const SEGMENT_SIZE: usize = 64;
pub const SECTOR_SIZE: usize = 1 << 22;

/// Calculates the Merkle root of a sector
pub fn sector_root(sector: &[u8]) -> Hash256 {
    assert_eq!(sector.len(), SECTOR_SIZE);
    let mut params = Params::new();
    params.hash_length(32);

    let mut tree_hashes = sector
        .par_chunks_exact(SEGMENT_SIZE)
        .map(|chunk| sum_leaf(&params, chunk))
        .collect::<Vec<_>>();

    let mut chunk_size = 2;
    while chunk_size <= tree_hashes.len() {
        tree_hashes
            .par_chunks_exact_mut(chunk_size)
            .for_each(|nodes| {
                nodes[0] = sum_node(&params, &nodes[0], &nodes[nodes.len() / 2]);
            });
        chunk_size *= 2;
    }
    Hash256::from(tree_hashes[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sector_root() {
        let sector = vec![0u8; SECTOR_SIZE];
        let root = sector_root(&sector);
        assert_eq!(
            root,
            Hash256::parse_string(
                "h:50ed59cecd5ed3ca9e65cec0797202091dbba45272dafa3faa4e27064eedd52c"
            )
            .unwrap()
        );
        println!("{root}");
    }
}
