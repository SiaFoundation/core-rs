use crate::merkle::{sum_leaf, sum_node};
use crate::Hash256;
use blake2b_simd::Params;
//use rayon::prelude::*;

pub const SEGMENT_SIZE: usize = 64;
pub const SECTOR_SIZE: usize = 1 << 22;

/// Calculates the Merkle root of a sector
pub fn sector_root(sector: &[u8]) -> Hash256 {
    assert_eq!(sector.len(), SECTOR_SIZE);
    let mut params = Params::new();
    params.hash_length(32);

    let mut tree_hashes = sector
        .chunks_exact(SEGMENT_SIZE)
        .map(|chunk| sum_leaf(&params, chunk))
        .collect::<Vec<_>>();

    let mut step_size = 1;
    while step_size < tree_hashes.len() {
        // Iterate over tree_hashes in steps of step_size * 2
        for i in (0..tree_hashes.len()).step_by(step_size * 2) {
            let j = i + step_size;
            if j < tree_hashes.len() {
                // Compute the parent node hash from two child hashes
                tree_hashes[i] = sum_node(&params, &tree_hashes[i], &tree_hashes[j]);
            }
        }
        step_size *= 2;
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
