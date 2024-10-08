use blake2b_simd::Params;

pub const LEAF_HASH_PREFIX: &[u8; 1] = &[0];
pub const NODE_HASH_PREFIX: &[u8; 1] = &[1];

// A generic Merkle tree accumulator.
pub struct Accumulator {
    trees: [[u8; 32]; 64],
    num_leaves: u64,
    params: Params,
}

impl Accumulator {
    pub fn new() -> Self {
        let mut params = Params::new();
        params.hash_length(32);
        Self {
            trees: [[0; 32]; 64],
            num_leaves: 0,
            params,
        }
    }

    const fn has_tree_at_height(&self, height: usize) -> bool {
        self.num_leaves & (1 << height) != 0
    }

    pub fn add_leaf(&mut self, h: &[u8; 32]) {
        let mut i = 0;
        let mut node = *h;
        while self.has_tree_at_height(i) {
            node = sum_node(&self.params, &self.trees[i], h);
            i += 1;
        }
        self.trees[i] = node;
        self.num_leaves += 1;
    }

    pub fn root(&self) -> [u8; 32] {
        let mut i = self.num_leaves.trailing_zeros() as usize;
        if i == 64 {
            return [0; 32];
        }
        let mut root = self.trees[i];
        i += 1;
        while i < 64 {
            if self.has_tree_at_height(i) {
                root = sum_node(&self.params, &self.trees[i], &root);
            }
            i += 1;
        }
        root
    }
}

#[allow(dead_code)]
pub fn sum_leaf(params: &Params, leaf: &[u8]) -> [u8; 32] {
    let h = params
        .to_state()
        .update(LEAF_HASH_PREFIX)
        .update(leaf)
        .finalize();

    h.as_bytes().try_into().unwrap()
}

pub fn sum_node(params: &Params, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let h = params
        .to_state()
        .update(NODE_HASH_PREFIX)
        .update(left)
        .update(right)
        .finalize();

    h.as_bytes().try_into().unwrap()
}
