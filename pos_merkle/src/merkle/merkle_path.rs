use super::{
    chip::{MerkleChip, MerkleInstructions},
    PoseidonInstructions, Pow5Chip, Pow5Config, StateWord,
};
use group::ff::{Field, PrimeField};
use halo2_gadgets::utilities::{cond_swap::CondSwapInstructions, UtilitiesInstructions, Var};
use halo2_gadgets::{
    poseidon::{
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    },
    utilities::i2lebsp,
};
use halo2_proofs::halo2curves::pasta::{pallas, Fp};
use halo2_proofs::{arithmetic::FieldExt, poly::Rotation};
use halo2_proofs::{
    circuit::Chip,
    plonk::{Advice, Column, Expression, Selector},
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use rand::rngs::OsRng;
use std::convert::TryInto;
use std::iter;
use std::marker::PhantomData;

// #[derive(Clone, Debug)]
// pub struct MerklePath<MerkleChip, F: FieldExt>
// where
//     MerkleChip: MerkleInstructions<F> + Clone,
// {
//     pub chip: MerkleChip,
//     pub leaf_pos: Value<u32>,
//     // // The Merkle path is ordered from leaves to root.
//     pub path: Value<[F; 4]>,
//     // chips: [MerkleChip; PAR],
// }

// impl<F: FieldExt, const WIDTH: usize, const RATE: usize> MerklePath<MerkleChip<F, WIDTH, RATE>, F>
// where
//     MerkleChip<F, WIDTH, RATE>: MerkleInstructions<F> + Clone,
// {
//     pub fn calculate_root(
//         &self,
//         mut layouter: impl Layouter<F>,
//         leaf: Self::Var,
//     ) -> Result<<MerkleChip<F, WIDTH, RATE> as UtilitiesInstructions<F>>::Var, Error> {
//         let path = self.path.transpose_array();

//         let pos: [Value<bool>; 4] = {
//             let pos: Value<[bool; 4]> = self.leaf_pos.map(|pos| i2lebsp(pos as u64));
//             pos.transpose_array()
//         };

//         let mut node = leaf;

//         for (layer, (sibling, pos)) in path.iter().zip(pos.iter()).enumerate() {
//             println!("sibling: {:?}\npos: {:?}", sibling, pos);

//             let pair = {
//                 let pair = (node, *sibling);

//                 // Swap node and sibling if needed
//                 self.chip
//                     .swap(layouter.namespace(|| "node position"), pair, *pos)?
//             };

//             // node = node;

//             // node = self.chip.hash_layer(
//             //     layouter.namespace(|| format!("hash l {}", layer)),
//             //     node,
//             //     *sibling,
//             //     *pos,
//             //     layer,
//             // )?;
//             node = self.chip.hash_layer(
//                 layouter.namespace(|| format!("MerkleCRH({}, left, right)", layer)),
//                 node,
//                 pair.0,
//                 pair.1,
//                 layer,
//             )?;
//         }

//         Ok(node)
//     }
// }

/// SWU hash-to-curve personalization for the Merkle CRH generator
pub const MERKLE_CRH_PERSONALIZATION: &str = "z.cash:Orchard-MerkleCRH";

#[derive(Clone, Debug)]
pub struct MerklePath<
    // C: CurveAffine,
    S: Spec<F, WIDTH, RATE>,
    F: FieldExt,
    MerkleChip,
    const WIDTH: usize,
    const RATE: usize,
    // const PATH_LENGTH: usize,
    // const K: usize,
    // const MAX_WORDS: usize,
    // const PAR: usize,
> where
    MerkleChip: MerkleInstructions<S, F, WIDTH, RATE> + Clone,
    // S: Spec<F, WIDTH, RATE>,
{
    pub chip: MerkleChip,
    // domain: MerkleChip::HashDomains,
    pub leaf_pos: Value<u32>,
    // The Merkle path is ordered from leaves to root.
    pub path: Value<[F; 32]>,
    pub phantom: PhantomData<S>,
}

impl<
        S: Spec<F, WIDTH, RATE>,
        F: FieldExt,
        MerkleChip,
        const WIDTH: usize,
        const RATE: usize,
        // const PATH_LENGTH: usize,
        // const K: usize,
        // const MAX_WORDS: usize,
        // const PAR: usize,
    > MerklePath<S, F, MerkleChip, WIDTH, RATE>
where
    MerkleChip: MerkleInstructions<S, F, WIDTH, RATE> + Clone,
{
    /// Constructs a [`MerklePath`].
    ///
    /// A circuit may have many more columns available than are required by a single
    /// `MerkleChip`. To make better use of the available circuit area, the `MerklePath`
    /// gadget will distribute its path hashing across each `MerkleChip` in `chips`, such
    /// that each chip processes `ceil(PATH_LENGTH / PAR)` layers (with the last chip
    /// processing fewer layers if the division is inexact).
    pub fn construct(
        chip: MerkleChip,
        // domain: MerkleChip::HashDomains,
        leaf_pos: Value<u32>,
        path: Value<[F; 32]>,
    ) -> Self {
        // assert_ne!(PAR, 0);
        Self {
            // chips,
            // domain,
            chip,
            leaf_pos,
            path,
            phantom: PhantomData,
        }
    }
}

#[allow(non_snake_case)]
impl<
        // C: CurveAffine,
        S: Spec<F, WIDTH, RATE>,
        F: FieldExt,
        MerkleChip,
        const WIDTH: usize,
        const RATE: usize,
        // const PATH_LENGTH: usize,
        // const K: usize,
        // const MAX_WORDS: usize,
        // const PAR: usize,
    > MerklePath<S, F, MerkleChip, WIDTH, RATE>
where
    MerkleChip: MerkleInstructions<S, F, WIDTH, RATE> + Clone,
{
    /// Calculates the root of the tree containing the given leaf at this Merkle path.
    ///
    /// Implements [Zcash Protocol Specification Section 4.9: Merkle Path Validity][merklepath].
    ///
    /// [merklepath]: https://zips.z.cash/protocol/protocol.pdf#merklepath
    pub fn calculate_root(
        &self,
        mut layouter: impl Layouter<F>,
        leaf: MerkleChip::Var,
    ) -> Result<MerkleChip::Var, Error> {
        // Each chip processes `ceil(PATH_LENGTH / PAR)` layers.
        // let layers_per_chip = (PATH_LENGTH + PAR - 1) / PAR;

        // Assign each layer to a chip.
        // let chips = (0..PATH_LENGTH).map(|i| self.chips[i / layers_per_chip].clone());

        // The Merkle path is ordered from leaves to root, which is consistent with the
        // little-endian representation of `pos` below.
        let path = self.path.transpose_array();

        // Get position as a PATH_LENGTH-bit bitstring (little-endian bit order).
        let pos: [Value<bool>; 32] = {
            let pos: Value<[bool; 32]> = self.leaf_pos.map(|pos| i2lebsp(pos as u64));
            pos.transpose_array()
        };

        // let Q = self.domain.Q();

        let mut node = leaf;
        for (i, (sibling, pos)) in path.iter().zip(pos.iter()).enumerate() {
            // `l` = MERKLE_DEPTH - layer - 1, which is the index obtained from
            // enumerating this Merkle path (going from leaf to root).
            // For example, when `layer = 31` (the first sibling on the Merkle path),
            // we have `l` = 32 - 31 - 1 = 0.
            // On the other hand, when `layer = 0` (the final sibling on the Merkle path),
            // we have `l` = 32 - 0 - 1 = 31.

            // Constrain which of (node, sibling) is (left, right) with a conditional swap
            // tied to the current bit of the position.
            let pair = {
                let pair = (node, *sibling);

                // Swap node and sibling if needed
                self.chip
                    .swap(layouter.namespace(|| "node position"), pair, *pos)?
            };

            println!(
                "idx: {}, pos: {:?}, \n--first: {:?}\n--second: {:?}\n",
                i, pos, pair.0, pair.1,
            );

            // Compute the node in layer l from its children:
            //     M^l_i = MerkleCRH(l, M^{l+1}_{2i}, M^{l+1}_{2i+1})
            node = self.chip.hash_layer(
                layouter.namespace(|| format!("MerkleCRH({}, left, right)", i)),
                pair.0,
                pair.1,
                i,
            )?;
        }

        Ok(node)
    }
}
