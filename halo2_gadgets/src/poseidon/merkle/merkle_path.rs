use super::{
    chip::{MerkleChip, MerkleInstructions},
    PoseidonInstructions, Pow5Chip, Pow5Config, StateWord,
};
use crate::utilities::{cond_swap::CondSwapInstructions, UtilitiesInstructions, Var};
use crate::{
    poseidon::{
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    },
    utilities::i2lebsp,
};
use group::ff::{Field, PrimeField};
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
use halo2curves::pasta::{pallas, Fp};
use rand::rngs::OsRng;
use std::convert::TryInto;
use std::iter;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct MerklePath<MerkleChip, F: FieldExt>
where
    MerkleChip: MerkleInstructions<F> + Clone,
{
    pub chip: MerkleChip,
    pub leaf_pos: Value<u32>,
    // // The Merkle path is ordered from leaves to root.
    pub path: Value<[F; 4]>,
    // chips: [MerkleChip; PAR],
}

impl<F: FieldExt, const WIDTH: usize, const RATE: usize> MerklePath<MerkleChip<F, WIDTH, RATE>, F>
where
    MerkleChip<F, WIDTH, RATE>: MerkleInstructions<F> + Clone,
{
    pub fn calculate_root(
        &self,
        mut layouter: impl Layouter<F>,
        leaf: <MerkleChip<F, WIDTH, RATE> as UtilitiesInstructions<F>>::Var,
    ) -> Result<<MerkleChip<F, WIDTH, RATE> as UtilitiesInstructions<F>>::Var, Error> {
        let mut node = leaf;

        let path = self.path.transpose_array();

        let pos: [Value<bool>; 4] = {
            let pos: Value<[bool; 4]> = self.leaf_pos.map(|pos| i2lebsp(pos as u64));
            pos.transpose_array()
        };

        for (layer, (sibling, pos)) in path.iter().zip(pos.iter()).enumerate() {
            println!("sibling: {:?}\npos: {:?}", sibling, pos);

            // let pair = {
            //     let pair = (node, *sibling);

            //     // Swap node and sibling if needed
            //     self.chip
            //         .swap(layouter.namespace(|| "node position"), pair, *pos)?
            // };

            // node = self.chip.hash_layer(
            //     layouter.namespace(|| format!("hash l {}", layer)),
            //     node,
            //     *sibling,
            //     *pos,
            //     layer,
            // )?;
        }

        Ok(node)
    }
}
