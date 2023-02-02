use super::{
    config::{MerkleChip, MerkleInstructions},
    PoseidonInstructions, Pow5Chip, Pow5Config, StateWord,
};
use crate::poseidon::{
    primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
    Hash,
};
use crate::utilities::Var;
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
    pub leaf_pos: Value<[F; 4]>,
    // // The Merkle path is ordered from leaves to root.
    pub path: Value<[F; 4]>,
}

impl<F: FieldExt, const WIDTH: usize, const RATE: usize> MerklePath<MerkleChip<F, WIDTH, RATE>, F>
where
    MerkleChip<F, WIDTH, RATE>: MerkleInstructions<F> + Clone,
{
    pub fn calculate_root(
        &self,
        mut layouter: impl Layouter<F>,
        leaf: <MerkleChip<F, WIDTH, RATE> as MerkleInstructions<F>>::Cell,
        // leaf: Value<F>,
    ) -> Result<<MerkleChip<F, WIDTH, RATE> as MerkleInstructions<F>>::Cell, Error> {
        let mut node = leaf;

        let path = self.path.transpose_array();
        let leaf_pos = self.leaf_pos.transpose_array();

        for (layer, (sibling, pos)) in path.iter().zip(leaf_pos.iter()).enumerate() {
            node = self.chip.hash_layer(
                layouter.namespace(|| format!("hash l {}", layer)),
                node,
                *sibling,
                *pos,
                layer,
            )?;
        }

        Ok(node)
    }
}
