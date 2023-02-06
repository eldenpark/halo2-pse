use super::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord};
use crate::utilities::cond_swap::{CondSwapConfig, CondSwapInstructions};
use crate::utilities::{UtilitiesInstructions, Var};
use crate::{
    poseidon::{
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    },
    utilities::cond_swap::CondSwapChip,
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

pub trait MerkleInstructions<F: FieldExt>:
    CondSwapInstructions<F> + UtilitiesInstructions<F> + Chip<F>
{
    fn hash_layer(
        &self,
        layouter: impl Layouter<F>,
        leaf_or_digest: Self::Var,
        // sibling: Value<F>,
        sibling: Self::Var,
        // position_bit: Value<F>,
        layer: usize,
    ) -> Result<Self::Var, Error>;
}

#[derive(Clone, Debug)]
pub struct MerkleConfig<F: FieldExt, const WIDTH: usize, const RATE: usize> {
    pub advices: [Column<Advice>; 5],
    pub poseidon_config: Pow5Config<F, WIDTH, RATE>,
    pub cond_swap_config: CondSwapConfig,
}

#[derive(Clone, Debug)]
pub struct MerkleChip<F: FieldExt, const WIDTH: usize, const RATE: usize> {
    pub config: MerkleConfig<F, WIDTH, RATE>,
}

impl<F: FieldExt, const WIDTH: usize, const RATE: usize> Chip<F> for MerkleChip<F, WIDTH, RATE> {
    type Config = MerkleConfig<F, WIDTH, RATE>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt, const WIDTH: usize, const RATE: usize> MerkleChip<F, WIDTH, RATE> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advices: [Column<Advice>; 5],
        poseidon_config: Pow5Config<F, WIDTH, RATE>,
    ) -> MerkleConfig<F, WIDTH, RATE> {
        let cond_swap_config = CondSwapChip::configure(meta, advices);
        // a,
        // b: advices[1],
        // a_swapped: advices[2],
        // b_swapped: advices[3],
        // swap: advices[4],

        MerkleConfig {
            advices,
            poseidon_config,
            cond_swap_config,
        }
    }

    pub fn construct(config: MerkleConfig<F, WIDTH, RATE>) -> Self {
        Self { config }
    }
}
// ANCHOR_END: chip-config

impl<F: FieldExt, const WIDTH: usize, const RATE: usize> MerkleInstructions<F>
    for MerkleChip<F, WIDTH, RATE>
{
    fn hash_layer(
        &self,
        mut layouter: impl Layouter<F>,
        leaf_or_digest: Self::Var,
        // sibling: Value<F>,
        sibling: Self::Var,
        // position_bit: Value<F>,
        layer: usize,
    ) -> Result<Self::Var, Error> {
        let config = self.config.clone();

        // let mut left_digest = None;
        // let mut right_digest = None;

        // let ret = layouter.assign_region(|| "aa", |mut region| Ok(()));

        return Ok(leaf_or_digest);

        layouter.assign_region(
            || format!("hash on (layer {})", layer),
            |mut region| {
                let mut row_offset = 0;

                let chip = Pow5Chip::construct(self.config.poseidon_config.clone());

                // let hasher = Hash::<F, _, OrchardNullifier, ConstantLength<2>, WIDTH, RATE>::init(
                //     chip,
                //     layouter.namespace(|| "init"),
                // )?;

                // let left_or_digest_value = leaf_or_digest.value();

                // let left_or_digest_cell = region.assign_advice(
                //     || format!("witness leaf or digest (layer {})", layer),
                //     config.advice[0],
                //     row_offset,
                //     || left_or_digest_value.ok_or(Error::SynthesisError),
                // )?;

                // if layer > 0 {
                //     region.constrain_equal(leaf_or_digest.cell(), left_or_digest_cell)?;
                //     // Should i do permutation here?
                // }

                // let _sibling_cell = region.assign_advice(
                //     || format!("witness sibling (layer {})", layer),
                //     config.advice[1],
                //     row_offset,
                //     || sibling,
                // )?;

                // let _position_bit_cell = region.assign_advice(
                //     || format!("witness positional_bit (layer {})", layer),
                //     config.advice[2],
                //     row_offset,
                //     || position_bit,
                // )?;

                // config.s_bool.enable(&mut region, row_offset)?;
                // config.s_swap.enable(&mut region, row_offset)?;

                // if position_bit == F::zero() {}

                // let (l_value, r_value): (Fp, Fp) = if position_bit == Some(Fp::zero()) {
                //     (
                //         left_or_digest_value.ok_or(Error::SynthesisError)?,
                //         sibling.ok_or(Error::SynthesisError)?,
                //     )
                // } else {
                //     (
                //         sibling.ok_or(Error::SynthesisError)?,
                //         left_or_digest_value.ok_or(Error::SynthesisError)?,
                //     )
                // };

                // row_offset += 1;

                // let l_cell = region.assign_advice(
                //     || format!("witness left (layer {})", layer),
                //     config.advice[0],
                //     row_offset,
                //     || Ok(l_value),
                // )?;

                // let r_cell = region.assign_advice(
                //     || format!("witness right (layer {})", layer),
                //     config.advice[1],
                //     row_offset,
                //     || Ok(r_value),
                // )?;

                // left_digest = Some(CellValue {
                //     cell: l_cell,
                //     value: Some(l_value),
                // });
                // right_digest = Some(CellValue {
                //     cell: r_cell,
                //     value: Some(r_value),
                // });

                Ok(())
            },
        )?;

        // let poseidon_chip = Pow5Chip::construct(config.hash_config.clone());

        // let mut poseidon_hasher: PoseidonHash<
        //     Fp,
        //     PoseidonChip<Fp>,
        //     P128Pow5T3,
        //     ConstantLength<2_usize>,
        //     3_usize,
        //     2_usize,
        // > = PoseidonHash::init(
        //     poseidon_chip,
        //     layouter.namespace(|| "init hasher"),
        //     ConstantLength::<2>,
        // )?;

        // let message = [left_digest.unwrap(), right_digest.unwrap()];
        // let loaded_message = poseidon_hasher.witness_message_pieces(
        //     config.hash_config.clone(),
        //     layouter.namespace(|| format!("witnessing hash of a layer: {}", layer)),
        //     message,
        // )?;

        // let word = poseidon_hasher.hash(
        //     layouter.namespace(|| format!("hashing layer: {}", layer)),
        //     loaded_message,
        // )?;
        // let digest: CellValue<Fp> = word.inner().into();

        // Ok(digest)
    }
}

impl<F: FieldExt, const WIDTH: usize, const RATE: usize> UtilitiesInstructions<F>
    for MerkleChip<F, WIDTH, RATE>
{
    type Var = AssignedCell<F, F>;
}

impl<F: FieldExt, const WIDTH: usize, const RATE: usize> CondSwapInstructions<F>
    for MerkleChip<F, WIDTH, RATE>
{
    #[allow(clippy::type_complexity)]
    fn swap(
        &self,
        layouter: impl Layouter<F>,
        pair: (Self::Var, Value<F>),
        swap: Value<bool>,
    ) -> Result<(Self::Var, Self::Var), Error> {
        let config = self.config().cond_swap_config.clone();
        let chip = CondSwapChip::<F>::construct(config);
        chip.swap(layouter, pair, swap)
    }
}
