use group::ff::{Field, PrimeField};
use halo2_gadgets::poseidon::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord};
use halo2_gadgets::utilities::cond_swap::{CondSwapConfig, CondSwapInstructions};
use halo2_gadgets::utilities::{UtilitiesInstructions, Var};
use halo2_gadgets::{
    poseidon::{
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    },
    utilities::cond_swap::CondSwapChip,
};
use halo2_proofs::circuit::Region;
use halo2_proofs::halo2curves::pasta::{pallas, Fp};
use halo2_proofs::plonk::Instance;
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

pub trait MerkleInstructions<
    S: Spec<F, WIDTH, RATE>,
    F: FieldExt,
    const WIDTH: usize,
    const RATE: usize,
>: CondSwapInstructions<F> + UtilitiesInstructions<F> + Chip<F>
{
    fn hash_layer(
        &self,
        layouter: impl Layouter<F>,
        leaf_or_digest: Self::Var,
        sibling: Self::Var,
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

impl<S: Spec<F, WIDTH, RATE>, F: FieldExt, const WIDTH: usize, const RATE: usize>
    MerkleInstructions<S, F, WIDTH, RATE> for MerkleChip<F, WIDTH, RATE>
{
    fn hash_layer(
        &self,
        mut layouter: impl Layouter<F>,
        leaf_or_digest: Self::Var,
        sibling: Self::Var,
        layer: usize,
    ) -> Result<Self::Var, Error> {
        let config = self.config.clone();

        let chip = Pow5Chip::construct(self.config.poseidon_config.clone());

        let hasher = Hash::<_, _, S, ConstantLength<2>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;

        let message = layouter.assign_region(
            || format!("hash on (layer {})", layer),
            |mut region| {
                let left = leaf_or_digest.copy_advice(
                    || format!("hash layer left"),
                    &mut region,
                    config.advices[0],
                    0,
                )?;

                let right = sibling.copy_advice(
                    || format!("hash layer left"),
                    &mut region,
                    config.advices[2],
                    0,
                )?;

                Ok([left, right])
            },
        )?;

        let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

        // println!("output: {:?}", output);

        Ok(output)
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
