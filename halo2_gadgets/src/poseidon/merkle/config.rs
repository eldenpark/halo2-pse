use super::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord};
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

pub trait MerkleInstructions<F: FieldExt>: Chip<F> {
    type Cell;

    fn hash_layer(
        &self,
        layouter: impl Layouter<F>,
        leaf_or_digest: Self::Cell,
        sibling: Value<F>,
        position_bit: Value<F>,
        layer: usize,
    ) -> Result<Self::Cell, Error>;
}

#[derive(Clone, Debug)]
pub struct MerkleConfig<F: FieldExt, const WIDTH: usize, const RATE: usize> {
    pub advice: [Column<Advice>; 3],
    pub s_bool: Selector,
    pub s_swap: Selector,
    pub hash_config: Pow5Config<F, WIDTH, RATE>,
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
        advice: [Column<Advice>; 3],
        hash_config: Pow5Config<F, WIDTH, RATE>,
    ) -> MerkleConfig<F, WIDTH, RATE> {
        for column in &advice {
            // meta.enable_equality((*column).into());
            meta.enable_equality(*column);
        }

        let s_bool = meta.selector();

        meta.create_gate("bool", |meta| {
            let position_bit = meta.query_advice(advice[2], Rotation::cur());
            let s_bool = meta.query_selector(s_bool);
            vec![s_bool * position_bit.clone() * (Expression::Constant(F::one()) - position_bit)]
        });

        let s_swap = meta.selector();

        meta.create_gate("swap", |meta| {
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let bit = meta.query_advice(advice[2], Rotation::cur());
            let s_swap = meta.query_selector(s_swap);
            let l = meta.query_advice(advice[0], Rotation::next());
            let r = meta.query_advice(advice[1], Rotation::next());
            vec![s_swap * ((bit * F::from(2) * (b.clone() - a.clone()) - (l - a)) - (b - r))]
        });

        let hash_config = hash_config.clone();

        MerkleConfig {
            advice,
            s_bool,
            s_swap,
            hash_config,
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
    type Cell = AssignedCell<F, F>;

    fn hash_layer(
        &self,
        mut layouter: impl Layouter<F>,
        leaf_or_digest: Self::Cell,
        sibling: Value<F>,
        position_bit: Value<F>,
        layer: usize,
    ) -> Result<Self::Cell, Error> {
        let config = self.config.clone();

        // let mut left_digest = None;
        // let mut right_digest = None;

        // let ret = layouter.assign_region(|| "aa", |mut region| Ok(()));

        return Ok(leaf_or_digest);

        layouter.assign_region(
            || format!("hash on (layer {})", layer),
            |mut region| {
                let mut row_offset = 0;

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
                //     // || sibling.ok_or(Error::SynthesisError),
                //     // || sibling,
                // )?;

                // let _position_bit_cell = region.assign_advice(
                //     || format!("witness positional_bit (layer {})", layer),
                //     config.advice[2],
                //     row_offset,
                //     || position_bit.ok_or(Error::SynthesisError),
                // )?;

                // config.s_bool.enable(&mut region, row_offset)?;
                // config.s_swap.enable(&mut region, row_offset)?;

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
