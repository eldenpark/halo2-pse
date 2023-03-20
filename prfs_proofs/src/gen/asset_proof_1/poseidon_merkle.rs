use crate::{
    chip::{MerkleChip, MerkleConfig},
    merkle_path::MerklePath,
};
use eth_types::{self, Field};
use halo2_gadgets::poseidon::{primitives::Spec, Pow5Chip, Pow5Config};
use halo2_proofs::plonk::Instance;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Column, ConstraintSystem, Error},
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct PoseidonMerkleConfig<F: Field, const WIDTH: usize, const RATE: usize> {
    pub instance: Column<Instance>,
    pub poseidon_config: Pow5Config<F, WIDTH, RATE>,
    pub merkle_config: MerkleConfig<F, WIDTH, RATE>,
}

impl<F: Field, const WIDTH: usize, const RATE: usize> PoseidonMerkleConfig<F, WIDTH, RATE> {
    pub fn construct<S: Spec<F, WIDTH, RATE>>(
        meta: &mut ConstraintSystem<F>,
    ) -> PoseidonMerkleConfig<F, WIDTH, RATE> {
        // total 5 advice columns
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>(); // 3
        let partial_sbox = meta.advice_column(); // 1
        let swap = meta.advice_column(); // 1

        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        meta.enable_constant(rc_b[0]);

        let poseidon_config = Pow5Chip::configure::<S>(
            meta,
            state.clone().try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        let advices = [
            state[0].clone(),
            state[1].clone(),
            state[2].clone(),
            partial_sbox.clone(),
            swap.clone(),
        ];

        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        let merkle_config = MerkleChip::configure(
            meta,
            advices.clone().try_into().unwrap(),
            poseidon_config.clone(),
        );

        PoseidonMerkleConfig {
            instance,
            poseidon_config,
            merkle_config,
        }
    }
}

/// Auxiliary Gadget to verify a that a message hash is signed by the public
/// key corresponding to an Ethereum Address.
#[derive(Clone, Debug)]
pub struct PoseidonMerkleChip<
    F: Field,
    S: Spec<F, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
> {
    pub _marker: PhantomData<F>,
    pub _marker2: PhantomData<S>,
}

impl<F: Field, S: Spec<F, WIDTH, RATE>, const WIDTH: usize, const RATE: usize>
    PoseidonMerkleChip<F, S, WIDTH, RATE>
{
    pub fn climb_up_tree(
        &self,
        merkle_config: MerkleConfig<F, WIDTH, RATE>,
        layouter: &mut impl Layouter<F>,
        leaf: &AssignedCell<F, F>,
        leaf_idx: Value<u32>,
        path: Value<[F; 31]>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let leaf = layouter.assign_region(
            || "temp",
            |mut region| {
                let address = leaf.copy_advice(
                    || "address as leaf",
                    &mut region,
                    merkle_config.advices[0],
                    0,
                );
                return address;
            },
        )?;

        let merkle_chip = MerkleChip::construct(merkle_config.clone());

        let merkle_inputs = MerklePath::<S, _, _, WIDTH, RATE> {
            chip: merkle_chip,
            leaf_idx,
            path,
            phantom: PhantomData,
        };

        let calculated_root =
            merkle_inputs.calculate_root(layouter.namespace(|| "merkle root calculation"), leaf)?;

        Ok(calculated_root)
    }
}

impl<F: Field, S: Spec<F, WIDTH, RATE>, const WIDTH: usize, const RATE: usize> Default
    for PoseidonMerkleChip<F, S, WIDTH, RATE>
{
    fn default() -> Self {
        Self {
            _marker: PhantomData,
            _marker2: PhantomData,
        }
    }
}
