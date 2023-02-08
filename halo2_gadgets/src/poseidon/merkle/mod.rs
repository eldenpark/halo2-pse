mod chip;
mod merkle_path;

use self::chip::{MerkleChip, MerkleConfig};
use super::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord};
use crate::utilities::{i2lebsp, Var};
use crate::{
    poseidon::{
        merkle::merkle_path::MerklePath,
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    },
    utilities::UtilitiesInstructions,
};
use group::ff::{Field, PrimeField};
use halo2_proofs::{arithmetic::FieldExt, poly::Rotation};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use halo2curves::pasta::{pallas, Fp};
use rand::rngs::OsRng;
use std::convert::TryInto;
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct MyConfig<F: FieldExt, const WIDTH: usize, const RATE: usize> {
    advices: [Column<Advice>; 5],
    instance: Column<Instance>,
    merkle_config: MerkleConfig<F, WIDTH, RATE>,
    poseidon_config: Pow5Config<F, WIDTH, RATE>,
}

impl<F: FieldExt, const WIDTH: usize, const RATE: usize> MyConfig<F, WIDTH, RATE> {
    pub fn construct_merkle_chip(&self) -> MerkleChip<F, WIDTH, RATE> {
        MerkleChip::construct(self.merkle_config.clone())
    }

    pub fn construct_poseidon_chip(&self) -> Pow5Chip<F, WIDTH, RATE> {
        Pow5Chip::construct(self.poseidon_config.clone())
    }
}

struct HashCircuit<
    S: Spec<F, WIDTH, RATE>,
    F: FieldExt,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    message: Value<F>,
    root: Value<F>,
    leaf_pos: Value<u32>,
    path: Value<[F; 4]>,
    _spec: PhantomData<S>,
}

impl<
        S: Spec<F, WIDTH, RATE>,
        F: FieldExt,
        const WIDTH: usize,
        const RATE: usize,
        const L: usize,
    > Circuit<F> for HashCircuit<S, F, WIDTH, RATE, L>
{
    type Config = MyConfig<F, WIDTH, RATE>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: Value::unknown(),
            root: Value::unknown(),
            leaf_pos: Value::unknown(),
            path: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> MyConfig<F, WIDTH, RATE> {
        // total 5 advice columns
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>(); // 3
        let partial_sbox = meta.advice_column(); // 1
        let swap = meta.advice_column(); // 1
                                         //

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

        let mut advices = state.clone();
        advices.push(partial_sbox.clone());
        advices.push(swap.clone());

        for advice in advices.iter() {
            meta.enable_equality(*advice);
        }

        let merkle_config = MerkleChip::configure(
            meta,
            advices.clone().try_into().unwrap(),
            poseidon_config.clone(),
        );

        let my_config = MyConfig {
            advices: advices.try_into().unwrap(),
            instance,
            poseidon_config,
            merkle_config,
        };

        my_config
    }

    fn synthesize(
        &self,
        config: MyConfig<F, WIDTH, RATE>,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        println!("synthesize()");

        let merkle_chip = config.construct_merkle_chip();

        let leaf = merkle_chip.load_private(
            layouter.namespace(|| "load_private"),
            config.advices[0],
            self.message,
        )?;

        println!("in-circuit: leaf: {:?}", leaf);

        let merkle_chip = config.construct_merkle_chip();

        let merkle_inputs = MerklePath::<S, _, _, WIDTH, RATE> {
            chip: merkle_chip,
            leaf_pos: self.leaf_pos,
            path: self.path,
            phantom: PhantomData,
        };

        let calculated_root =
            merkle_inputs.calculate_root(layouter.namespace(|| "merkle root calculation"), leaf)?;

        println!("in_circuit: root: {:?}", calculated_root);

        layouter.constrain_instance(calculated_root.cell(), config.instance, 0)?;

        Ok(())
    }
}

#[test]
fn poseidon_hash2() {
    println!("poseidon_hash2()");

    let rng = OsRng;

    let leaf = Fp::from(2);
    let path = [Fp::from(1), Fp::from(1), Fp::from(1), Fp::from(1)];
    let pos = 0;
    let pos_bits: [bool; 4] = i2lebsp(pos as u64);

    println!("out-circuit: pos_bits: {:?}", pos_bits);
    println!("out-circuit: leaf: {:?}", leaf);

    let mut root = leaf;
    for (idx, el) in path.iter().enumerate() {
        let msg = if pos_bits[idx] {
            [*el, root]
        } else {
            [root, *el]
        };

        println!("idx: {}, msg: {:?}", idx, msg);
        root = poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(msg);
    }

    println!("out-circuit: root: {:?}", root);

    let k = 16;

    let circuit = HashCircuit::<OrchardNullifier, Fp, 3, 2, 2> {
        message: Value::known(leaf),
        root: Value::known(root),
        leaf_pos: Value::known(pos),
        path: Value::known(path),
        _spec: PhantomData,
    };

    let prover = MockProver::run(k, &circuit, vec![vec![root]]).unwrap();

    assert_eq!(prover.verify(), Ok(()))
}
