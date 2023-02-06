mod chip;
mod merkle_path;

use group::ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use halo2curves::pasta::{pallas, Fp};
use rand::rngs::OsRng;
use std::convert::TryInto;
use std::iter;

use self::chip::{MerkleChip, MerkleConfig};

use super::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord};
use crate::utilities::Var;
use crate::{
    poseidon::{
        merkle::merkle_path::MerklePath,
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    },
    utilities::UtilitiesInstructions,
};
use halo2_proofs::{arithmetic::FieldExt, poly::Rotation};
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

struct HashCircuit<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize>
{
    message: Value<Fp>,
    root: Value<Fp>,
    leaf_pos: Value<u32>,
    path: Value<[Fp; 4]>,
    _spec: PhantomData<S>,
}

impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<Fp>
    for HashCircuit<S, WIDTH, RATE, L>
{
    // type Config = Pow5Config<Fp, WIDTH, RATE>;
    type Config = MyConfig<Fp, WIDTH, RATE>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            message: Value::unknown(),
            // output: Value::unknown(),
            root: Value::unknown(),
            leaf_pos: Value::unknown(),
            path: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> MyConfig<Fp, WIDTH, RATE> {
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

        // let mut merkle_advices = state.clone(); // length 3
        // merkle_advices.push(meta.advice_column());
        // merkle_advices.push(meta.advice_column());
        //
        let mut advices = state.clone();
        advices.push(partial_sbox.clone());
        advices.push(swap.clone());

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
        config: MyConfig<Fp, WIDTH, RATE>,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        println!("synthesize()");

        let chip = Pow5Chip::construct(config.poseidon_config.clone());

        // let message = layouter.assign_region(
        //     || "load message",
        //     |mut region| {
        //         let message_word = |i: usize| {
        //             let value = self.message.map(|message_vals| message_vals[i]);

        //             println!("msg, i: {}, value: {:?}", i, value);

        //             region.assign_advice(
        //                 || format!("load message_{}", i),
        //                 config.poseidon_config.state[i],
        //                 0,
        //                 || value,
        //             )
        //         };

        //         let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
        //         Ok(message?.try_into().unwrap())
        //     },
        // )?;

        // let leaf = chip_1.load_private(
        //     layouter.namespace(|| ""),
        //     config.0.cond_swap_config.a(),
        //     self.leaf,
        // )?;
        //
        //
        // config.merkle_config.cond_swap_config.a();

        let merkle_chip = config.construct_merkle_chip();

        let leaf = merkle_chip.load_private(
            layouter.namespace(|| "load_private"),
            config.advices[0],
            self.message,
        )?;

        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;

        // let output = hasher.hash(layouter.namespace(|| "hash"), self.message)?;

        let chip = Pow5Chip::construct(config.poseidon_config.clone());
        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;

        let merkle_chip = config.construct_merkle_chip();

        let merkle_inputs = MerklePath {
            chip: merkle_chip,
            leaf_pos: self.leaf_pos,
            path: self.path,
        };

        let calculated_root =
            merkle_inputs.calculate_root(layouter.namespace(|| "merkle root calculation"), leaf)?;

        // let a = layouter.assign_region(
        //     || "constrain output",
        //     |mut region| {
        //         let expected_var =
        //             region.assign_advice(|| "load output", config.state[0], 0, || self.output)?;

        //         println!("22");

        //         region.constrain_equal(output2.cell(), expected_var.cell())
        //     },
        // );

        Ok(())
    }
}

#[test]
fn poseidon_hash2() {
    println!("1111111");

    let rng = OsRng;

    let leaf = Fp::from(2);
    let path = [Fp::from(1), Fp::from(1), Fp::from(1), Fp::from(1)];
    // let position_bits = [Fp::from(0), Fp::from(0), Fp::from(0), Fp::from(0)];
    let pos = 0;

    let mut root = leaf;
    for el in path {
        // root = Hash::init(P128Pow5T3, ConstantLength::<2>).hash([root, el]);
        let msg = [root, el];
        root = poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(msg);
    }

    println!("out-circuit: root: {:?}", root);

    let k = 16;

    let circuit = HashCircuit::<OrchardNullifier, 3, 2, 2> {
        message: Value::known(leaf),
        // output: Value::known(output),
        root: Value::known(root),
        leaf_pos: Value::known(pos),
        path: Value::known(path),
        _spec: PhantomData,
    };

    let prover = MockProver::run(k, &circuit, vec![vec![]]).unwrap();

    // assert_eq!(prover.verify(), Ok(()))
}
