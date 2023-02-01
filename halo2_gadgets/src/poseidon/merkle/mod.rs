mod config;

use group::ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2curves::pasta::{pallas, Fp};
use rand::rngs::OsRng;
use std::convert::TryInto;
use std::iter;

use super::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord};
use crate::poseidon::{
    primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
    Hash,
};
use halo2_proofs::{arithmetic::FieldExt, poly::Rotation};
use std::marker::PhantomData;

use crate::utilities::Var;

struct HashCircuit<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize>
{
    // message: Value<[Fp; L]>,
    root: Value<Fp>,
    position_bits: Value<[Fp; 4]>,
    path: Value<[Fp; 4]>,
    _spec: PhantomData<S>,
}

impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize> Circuit<Fp>
    for HashCircuit<S, WIDTH, RATE, L>
{
    type Config = Pow5Config<Fp, WIDTH, RATE>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            // message: Value::unknown(),
            // output: Value::unknown(),
            root: Value::unknown(),
            position_bits: Value::unknown(),
            path: Value::unknown(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Pow5Config<Fp, WIDTH, RATE> {
        let state = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();
        let partial_sbox = meta.advice_column();

        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        meta.enable_constant(rc_b[0]);

        Pow5Chip::configure::<S>(
            meta,
            state.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        )
    }

    fn synthesize(
        &self,
        config: Pow5Config<Fp, WIDTH, RATE>,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        println!("synthesize()");

        let chip = Pow5Chip::construct(config.clone());

        // let message = layouter.assign_region(
        //     || "load message",
        //     |mut region| {
        //         let message_word = |i: usize| {
        //             let value = self.message.map(|message_vals| message_vals[i]);

        //             println!("msg value: {:?}", value);

        //             region.assign_advice(
        //                 || format!("load message_{}", i),
        //                 config.state[i],
        //                 0,
        //                 || value,
        //             )
        //         };

        //         let message: Result<Vec<_>, Error> = (0..L).map(message_word).collect();
        //         Ok(message?.try_into().unwrap())
        //     },
        // )?;

        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;

        // let output = hasher.hash(layouter.namespace(|| "hash"), message)?;

        let chip = Pow5Chip::construct(config.clone());
        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;

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
    let position_bits = [Fp::from(0), Fp::from(0), Fp::from(0), Fp::from(0)];

    let mut root = leaf;
    for el in path {
        // root = Hash::init(P128Pow5T3, ConstantLength::<2>).hash([root, el]);
        let msg = [root, el];
        root = poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(msg);
    }

    println!("out-circuit: root: {:?}", root);

    let k = 16;

    let circuit = HashCircuit::<OrchardNullifier, 3, 2, 2> {
        // message: Value::known(message),
        // output: Value::known(output),
        root: Value::known(root),
        position_bits: Value::known(position_bits),
        path: Value::known(path),
        _spec: PhantomData,
    };

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();

    // assert_eq!(prover.verify(), Ok(()))
}
