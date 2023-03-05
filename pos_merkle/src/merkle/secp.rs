use halo2_gadgets::poseidon::{
    self,
    primitives::{ConstantLength, P128Pow5T3Sec},
};
use halo2_proofs::halo2curves::secp256k1::Fp;
// use rand_core::OsRng;

// #[test]
// pub fn test_secp_poseidon1() {
//     println!("1111");

//     let rng = OsRng;

//     let message = [Fp::random(rng), Fp::random(rng)];
//     let output =
//         poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(message);
//     println!("output: {:?}", output);

//     let k = 6;
//     let circuit = HashCircuit::<P128Pow5T3Sec, 3, 2, 2> {
//         message: Value::known(message),
//         output: Value::known(output),
//         _spec: PhantomData,
//     };
//     let prover = MockProver::run(k, &circuit, vec![]).unwrap();
//     assert_eq!(prover.verify(), Ok(()))
// }
