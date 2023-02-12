use super::chip::{MerkleChip, MerkleConfig};
use super::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};
use super::{EcdsaConfig, TestCircuitEcdsaVerifyConfig, BIT_LEN_LIMB, NUMBER_OF_LIMBS};
use crate::merkle::merkle_path::MerklePath;
use crate::merkle::HashCircuit;
use ecc::GeneralEccChip;
use group::ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use group::Curve;
use group::Group;
use halo2_gadgets::poseidon::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord};
use halo2_gadgets::utilities::{i2lebsp, Var};
use halo2_gadgets::{
    poseidon::{
        // merkle::merkle_path::MerklePath,
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    },
    utilities::UtilitiesInstructions,
};
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::halo2curves::pairing::Engine;
use halo2_proofs::halo2curves::pasta::{pallas, vesta, EpAffine, EqAffine, Fp};
use halo2_proofs::halo2curves::CurveAffine;
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk};
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_proofs::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
use halo2_proofs::poly::ipa::multiopen::ProverIPA;
use halo2_proofs::poly::kzg::multiopen::ProverGWC;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer};
use halo2_proofs::SerdeFormat;
use halo2_proofs::{arithmetic::FieldExt, poly::Rotation};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use integer::{IntegerInstructions, Range};
use maingate::{
    big_to_fe, fe_to_big, mock_prover_verify, DimensionMeasurement, MainGate, RangeChip,
    RangeInstructions, RegionCtx,
};
use rand::rngs::OsRng;
use std::convert::TryInto;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::marker::PhantomData;
use std::path::PathBuf;
use std::time::Instant;

#[test]
fn poseidon_hash2() {
    fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
        let x_big = fe_to_big(x);
        big_to_fe(x_big)
    }

    let mut project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let params_path = project_root.join("params.dat");
    let params_fd = File::create(params_path).unwrap();

    let pk_path = project_root.join("pk.dat");
    let pk_fd = File::create(pk_path).unwrap();

    let start = Instant::now();
    println!("poseidon_hash2(): t: {:?}", start.elapsed());

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

    println!("out-circuit: root: {:?}, t: {:?}", root, start.elapsed());

    let g = pallas::Affine::generator();

    // Generate a key pair
    let sk = <pallas::Affine as CurveAffine>::ScalarExt::random(OsRng);
    let public_key = (g * sk).to_affine();

    // Generate a valid signature
    // Suppose `m_hash` is the message hash
    let msg_hash = <pallas::Affine as CurveAffine>::ScalarExt::random(OsRng);

    // Draw arandomness
    let k = <pallas::Affine as CurveAffine>::ScalarExt::random(OsRng);
    let k_inv = k.invert().unwrap();

    // Calculate `r`
    let r_point = (g * k).to_affine().coordinates().unwrap();
    let x = r_point.x();
    let r = mod_n::<pallas::Affine>(*x);

    // Calculate `s`
    let s = k_inv * (msg_hash + (r * sk));

    // Sanity check. Ensure we construct a valid signature. So lets verify it
    {
        let s_inv = s.invert().unwrap();
        let u_1 = msg_hash * s_inv;
        let u_2 = r * s_inv;
        let r_point = ((g * u_1) + (public_key * u_2))
            .to_affine()
            .coordinates()
            .unwrap();
        let x_candidate = r_point.x();
        let r_candidate = mod_n::<pallas::Affine>(*x_candidate);
        assert_eq!(r, r_candidate);
    }

    println!("aux gen, t: {:?}", start.elapsed());

    let aux_generator = <pallas::Affine as CurveAffine>::CurveExt::random(OsRng).to_affine();

    let circuit = HashCircuit::<pallas::Affine, OrchardNullifier, Fp, 3, 2, 2> {
        message: Value::known(leaf),
        root: Value::known(root),
        leaf_pos: Value::known(pos),
        path: Value::known(path),

        public_key: Value::known(public_key),
        signature: Value::known((r, s)),
        msg_hash: Value::known(msg_hash),
        aux_generator,
        window_size: 2,
        _spec: PhantomData,
        _spec2: PhantomData,
    };

    // let instance = vec![vec![root], vec![]];
    // let instance = vec![vec![], vec![]];

    let dimension = DimensionMeasurement::measure(&circuit).unwrap();
    let k = dimension.k();

    println!("proving");
    // let prover = MockProver::run(k, &circuit, instance).unwrap();
    // assert_eq!(prover.verify(), Ok(()))

    println!("params generating, t: {:?}", start.elapsed());
    let params: ParamsIPA<_> = ParamsIPA::new(k);

    let mut writer = BufWriter::new(params_fd);
    params.write(&mut writer).unwrap();
    writer.flush().unwrap();

    println!("11 vk generating, t: {:?}", start.elapsed());
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");

    println!("22 pk generating, t: {:?}", start.elapsed());
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");

    let mut writer = BufWriter::new(pk_fd);
    // pk.to_bytes(SerdeFormat::RawBytes);
    // pk.write(&mut writer, SerdeFormat::RawBytes).unwrap();
    // writer.flush().unwrap();

    let mut rng = OsRng;
    let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);

    println!("creating proof, t: {:?}", start.elapsed());
    create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&[&[root], &[]]],
        &mut rng,
        &mut transcript,
    )
    .unwrap();

    println!("proof generated, t: {:?}", start.elapsed());
    let proof = transcript.finalize();

    println!("proof: {:?}, t: {:?}", proof, start.elapsed());
}
