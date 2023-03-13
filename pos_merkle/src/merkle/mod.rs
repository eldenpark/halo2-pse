mod chip;
mod merkle_path;
mod test1;

use self::chip::{MerkleChip, MerkleConfig};
use super::ecdsa::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};
use super::ecdsa::{EcdsaConfig, TestCircuitEcdsaVerifyConfig, BIT_LEN_LIMB, NUMBER_OF_LIMBS};
use crate::merkle::merkle_path::MerklePath;
use crate::ProofError;
use ecc::{GeneralEccChip, Point};
use group::ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use group::{Curve, GroupEncoding};
use group::{Group, UncompressedEncoding};
use halo2_gadgets::ecc::NonIdentityPoint;
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
use halo2_proofs::halo2curves::pasta::{pallas, vesta, Ep, EpAffine, EqAffine, Fp, Fq};
use halo2_proofs::halo2curves::secp256k1::{Secp256k1, Secp256k1Affine, Secp256k1Uncompressed};
use halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_proofs::halo2curves::CurveAffine;
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, ProvingKey, VerifyingKey};
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
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Seek, Write};
use std::marker::PhantomData;
use std::ops::{Mul, Neg};
use std::path::PathBuf;
use std::time::Instant;
// use web_sys::console;
// use std::time::{Instant, SystemTime};

#[derive(Clone, Debug)]
pub struct MyConfig<F: FieldExt, const WIDTH: usize, const RATE: usize> {
    advices: [Column<Advice>; 5],
    instance: Column<Instance>,
    merkle_config: MerkleConfig<F, WIDTH, RATE>,
    poseidon_config: Pow5Config<F, WIDTH, RATE>,
    ecdsa_config: EcdsaConfig,
    // ecdsa_config: TestCircuitEcdsaVerifyConfig,
    _f: PhantomData<F>,
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
    // C: Curve,
    N: CurveAffine,
    S: Spec<F, WIDTH, RATE>,
    F: FieldExt,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    leaf: Value<F>,
    root: Value<F>,
    leaf_idx: Value<u32>,
    path: Value<[F; 31]>,

    // t: Value<N>,
    // u: Value<N>,
    public_key: Value<N>,
    signature: Value<(N::Scalar, N::Scalar)>,
    msg_hash: Value<N::Scalar>,
    aux_generator: N,
    window_size: usize,

    _spec: PhantomData<S>,
    _spec2: PhantomData<N>,
}

impl<
        // C: Curve,
        N: CurveAffine,
        S: Spec<F, WIDTH, RATE>,
        F: FieldExt,
        const WIDTH: usize,
        const RATE: usize,
        const L: usize,
    > Circuit<F> for HashCircuit<N, S, F, WIDTH, RATE, L>
{
    type Config = MyConfig<F, WIDTH, RATE>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            leaf: Value::unknown(),
            root: Value::unknown(),
            leaf_idx: Value::unknown(),
            path: Value::unknown(),

            public_key: Value::unknown(),
            signature: Value::unknown(),
            msg_hash: Value::unknown(),
            aux_generator: N::default(),
            window_size: usize::default(),

            _spec: PhantomData,
            _spec2: PhantomData,
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

        let ecdsa_config = {
            let (rns_base, rns_scalar) =
                GeneralEccChip::<N, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
            let main_gate_config = MainGate::<F>::configure(meta, advices);
            let mut overflow_bit_lens: Vec<usize> = vec![];
            overflow_bit_lens.extend(rns_base.overflow_lengths());
            overflow_bit_lens.extend(rns_scalar.overflow_lengths());
            let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

            let range_config = RangeChip::<F>::configure(
                meta,
                &main_gate_config,
                composition_bit_lens,
                overflow_bit_lens,
            );

            EcdsaConfig::new(range_config, main_gate_config)
        };

        let my_config = MyConfig {
            advices,
            instance,
            poseidon_config,
            merkle_config,
            ecdsa_config,
            _f: PhantomData,
        };

        my_config
    }

    fn synthesize(
        &self,
        config: MyConfig<F, WIDTH, RATE>,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let merkle_chip = config.construct_merkle_chip();

        let leaf = merkle_chip.load_private(
            layouter.namespace(|| "load_private"),
            config.advices[0],
            self.leaf,
        )?;

        println!("in-circuit: leaf: {:?}", leaf);

        let merkle_inputs = MerklePath::<S, _, _, WIDTH, RATE> {
            chip: merkle_chip,
            leaf_idx: self.leaf_idx,
            path: self.path,
            phantom: PhantomData,
        };

        let calculated_root =
            merkle_inputs.calculate_root(layouter.namespace(|| "merkle root calculation"), leaf)?;

        println!("in_circuit: root: {:?}", calculated_root);

        layouter.constrain_instance(calculated_root.cell(), config.instance, 0)?;

        {
            let mut ecc_chip = GeneralEccChip::<N, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(
                config.ecdsa_config.ecc_chip_config(),
            );

            layouter.assign_region(
                || "assign aux values",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    ecc_chip.assign_aux_generator(ctx, Value::known(self.aux_generator))?;
                    ecc_chip.assign_aux(ctx, self.window_size, 1)?;
                    Ok(())
                },
            )?;

            let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());
            let scalar_chip = ecc_chip.scalar_field_chip();

            layouter.assign_region(
                || "temp",
                |region| {
                    // ecc_chip.new_unassigned_scalar(self.leaf);
                    return Ok(());
                },
            )?;

            layouter.assign_region(
                || "region 0",
                |region| {
                    let offset = 0;
                    let ctx = &mut RegionCtx::new(region, offset);

                    let r = self.signature.map(|signature| signature.0);
                    let s = self.signature.map(|signature| signature.1);
                    let integer_r = ecc_chip.new_unassigned_scalar(r);
                    let integer_s = ecc_chip.new_unassigned_scalar(s);
                    let msg_hash = ecc_chip.new_unassigned_scalar(self.msg_hash);

                    let r_assigned =
                        scalar_chip.assign_integer(ctx, integer_r, Range::Remainder)?;

                    let s_assigned =
                        scalar_chip.assign_integer(ctx, integer_s, Range::Remainder)?;

                    let sig = AssignedEcdsaSig {
                        r: r_assigned,
                        s: s_assigned,
                    };

                    // println!(
                    //     "synthesize(), got sig, t: {:?}",
                    //     SystemTime::now().duration_since(SystemTime::UNIX_EPOCH),
                    // );

                    let pk_in_circuit = ecc_chip.assign_point(ctx, self.public_key)?;

                    println!(">>> pk: {:?}", pk_in_circuit);

                    let pk_assigned = AssignedPublicKey {
                        point: pk_in_circuit,
                    };

                    let msg_hash = scalar_chip.assign_integer(ctx, msg_hash, Range::Remainder)?;

                    // let t_in_circuit = ecc_chip.assign_point(ctx, self.t)?;
                    // let u_in_circuit = ecc_chip.assign_point(ctx, self.u)?;

                    ecdsa_chip.verify(ctx, &sig, &pk_assigned, &msg_hash)
                    // ecdsa_chip.verify2(
                    //     ctx,
                    //     &sig,
                    //     &pk_assigned,
                    //     &msg_hash,
                    //     &t_in_circuit,
                    //     &u_in_circuit,
                    // )
                },
            )?;

            // println!("synthesize(): start range chip thing");
            let range_chip = RangeChip::<F>::new(config.ecdsa_config.range_config);
            range_chip.load_table(&mut layouter)?;
        }

        // println!("synthesize(): end");

        Ok(())
    }
}

pub fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
    let x_big = fe_to_big(x);
    big_to_fe(x_big)
}

#[test]
pub fn test_poseidon2() {
    println!("111");

    // println!("out-circuit: root: {:?}, t: {:?}", root, start.elapsed());
    let g = Secp256k1Affine::generator();

    // Generate a key pair
    let sk = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);
    let public_key = (g * sk).to_affine();
    let pk_1 = public_key.to_bytes();
    println!("pk_1: {:?}, ", pk_1);

    let aaa = public_key.to_uncompressed();
    println!("aaa: {:?}", aaa);

    let pk = "04d116ed27a37326d9679d52ddd511f0c671e2d0ff68d30fb78c1fc64eb8fe0ec2e0b260e5c453f856a3297588931aca98d4b2bd14ff1fff6d9b95ed9cd2e5cad8";
    let vv = hex::decode(pk).unwrap();
    println!("vv: {:?}, len: {}", vv, vv.len());

    // Secp256k1Affine::from_bytes(&vv);
    // let bb = Secp256k1Affine::from(&vv).unwrap();

    println!(">>> out circuit public key: {:?}", public_key);

    // let a = public_key.to_bytes();
    // let b = EpAffine::from_bytes(&a).unwrap();
    // println!("pk: {:?}, aaa: {:?}", public_key, a,);
    // EpAffine::from_bytes(bytes)
    // println!("c: {:?}", b);
    // println!("re pk: {:?}", b);

    // Generate a valid signature
    // Suppose `m_hash` is the message hash
    let msg_hash = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);

    // Draw a randomness
    let k = <Secp256k1Affine as CurveAffine>::ScalarExt::random(OsRng);
    let k_inv = k.invert().unwrap();

    // Calculate `r`
    let big_r = g * k;
    let r_point = big_r.to_affine().coordinates().unwrap();
    let x = r_point.x();
    let r = mod_n::<Secp256k1Affine>(*x);

    // Calculate `s`
    let s = k_inv * (msg_hash + (r * sk));
    // println!("r: {:?}, s: {:?}", r, s);

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
        let r_candidate = mod_n::<Secp256k1Affine>(*x_candidate);

        assert_eq!(r, r_candidate);
    }

    // let (t, u) = {
    //     let r_inv = r.invert().unwrap();
    //     let t = big_r * r_inv;
    //     let u = -(g * (r_inv * msg_hash));

    //     // let u_neg = u.neg();
    //     // println!("444 u_neg: {:?}", u_neg);

    //     let pk_candidate = (t * s + u).to_affine();
    //     assert_eq!(public_key, pk_candidate);

    //     (t.to_affine(), u.to_affine())
    // };

    ////////////////////////////////////////////////////////////
    //// Merkle proof
    ////////////////////////////////////////////////////////////
    let path = [
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
        Fp::from(1),
    ];

    let leaf = Fp::from(2);

    let pos = 0;

    let pos_bits: [bool; 31] = i2lebsp(pos as u64);

    let mut root = leaf;
    for (idx, el) in path.iter().enumerate() {
        let msg = if pos_bits[idx] {
            [*el, root]
        } else {
            [root, *el]
        };

        // println!("idx: {}, msg: {:?}", idx, msg);
        root = poseidon::Hash::<Fp, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(msg);
    }

    gen_id_proof::<Secp256k1Affine, Fp>(path, leaf, root, pos, public_key, msg_hash, r, s).unwrap();
}

pub fn gen_id_proof<C: CurveAffine, F: FieldExt>(
    path: [Fp; 31],
    leaf: Fp,
    root: Fp,
    idx: u32,
    public_key: C,
    msg_hash: C::Scalar,
    r: C::Scalar,
    s: C::Scalar,
) -> Result<Vec<u8>, ProofError> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let start = Instant::now();

    let aux_generator = <C as CurveAffine>::CurveExt::random(OsRng).to_affine();

    let circuit = HashCircuit::<C, OrchardNullifier, Fp, 3, 2, 2> {
        leaf: Value::known(leaf),
        root: Value::known(root),
        leaf_idx: Value::known(idx),
        path: Value::known(path),

        public_key: Value::known(public_key),
        signature: Value::known((r, s)),
        msg_hash: Value::known(msg_hash),
        aux_generator,
        window_size: 2,

        _spec: PhantomData,
        _spec2: PhantomData,
    };

    let instance = vec![vec![root], vec![]];

    let dimension = DimensionMeasurement::measure(&circuit).unwrap();
    let k = dimension.k();

    let prover = MockProver::run(k, &circuit, instance).unwrap();
    prover.verify().unwrap();
    println!("\nMock prover susccess!!!");

    return Ok(vec![]);

    println!("params generating, t: {:?}", start.elapsed());

    let params = {
        let params_path = project_root.join(format!("params_{}.dat", k));

        match File::open(&params_path) {
            Ok(fd) => {
                let mut reader = BufReader::new(fd);
                ParamsIPA::read(&mut reader).unwrap()
            }
            Err(_) => {
                let fd = File::create(&params_path).unwrap();
                let params: ParamsIPA<EqAffine> = ParamsIPA::new(k);
                let mut writer = BufWriter::new(fd);
                params.write(&mut writer).unwrap();
                writer.flush().unwrap();
                params
            }
        }
    };

    println!("11 vk loading, t: {:?}", start.elapsed());

    let circuit_name = "pos_merkle";
    let vk = {
        let vk_path = project_root.join(format!("vk_{}.dat", circuit_name));

        match File::open(&vk_path) {
            Ok(fd) => {
                let mut reader = BufReader::new(fd);
                let vk = VerifyingKey::<_>::read::<
                    _,
                    HashCircuit<
                        //
                        pallas::Affine,
                        OrchardNullifier,
                        Fp,
                        3,
                        2,
                        2,
                    >,
                >(&mut reader, SerdeFormat::Processed)
                .unwrap();
                vk
            }
            Err(_) => {
                let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
                let fd = File::create(&vk_path).unwrap();
                let mut writer = BufWriter::new(fd);
                vk.write(&mut writer, SerdeFormat::Processed).unwrap();
                writer.flush().unwrap();
                vk
            }
        }
    };

    println!("11 pk loading, t: {:?}", start.elapsed());

    let pk = {
        let pk_path = project_root.join(format!("pk_{}.dat", circuit_name));

        match File::open(&pk_path) {
            Ok(fd) => {
                let mut reader = BufReader::new(fd);
                let pk = ProvingKey::<_>::read::<
                    _,
                    HashCircuit<
                        //
                        pallas::Affine,
                        OrchardNullifier,
                        Fp,
                        3,
                        2,
                        2,
                    >,
                >(&mut reader, SerdeFormat::Processed)
                .unwrap();

                pk
            }
            Err(_) => {
                let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");
                let fd = File::create(&pk_path).unwrap();
                let mut writer = BufWriter::new(fd);
                pk.write(&mut writer, SerdeFormat::Processed).unwrap();
                writer.flush().unwrap();
                pk
            }
        }
    };

    let mut rng = OsRng;
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

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

    let proof = transcript.finalize();

    println!(
        "proof generated, len: {}, t: {:?}",
        proof.len(),
        start.elapsed()
    );

    return Ok(proof);
}
