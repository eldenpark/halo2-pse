mod chip;
mod merkle_path;
mod test1;

use self::chip::{MerkleChip, MerkleConfig};
use super::ecdsa::{EcdsaConfig, TestCircuitEcdsaVerifyConfig, BIT_LEN_LIMB, NUMBER_OF_LIMBS};
use super::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord};
use crate::poseidon::ecdsa::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};
use crate::utilities::{i2lebsp, Var};
use crate::{
    poseidon::{
        merkle::merkle_path::MerklePath,
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    },
    utilities::UtilitiesInstructions,
};
use ecc::GeneralEccChip;
use group::ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use group::Curve;
use group::Group;
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::halo2curves::pairing::Engine;
use halo2_proofs::halo2curves::pasta::{pallas, vesta, EqAffine, Fp};
use halo2_proofs::halo2curves::CurveAffine;
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk};
use halo2_proofs::poly::commitment::ParamsProver;
use halo2_proofs::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
use halo2_proofs::poly::ipa::multiopen::ProverIPA;
use halo2_proofs::poly::kzg::multiopen::ProverGWC;
use halo2_proofs::transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer};
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
use std::marker::PhantomData;
use std::time::Instant;

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
    N: CurveAffine,
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

    public_key: Value<N>,
    signature: Value<(N::Scalar, N::Scalar)>,
    msg_hash: Value<N::Scalar>,
    aux_generator: N,
    window_size: usize,

    _spec: PhantomData<S>,
    _spec2: PhantomData<N>,
}

impl<
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
            message: Value::unknown(),
            root: Value::unknown(),
            leaf_pos: Value::unknown(),
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
            advices: advices.try_into().unwrap(),
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

                    let pk_in_circuit = ecc_chip.assign_point(ctx, self.public_key)?;
                    let pk_assigned = AssignedPublicKey {
                        point: pk_in_circuit,
                    };
                    let msg_hash = scalar_chip.assign_integer(ctx, msg_hash, Range::Remainder)?;
                    ecdsa_chip.verify(ctx, &sig, &pk_assigned, &msg_hash)
                },
            )?;

            println!("synthesize(): start range chip thing");
            let range_chip = RangeChip::<F>::new(config.ecdsa_config.range_config);
            range_chip.load_table(&mut layouter)?;
        }

        println!("synthesize(): end");

        Ok(())
    }
}

#[test]
fn poseidon_hash2() {
    fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
        let x_big = fe_to_big(x);
        big_to_fe(x_big)
    }

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

    // assert_eq!(mock_prover_verify(&circuit, instance), Ok(()));
    //
    // println!("dimension checking, t: {:?}", start.elapsed());

    let dimension = DimensionMeasurement::measure(&circuit).unwrap();
    let k = dimension.k();

    println!("proving");
    // let prover = MockProver::run(k, &circuit, instance).unwrap();
    // assert_eq!(prover.verify(), Ok(()))

    println!("params generating, t: {:?}", start.elapsed());
    let params: ParamsIPA<vesta::Affine> = ParamsIPA::new(k);

    println!("11 vk generating, t: {:?}", start.elapsed());
    let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    println!("22 pk generating, t: {:?}", start.elapsed());
    let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");

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

    // let instances = &[&[root]];
    // let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    // create_proof::<
    //     KZGCommitmentScheme<Bn256>,
    //     ProverGWC<'_, Bn256>,
    //     Challenge255<G1Affine>,
    //     _,
    //     Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
    //     _,
    // >(
    //     &params,
    //     &pk,
    //     &[circuit],
    //     &[instances],
    //     OsRng,
    //     &mut transcript,
    // )
    // .expect("prover should not fail");

    // println!("proof: {:?}", proof);
}
