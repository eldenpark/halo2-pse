mod constants;
mod poseidon_merkle;
mod sign_verify;

use self::{
    poseidon_merkle::{PoseidonMerkleChip, PoseidonMerkleConfig},
    sign_verify::{SignVerifyChip, SignVerifyConfig},
};
use crate::{pk_bytes_le, pk_bytes_swap_endianness};
use crate::{
    zkevm_circuits::{
        table::KeccakTable,
        util::{Challenges, Expr},
    },
    ProofError,
};
use bus_mapping::circuit_input_builder::keccak_inputs_sign_verify;
use constants::{POS_RATE, POS_WIDTH};
use eth_types::sign_types::sign;
use eth_types::sign_types::SignData;
use eth_types::{self, Field};
use ff::PrimeField;
use group::Curve;
use halo2_gadgets::poseidon::primitives::Spec;
use halo2_gadgets::{
    poseidon::{
        self,
        primitives::{ConstantLength, P128Pow5T3},
    },
    utilities::i2lebsp,
};
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::group::Group;
use halo2_proofs::halo2curves::secp256k1;
use halo2_proofs::halo2curves::secp256k1::Secp256k1Affine;
use halo2_proofs::halo2curves::CurveAffine;
use halo2_proofs::halo2curves::{
    pasta::{EqAffine, Fp as PastaFp},
    FieldExt,
};
use halo2_proofs::{circuit::SimpleFloorPlanner, plonk::Circuit};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error},
};
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
    poly::{
        commitment::{Params, ParamsProver},
        ipa::{
            commitment::{IPACommitmentScheme, ParamsIPA},
            multiopen::ProverIPA,
        },
    },
    transcript::{Blake2bWrite, Challenge255, TranscriptWriterBuffer},
    SerdeFormat,
};
use keccak256::plain::Keccak;
use maingate::DimensionMeasurement;
use rand::{RngCore, SeedableRng};
use rand_core::OsRng;
use rand_xorshift::XorShiftRng;
use std::marker::PhantomData;
use std::{
    fs::File,
    io::{BufReader, BufWriter, Write},
    path::PathBuf,
    time::Instant,
};

fn pub_key_hash_to_address<F: Field>(pk_hash: &[u8]) -> F {
    pk_hash[32 - 20..]
        .iter()
        .fold(F::zero(), |acc, b| acc * F::from(256) + F::from(*b as u64))
}

#[derive(Clone, Debug)]
struct TestCircuitSignVerifyConfig<F: Field, const WIDTH: usize, const RATE: usize> {
    pub sign_verify_config: SignVerifyConfig,
    pub poseidon_merkle_config: PoseidonMerkleConfig<F, WIDTH, RATE>,
    pub challenges: Challenges,
}

#[derive(Default)]
struct TestCircuitSignVerify<
    F: Field,
    S: Spec<F, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
> {
    sign_verify_chip: SignVerifyChip<F>,
    poseidon_merkle_chip: PoseidonMerkleChip<F, S, WIDTH, RATE>,

    signatures: Vec<SignData>,

    leaf: Value<F>,
    root: Value<F>,
    leaf_idx: Value<u32>,
    path: Value<[F; 31]>,

    _marker: PhantomData<F>,
    _marker2: PhantomData<S>,
}

impl<F: Field, S: Spec<F, WIDTH, RATE>, const WIDTH: usize, const RATE: usize> Circuit<F>
    for TestCircuitSignVerify<F, S, WIDTH, RATE>
{
    type Config = TestCircuitSignVerifyConfig<F, WIDTH, RATE>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        TestCircuitSignVerify {
            sign_verify_chip: Default::default(),
            poseidon_merkle_chip: Default::default(),

            signatures: Default::default(),

            leaf: Value::unknown(),
            root: Value::unknown(),
            leaf_idx: Value::unknown(),
            path: Value::unknown(),

            _marker: PhantomData,
            _marker2: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let poseidon_merkle_config = PoseidonMerkleConfig::construct::<S>(meta);

        let keccak_table = KeccakTable::construct(meta);
        let challenges = Challenges::construct(meta);

        let sign_verify_config = {
            let challenges = challenges.exprs(meta);
            SignVerifyConfig::new(meta, keccak_table, challenges)
        };

        TestCircuitSignVerifyConfig {
            sign_verify_config,
            poseidon_merkle_config,
            challenges,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        println!("\nsynthesize()");

        let challenges = config.challenges.values(&mut layouter);

        let sig_verifications = self.sign_verify_chip.assign(
            &config.sign_verify_config,
            &mut layouter,
            &self.signatures,
            &challenges,
        )?;

        let calculated_root = self.poseidon_merkle_chip.climb_up_tree(
            config.poseidon_merkle_config.merkle_config,
            &mut layouter,
            &sig_verifications.get(0).unwrap().address,
            self.leaf_idx,
            self.path,
        )?;

        layouter.constrain_instance(
            calculated_root.cell(),
            config.poseidon_merkle_config.instance,
            0,
        )?;

        println!("calculated_root: {:?}", calculated_root);

        let address = &sig_verifications[0].address;
        println!("address: {:?}", address);

        address.value().map(|v| {
            let mut arr = v.to_repr();
            arr.reverse();
            let arr_str = hex::encode(arr);
            println!("in-circuit: arr rev: {:?}", arr_str);
        });

        config.sign_verify_config.keccak_table.dev_load(
            &mut layouter,
            &keccak_inputs_sign_verify(&self.signatures),
            &challenges,
        )?;

        config.sign_verify_config.load_range(&mut layouter)?;
        Ok(())
    }
}

#[cfg(test)]
mod sign_verify_tests {
    use super::*;
    use ff::Field;

    #[test]
    fn sign_verify1() {
        // Vectors using `XorShiftRng::seed_from_u64(1)`
        // sk: 0x771bd7bf6c6414b9370bb8559d46e1cedb479b1836ea3c2e59a54c343b0d0495
        // pk: (
        //   0x8e31a3586d4c8de89d4e0131223ecfefa4eb76215f68a691ae607757d6256ede,
        //   0xc76fdd462294a7eeb8ff3f0f698eb470f32085ba975801dbe446ed8e0b05400b
        // )
        // pk_hash: d90e2e9d267cbcfd94de06fa7adbe6857c2c733025c0b8938a76beeefc85d6c7
        // addr: 0x7adbe6857c2c733025c0b8938a76beeefc85d6c7
        let mut rng = XorShiftRng::seed_from_u64(1);

        let (sign_data, address) = {
            let (sk, pk) = gen_key_pair(&mut rng);
            println!("pk: {:?}", pk);

            let pk_le = pk_bytes_le(&pk);
            let pk_be = pk_bytes_swap_endianness(&pk_le);
            let pk_hash = (!false)
                .then(|| {
                    let mut keccak = Keccak::default();
                    keccak.update(&pk_be);
                    let hash: [_; 32] =
                        keccak.digest().try_into().expect("vec to array of size 32");
                    hash
                })
                .unwrap_or_default();
            // .map(|byte| Value::known(F::from(byte as u64)));

            let pk_hash_str = hex::encode(pk_hash);
            println!("pk_hash_str: {:?}", pk_hash_str);

            let address = {
                let mut a = [0u8; 32];
                a[12..].clone_from_slice(&pk_hash[12..]);
                a
            };
            let address_str = hex::encode(&address);
            println!("address_str: {:?}", address_str);

            let msg_hash = gen_msg_hash(&mut rng);
            let sig = sign_with_rng(&mut rng, sk, msg_hash);

            let sign_data = SignData {
                signature: sig,
                pk,
                msg_hash,
            };

            (sign_data, address)
        };

        let (leaf, root, leaf_idx, path) = {
            let mut addr = address;
            addr.reverse();

            let leaf = PastaFp::from_repr(addr).unwrap();

            let path = [
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
                PastaFp::from(1),
            ];

            let leaf_idx = 0;

            let pos_bits: [bool; 31] = i2lebsp(leaf_idx as u64);
            let mut root = leaf;
            for (idx, el) in path.iter().enumerate() {
                let msg = if pos_bits[idx] {
                    [*el, root]
                } else {
                    [root, *el]
                };

                root = poseidon::primitives::Hash::<
                    PastaFp,
                    P128Pow5T3,
                    ConstantLength<2>,
                    POS_WIDTH,
                    POS_RATE,
                >::init()
                .hash(msg);
            }

            println!("leaf: {:?}", leaf);
            println!("leaf_idx: {:?}", leaf_idx);
            println!("root: {:?}", root);

            (leaf, root, leaf_idx, path)
        };
    }

    fn gen_key_pair(rng: impl RngCore) -> (secp256k1::Fq, Secp256k1Affine) {
        let generator = Secp256k1Affine::generator();
        let sk = secp256k1::Fq::random(rng);
        let pk = generator * sk;
        let pk = pk.to_affine();

        (sk, pk)
    }

    fn gen_msg_hash(rng: impl RngCore) -> secp256k1::Fq {
        secp256k1::Fq::random(rng)
    }

    fn sign_with_rng(
        rng: impl RngCore,
        sk: secp256k1::Fq,
        msg_hash: secp256k1::Fq,
    ) -> (secp256k1::Fq, secp256k1::Fq) {
        let randomness = secp256k1::Fq::random(rng);
        sign(randomness, sk, msg_hash)
    }
}

pub fn gen_asset_proof<C: CurveAffine, F: FieldExt>(
    path: [PastaFp; 31],
    leaf: PastaFp,
    root: PastaFp,
    leaf_idx: u32,
    public_key: C,
    msg_hash: C::Scalar,
    r: C::Scalar,
    s: C::Scalar,
    sign_data: SignData,
) -> Result<Vec<u8>, ProofError> {
    let mut rng = XorShiftRng::seed_from_u64(2);
    let aux_generator = <Secp256k1Affine as CurveAffine>::CurveExt::random(&mut rng).to_affine();

    // SignVerifyChip -> ECDSAChip -> MainGate instance column
    let circuit = TestCircuitSignVerify::<PastaFp, P128Pow5T3, POS_WIDTH, POS_RATE> {
        sign_verify_chip: SignVerifyChip {
            aux_generator,
            window_size: 2,
            max_verif: 1,
            _marker: PhantomData,
        },
        poseidon_merkle_chip: PoseidonMerkleChip {
            _marker: PhantomData,
            _marker2: PhantomData,
        },

        signatures: vec![sign_data],

        leaf: Value::known(leaf),
        root: Value::known(root),
        leaf_idx: Value::known(leaf_idx),
        path: Value::known(path),

        _marker: PhantomData,
        _marker2: PhantomData,
    };

    let dimension = DimensionMeasurement::measure(&circuit).unwrap();
    let k = dimension.k();

    let instance = vec![vec![root], vec![]];

    println!("Running mock prover, k: {}", k);
    let prover = match MockProver::run(k, &circuit, instance) {
        Ok(prover) => prover,
        Err(e) => panic!("{:#?}", e),
    };

    prover.verify().unwrap();

    let start = Instant::now();
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

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

    let circuit_name = "asset_proof_1";
    let vk = {
        let vk_path = project_root.join(format!("vk_{}.dat", circuit_name));

        match File::open(&vk_path) {
            Ok(fd) => {
                let mut reader = BufReader::new(fd);
                let vk = VerifyingKey::<_>::read::<
                    _,
                    TestCircuitSignVerify<PastaFp, P128Pow5T3, POS_WIDTH, POS_RATE>,
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
                    TestCircuitSignVerify<PastaFp, P128Pow5T3, POS_WIDTH, POS_RATE>,
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
    Ok(vec![])
}
