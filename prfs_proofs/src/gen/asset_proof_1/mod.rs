pub mod constants;
mod poseidon_merkle;
mod sign_verify;

use self::{
    poseidon_merkle::{PoseidonMerkleChip, PoseidonMerkleConfig},
    sign_verify::{SignVerifyChip, SignVerifyConfig},
};
use crate::gen_key_pair;
use crate::{gen_msg_hash, sign_with_rng};
use crate::{pk_bytes_le, pk_bytes_swap_endianness};
use crate::{
    zkevm_circuits::{
        table::KeccakTable,
        util::{Challenges, Expr},
    },
    ProofError,
};
use bus_mapping::circuit_input_builder::keccak_inputs_sign_verify;
pub use constants::*;
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

            // leaf: Value::unknown(),
            // root: Value::unknown(),
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
        println!("in-circuit: calculated_root: {:?}", calculated_root.value());

        layouter.constrain_instance(
            calculated_root.cell(),
            config.poseidon_merkle_config.instance,
            0,
        )?;

        let address = &sig_verifications[0].address;
        println!("address: {:?}", address.value());

        address.value().map(|v| {
            let mut arr = v.to_repr();
            arr.reverse();
            let arr_str = hex::encode(arr);
            println!("in-circuit: address: {:?}", arr_str);
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
    use ff::Field;
    use group::GroupEncoding;
    use halo2_proofs::halo2curves::secp256k1::Fp as SecFp;
    use halo2_proofs::halo2curves::secp256k1::Fq as SecFq;

    use crate::gen_msg_hash2;

    use super::*;

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
        //
        //
        let (sk, pk) = {
            let sk = "";
            let mut sk_arr = hex::decode(sk).unwrap();
            sk_arr.reverse();
            let sk_arr: [u8; 32] = sk_arr.try_into().unwrap();
            let sk_fq = SecFq::from_bytes(&sk_arr).unwrap();
            println!("sk_fq: {:?}", sk_fq);

            let generator = Secp256k1Affine::generator();
            let sk = generator * sk_fq;
            let pk_affine = sk.to_affine();

            pk_affine.to_bytes();
            println!("pk affine: {:?}", pk_affine);

            (sk_fq, pk_affine)
        };

        let mut rng = XorShiftRng::seed_from_u64(1);

        let (sign_data, address) = {
            // let (sk, pk) = gen_key_pair(&mut rng);
            println!("pk: {:?}", pk);

            let pk_le = pk_bytes_le(&pk);
            let pk_be = pk_bytes_swap_endianness(&pk_le);
            let pk_hash = {
                let mut keccak = Keccak::default();
                keccak.update(&pk_be);
                let hash: [_; 32] = keccak.digest().try_into().expect("vec to array of size 32");
                hash
            };

            let pk_hash_str = hex::encode(pk_hash);
            println!("pk_hash_str: {:?}", pk_hash_str);

            let address = {
                let mut a = [0u8; 32];
                a[12..].clone_from_slice(&pk_hash[12..]);
                a
            };

            let address_str = hex::encode(&address);
            println!("address_str: {:?}", address_str);

            let k_vec: [u8; 32] = {
                let k = "EC633BD56A5774A0940CB97E27A9E4E51DC94AF737596A0C5CBB3D30332D92A5";
                let mut v = hex::decode(k).unwrap();
                v.reverse();
                v.try_into().unwrap()
            };
            println!("\nk_vec: {:?}", k_vec);

            // let msg_hash = gen_msg_hash2("test".to_string()).unwrap();
            // println!("msg_hash: {:?}", msg_hash);
            // 106921163081766108504851361111784132394560360614702516671885466167202468958885
            // let msg_hash = {
            //     let m = "06EF2B193B83B3D701F765F1DB34672AB84897E1252343CC2197829AF3A30456";
            //     let mut v = hex::decode(m).unwrap();
            //     v.reverse();

            //     let m: [u8; 32] = v.try_into().unwrap();
            //     SecFq::from_bytes(&m).unwrap()
            // };
            // println!("msg_hash: {:?}", msg_hash);

            let msg_hash = {
                let m = "4a5c5d454721bbbb25540c3317521e71c373ae36458f960d2ad46ef088110e95";
                let mut v = hex::decode(&m).unwrap();
                v.reverse();
                let m: [u8; 32] = v.try_into().unwrap();

                SecFq::from_bytes(&m).unwrap()
            };
            println!("msg_hash: {:?}", msg_hash);

            // let randomness = secp256k1::Fq::random(rng);
            // // let randomness = SecFq::from_bytes(&k_vec).unwrap();
            // println!("randomness: {:?}", randomness);

            // let sig = sign_with_rng(&mut rng, sk, msg_hash);
            // let sig = sign_with_rng(randomness, sk, msg_hash);
            // let r: [u8; 32] = {
            //     let r = "33A69CD2065432A30F3D1CE4EB0D59B8AB58C74F27C41A7FDB5696AD4E6108C9";
            //     let mut v = hex::decode(r).unwrap();
            //     v.reverse();
            //     v.try_into().unwrap()
            // };
            // let r = SecFq::from_bytes(&r).unwrap();
            // println!("r: {:?}", r);

            // let s: [u8; 32] = {
            //     let s = "6F807982866F785D3F6418D24163DDAE117B7DB4D5FDF0071DE069FA54342262";
            //     let mut v = hex::decode(s).unwrap();
            //     v.reverse();
            //     v.try_into().unwrap()
            // };
            // let s = SecFq::from_bytes(&s).unwrap();
            // println!("s: {:?}", s);

            let sig = {
                let sig = "8918975215107b43c9dabe0d0c293ac21a6aa24f785de2b1920badec0f8039fb70516ee590319425bef709f58f0208d37fb18f15ba077e70d21014bc731253af1c";

                let r: [u8; 32] = {
                    let r = sig[..64].to_string();
                    let mut v = hex::decode(r).unwrap();
                    v.reverse();
                    v.try_into().unwrap()
                };
                let r = SecFq::from_bytes(&r).unwrap();
                println!("r: {:?}", r);

                let s: [u8; 32] = {
                    let s = sig[64..128].to_string();
                    let mut v = hex::decode(s).unwrap();
                    v.reverse();
                    v.try_into().unwrap()
                };
                let s = SecFq::from_bytes(&s).unwrap();
                println!("s: {:?}", s);

                (r, s)
            };

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

        gen_asset_proof::<Secp256k1Affine, PastaFp>(path, leaf, root, leaf_idx, sign_data).unwrap();
    }
}

pub fn gen_asset_proof<C: CurveAffine, F: FieldExt>(
    path: [PastaFp; 31],
    leaf: PastaFp,
    root: PastaFp,
    leaf_idx: u32,
    sign_data: SignData,
) -> Result<Vec<u8>, ProofError> {
    println!("\ngen_asset_proof()");
    println!(
        "out-circuit: leaf: {:?}\nroot: {:?}\nleaf_idx: {}\nsign_data: {:?}",
        leaf, root, leaf_idx, sign_data
    );

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

        leaf_idx: Value::known(leaf_idx),
        path: Value::known(path),

        _marker: PhantomData,
        _marker2: PhantomData,
    };

    let dimension = DimensionMeasurement::measure(&circuit).unwrap();
    let k = dimension.k();

    let instance = vec![vec![root], vec![]];

    println!("\nRunning mock prover, k: {}", k);
    let prover = MockProver::run(k, &circuit, instance).unwrap();

    println!("\nVerifying proof");
    if let Err(err) = prover.verify() {
        println!("proof verification failed, \nerr: {:?}", err);
    } else {
        println!("proof verification success");
    }

    // let start = Instant::now();
    // let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    // let params = {
    //     let params_path = project_root.join(format!("params_{}.dat", k));

    //     match File::open(&params_path) {
    //         Ok(fd) => {
    //             let mut reader = BufReader::new(fd);
    //             ParamsIPA::read(&mut reader).unwrap()
    //         }
    //         Err(_) => {
    //             let fd = File::create(&params_path).unwrap();
    //             let params: ParamsIPA<EqAffine> = ParamsIPA::new(k);
    //             let mut writer = BufWriter::new(fd);
    //             params.write(&mut writer).unwrap();
    //             writer.flush().unwrap();
    //             params
    //         }
    //     }
    // };

    // println!("11 vk loading, t: {:?}", start.elapsed());

    // let circuit_name = "asset_proof_1";
    // let vk = {
    //     let vk_path = project_root.join(format!("vk_{}.dat", circuit_name));

    //     match File::open(&vk_path) {
    //         Ok(fd) => {
    //             let mut reader = BufReader::new(fd);
    //             let vk = VerifyingKey::<_>::read::<
    //                 _,
    //                 TestCircuitSignVerify<PastaFp, P128Pow5T3, POS_WIDTH, POS_RATE>,
    //             >(&mut reader, SerdeFormat::Processed)
    //             .unwrap();
    //             vk
    //         }
    //         Err(_) => {
    //             let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
    //             let fd = File::create(&vk_path).unwrap();
    //             let mut writer = BufWriter::new(fd);
    //             vk.write(&mut writer, SerdeFormat::Processed).unwrap();
    //             writer.flush().unwrap();
    //             vk
    //         }
    //     }
    // };

    // println!("11 pk loading, t: {:?}", start.elapsed());

    // let pk = {
    //     let pk_path = project_root.join(format!("pk_{}.dat", circuit_name));

    //     match File::open(&pk_path) {
    //         Ok(fd) => {
    //             let mut reader = BufReader::new(fd);
    //             let pk = ProvingKey::<_>::read::<
    //                 _,
    //                 TestCircuitSignVerify<PastaFp, P128Pow5T3, POS_WIDTH, POS_RATE>,
    //             >(&mut reader, SerdeFormat::Processed)
    //             .unwrap();

    //             pk
    //         }
    //         Err(_) => {
    //             let pk = keygen_pk(&params, vk, &circuit).expect("pk should not fail");
    //             let fd = File::create(&pk_path).unwrap();
    //             let mut writer = BufWriter::new(fd);
    //             pk.write(&mut writer, SerdeFormat::Processed).unwrap();
    //             writer.flush().unwrap();
    //             pk
    //         }
    //     }
    // };

    // let mut rng = OsRng;
    // let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    // println!("creating proof, t: {:?}", start.elapsed());

    // create_proof::<IPACommitmentScheme<_>, ProverIPA<_>, _, _, _, _>(
    //     &params,
    //     &pk,
    //     &[circuit],
    //     &[&[&[root], &[]]],
    //     &mut rng,
    //     &mut transcript,
    // )
    // .unwrap();

    // let proof = transcript.finalize();

    // println!(
    //     "proof generated, len: {}, t: {:?}",
    //     proof.len(),
    //     start.elapsed()
    // );
    Ok(vec![])
}
