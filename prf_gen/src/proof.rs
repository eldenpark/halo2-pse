use crate::hexutils::{self, convert_fp_to_string, convert_string_into_fp};
use crate::{PrfGenError, State};
use group::ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use group::Group;
use group::{Curve, GroupEncoding};
use halo2_gadgets::ecc::NonIdentityPoint;
use halo2_gadgets::poseidon::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord};
use halo2_gadgets::utilities::{i2lebsp, Var};
use halo2_gadgets::{
    poseidon::{
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    },
    utilities::UtilitiesInstructions,
};
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::halo2curves::pairing::Engine;
use halo2_proofs::halo2curves::pasta::{self, pallas, vesta, Ep, EpAffine, EqAffine, Fp, Fq};
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
use hyper::{header, Body, Request, Response, Server, StatusCode};
use rand::rngs::OsRng;
use routerify::prelude::*;
use routerify::{Middleware, RequestInfo, Router, RouterService};
use routerify_cors::enable_cors_all;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Seek, Write};
use std::marker::PhantomData;
use std::ops::{Mul, Neg};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use std::{convert::Infallible, net::SocketAddr};
use tokio_postgres::{Client, NoTls};

#[derive(Serialize, Deserialize, Debug)]
struct Proof {
    power: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProofRequest {
    addr: String,
    sig: String,
}

struct ProofResponse {
    data: Vec<u8>,
}

pub async fn gen_proof_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let state = req.data::<State>().unwrap();
    let pg_client = state.pg_client.clone();

    let body = hyper::body::to_bytes(req.into_body()).await.unwrap();
    let proof_gen_request: ProofRequest = serde_json::from_slice(&body).unwrap();

    let sig = proof_gen_request.sig.strip_prefix("0x").unwrap();
    let sig_val = hex::decode(sig).unwrap();

    let r = &sig_val[1..33];
    let r: [u8; 32] = r.try_into().unwrap();
    let s = &sig_val[33..65];
    let s: [u8; 32] = s.try_into().unwrap();

    println!("sig: {:?}, siglen: {}", sig_val, sig_val.len());

    println!("proof_gen_requeset: {:?}", proof_gen_request);

    let proof = gen_proof(&pg_client, proof_gen_request.addr, r, s)
        .await
        .unwrap();

    let data = serde_json::to_string(&proof).unwrap();

    let res = Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(data))
        .unwrap();

    Ok(res)
}

async fn gen_proof(
    pg_client: &Arc<Client>,
    addr: String,
    r: [u8; 32],
    s: [u8; 32],
) -> Result<Vec<u8>, PrfGenError> {
    // let addr = "0x33d10Ab178924Cb7aD52f4c0C8062C3066607ec".to_lowercase();
    let addr = addr.to_lowercase();

    let row = pg_client
        .query_one(
            "SELECT pos, table_id, val FROM nodes WHERE addr=$1",
            &[&addr],
        )
        .await
        .expect("addr should be found");

    let addr: &str = row.get("val");
    let addr_pos: &str = row.get("pos");
    let addr_val = hexutils::convert_string_into_fp(addr);

    println!("STARTING addr: {}, addr_val (fp): {:?}", addr, addr_val);

    let auth_paths = generate_auth_paths(385);

    let mut nodes = vec![];

    for (_height, path) in auth_paths.iter().enumerate() {
        let pos = &path.node_loc;

        let node = match pg_client
            .query_one("SELECT pos, table_id, val FROM nodes WHERE pos=$1", &[&pos])
            .await
        {
            Ok(row) => {
                let val: &str = row.get("val");
                // let pos: &str = row.get("pos");

                // println!("sibling node, pos: {}, val: {}", pos, val);

                let node = hexutils::convert_string_into_fp(val);

                node
            }
            Err(_err) => {
                // println!("value doesn't exist, pos: {}", pos,);

                let node = Fp::zero();
                node
            }
        };

        nodes.push(node);
    }

    // println!("auth path: {:?}, len: {}", auth_paths, auth_paths.len());

    let leaf = addr_val;

    let pos = addr_pos.strip_prefix("0_").unwrap().parse::<u32>().unwrap();

    let auth_paths: [Fp; 31] = nodes.try_into().unwrap();

    // let pos_bits: [bool; 31] = i2lebsp(pos as u64);
    // let mut root = addr_val;
    // for (idx, el) in auth_paths.iter().enumerate() {
    //     let msg = if pos_bits[idx] {
    //         [*el, root]
    //     } else {
    //         [root, *el]
    //     };

    //     // println!("idx: {}, msg: {:?}", idx, msg);
    //     root = poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(msg);
    // }

    let r = Fq::from_repr(r).unwrap();
    let s = Fq::from_repr(s).unwrap();

    let row = pg_client
        .query_one(
            "SELECT pos, table_id, val FROM nodes WHERE pos=$1",
            &[&"31_0"],
        )
        .await
        .unwrap();

    let root_val = row.get("val");
    let root = convert_string_into_fp(root_val);

    ////////////////////////////////////////////////////////

    // println!("out-circuit: root: {:?}, t: {:?}", root, start.elapsed());
    let g = pallas::Affine::generator();

    // Generate a key pair
    let sk = <pallas::Affine as CurveAffine>::ScalarExt::random(OsRng);
    let public_key = (g * sk).to_affine();
    // EpAffine::from_bytes(bytes)
    // println!("public key: {:?}", public_key,);

    // Generate a valid signature
    // Suppose `m_hash` is the message hash
    let msg_hash = <pallas::Affine as CurveAffine>::ScalarExt::random(OsRng);

    // Draw arandomness
    let k = <pallas::Affine as CurveAffine>::ScalarExt::random(OsRng);
    let k_inv = k.invert().unwrap();

    // Calculate `r`
    let big_r = g * k;
    let r_point = big_r.to_affine().coordinates().unwrap();
    let x = r_point.x();
    let r = mod_n::<pallas::Affine>(*x);

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
        let r_candidate = mod_n::<pallas::Affine>(*x_candidate);

        assert_eq!(r, r_candidate);
    }

    let proof =
        pos_merkle::gen_id_proof(auth_paths, msg_hash, leaf, root, pos, public_key, r, s).unwrap();

    Ok(proof)
}

#[derive(Debug, Clone)]
pub struct MerklePath {
    // Node idx at height
    pub idx: u128,

    // Relative position of sibling to curr node. e.g. 0_0 has 0_1 sibling with
    // direction "false"
    pub direction: bool,

    // Node location, e.g. 0_1 refers to the second node in the lowest height
    pub node_loc: String,
}

fn generate_auth_paths(idx: u128) -> Vec<MerklePath> {
    let height = 31;
    let mut auth_path = vec![];
    let mut curr_idx = idx;

    for h in 0..height {
        let sibling_idx = get_sibling_idx(curr_idx);

        let sibling_dir = if sibling_idx % 2 == 0 { true } else { false };

        let p = MerklePath {
            idx: sibling_idx,
            direction: sibling_dir,
            node_loc: format!("{}_{}", h, sibling_idx),
        };

        auth_path.push(p);

        let parent_idx = get_parent_idx(curr_idx);
        curr_idx = parent_idx;
    }

    auth_path
}

fn get_sibling_idx(idx: u128) -> u128 {
    if idx % 2 == 0 {
        idx + 1
    } else {
        idx - 1
    }
}

pub fn get_parent_idx(idx: u128) -> u128 {
    idx / 2
}

fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
    let x_big = halo2wrong::utils::fe_to_big(x);
    halo2wrong::utils::big_to_fe(x_big)
}
