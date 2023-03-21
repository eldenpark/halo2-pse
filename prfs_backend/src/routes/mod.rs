use crate::{middleware, State};
use eth_types::sign_types::SignData;
use group::ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use group::Curve;
use group::Group;
use group::GroupEncoding;
use halo2_gadgets::poseidon::{self, PoseidonInstructions, Pow5Chip, Pow5Config, StateWord};
use halo2_gadgets::utilities::i2lebsp;
use halo2_gadgets::utilities::Var;
use halo2_gadgets::{
    poseidon::{
        primitives::{ConstantLength, P128Pow5T3, Spec},
        Hash,
    },
    utilities::UtilitiesInstructions,
};
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::halo2curves::pairing::Engine;
use halo2_proofs::halo2curves::pasta::{
    pallas, vesta, Ep, EpAffine, EqAffine, Fp as PastaFp, Fq as PastaFq,
};
use halo2_proofs::halo2curves::secp256k1::{Fp as SecFp, Fq as SecFq, Secp256k1Affine};
use halo2_proofs::halo2curves::CurveAffine;
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use hyper::{body, header, Body, Request, Response, Server, StatusCode};
use keccak256::plain::Keccak;
use prfs_proofs::asset_proof_1::constants::{POS_RATE, POS_WIDTH};
use prfs_proofs::{asset_proof_1, gen_key_pair};
use prfs_proofs::{gen_msg_hash, pk_bytes_le, pk_bytes_swap_endianness, sign_with_rng};
use rand::rngs::OsRng;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;
use routerify::prelude::*;
use routerify::{Middleware, RequestInfo, Router, RouterService};
use routerify_cors::enable_cors_all;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{convert::Infallible, net::SocketAddr};
use tokio_postgres::{Client, NoTls};

#[derive(Serialize, Deserialize, Debug)]
struct GenProofRequest<'a> {
    proof_type: &'a str,
    address: &'a str,
    signature: &'a str,
    // leaf: &'a str,
    leaf_idx: u32,
    path: Vec<&'a str>,
    public_key: &'a str,
    msg_hash: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProofResponse {
    proof: Vec<u8>,
}

// Create a `Router<Body, Infallible>` for response body type `hyper::Body`
// and for handler error type `Infallible`.
pub fn router(pg_client: Arc<Client>) -> Router<Body, Infallible> {
    // Create a router and specify the logger middleware and the handlers.
    // Here, "Middleware::pre" means we're adding a pre middleware which will be executed
    // before any route handlers.
    let state = State { pg_client };

    Router::builder()
        .data(state)
        .middleware(Middleware::pre(middleware::logger))
        .middleware(enable_cors_all())
        .post("/gen_proof", gen_proof_handler)
        .err_handler_with_info(middleware::error_handler)
        .build()
        .unwrap()
}

async fn gen_proof_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    println!("gen proof request");

    let _state = req.data::<State>().unwrap();

    let bytes = body::to_bytes(req.into_body()).await.unwrap();
    let body_str = String::from_utf8(bytes.to_vec()).unwrap();
    let gen_proof_req = serde_json::from_str::<GenProofRequest>(&body_str).unwrap();

    println!("gen_proof_req: {:?}", gen_proof_req);

    // let region_provider = RegionProviderChain::default_provider();
    // let config = aws_config::from_env().region(region_provider).load().await;
    // aws rds call
    //

    let proof = {
        let address = {
            let mut address_vec = hex::decode(&gen_proof_req.address[2..]).unwrap();
            address_vec.reverse();
            let mut address = [0u8; 32];
            address[12..].clone_from_slice(&address_vec);
            address
        };

        let pk_be = hex::decode(&gen_proof_req.public_key[4..]).unwrap();
        let pk_le = pk_bytes_swap_endianness(&pk_be);
        let pk_x_le: [u8; 32] = pk_le[..32].try_into().unwrap();
        let pk_y_le: [u8; 32] = pk_le[32..].try_into().unwrap();
        let pk_x = SecFp::from_bytes(&pk_x_le).unwrap();
        let pk_y = SecFp::from_bytes(&pk_y_le).unwrap();
        println!("x: {:?}", pk_x);
        println!("y: {:?}", pk_y);

        let public_key = Secp256k1Affine::from_xy(pk_x, pk_y).unwrap();

        let signature = {
            let mut sig = hex::decode(&gen_proof_req.signature[4..]).unwrap();
            let r = &mut sig[..32];
            r.reverse();
            let r_le: [u8; 32] = r.try_into().unwrap();
            let r = SecFq::from_bytes(&r_le).unwrap();

            let s = &mut sig[32..];
            s.reverse();
            let s_le: [u8; 32] = s.try_into().unwrap();
            let s = SecFq::from_bytes(&s_le).unwrap();

            (r, s)
        };
        println!("signature: {:?}", signature);

        let msg_hash = {
            let mut msg_hash = hex::decode(&gen_proof_req.msg_hash[2..]).unwrap();
            msg_hash.reverse();
            let msg_hash_le: [u8; 32] = msg_hash.try_into().unwrap();
            SecFq::from_bytes(&msg_hash_le).unwrap()
        };
        println!("msg_hash: {:?}", msg_hash);

        let sign_data = SignData {
            pk: public_key,
            signature,
            msg_hash,
        };

        let leaf_idx = gen_proof_req.leaf_idx;

        let (leaf, root, path) = {
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

            (leaf, root, path)
        };

        asset_proof_1::gen_asset_proof::<Secp256k1Affine, PastaFp>(
            path, leaf, root, leaf_idx, sign_data,
        )
        .unwrap()
    };

    let proof_resp = ProofResponse { proof };

    let data = serde_json::to_string(&proof_resp).unwrap();

    let res = Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(data))
        .unwrap();

    Ok(res)
}
