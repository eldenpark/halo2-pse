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
use halo2_proofs::halo2curves::pasta::{pallas, vesta, Ep, EpAffine, EqAffine, Fp as PastaFp, Fq};
use halo2_proofs::halo2curves::secp256k1::Secp256k1Affine;
use halo2_proofs::halo2curves::CurveAffine;
use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, ProvingKey, VerifyingKey};
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use hyper::{header, Body, Request, Response, Server, StatusCode};
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
        .get("/users/:userId", user_handler)
        .err_handler_with_info(middleware::error_handler)
        .build()
        .unwrap()
}

// A handler for "/" page.
async fn gen_proof_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    println!("gen proof");

    let _state = req.data::<State>().unwrap();

    // let region_provider = RegionProviderChain::default_provider();
    // let config = aws_config::from_env().region(region_provider).load().await;

    // aws rds call

    // let proof = vec![];
    let proof = {
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

// A handler for "/users/:userId" page.
async fn user_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let user_id = req.param("userId").unwrap();
    Ok(Response::new(Body::from(format!("Hello {}", user_id))))
}
