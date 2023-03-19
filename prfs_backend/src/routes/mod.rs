use group::prime::PrimeCurveAffine;
use group::GroupEncoding;
use halo2_gadgets::utilities::i2lebsp;
use halo2_proofs::halo2curves::CurveAffine;
use hyper::{header, Body, Request, Response, Server, StatusCode};
use rand::rngs::OsRng;
// Import the routerify prelude traits.
use routerify::prelude::*;
use routerify::{Middleware, RequestInfo, Router, RouterService};
use routerify_cors::enable_cors_all;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{convert::Infallible, net::SocketAddr};
use tokio_postgres::{Client, NoTls};

use crate::{middleware, State};
use group::ff::{Field, PrimeField};
use group::Curve;
use group::Group;
use halo2_gadgets::ecc::NonIdentityPoint;
use halo2_gadgets::poseidon::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord};
use halo2_gadgets::utilities::Var;
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
use std::convert::TryInto;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Seek, Write};
use std::marker::PhantomData;
use std::ops::{Mul, Neg};
use std::path::PathBuf;
use std::time::Instant;

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

    let proof = prfs_proofs::gen_id_proof(path, leaf, root, idx, public_key, msg_hash, r, s);

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
