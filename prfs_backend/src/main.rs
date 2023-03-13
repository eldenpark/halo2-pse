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

pub type BackendError = Box<dyn std::error::Error + Send + Sync>;

// Define an app state to share it across the route handlers and middlewares.
struct State {
    pg_client: Arc<Client>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProofResponse {
    proof: Vec<u8>,
}

async fn gen_proof() -> Result<Vec<u8>, BackendError> {
    let g = EpAffine::generator();

    // Generate a key pair
    let sk = <EpAffine as CurveAffine>::ScalarExt::random(OsRng);
    let public_key = (g * sk).to_affine();
    // println!("public key: {:?}", public_key,);
    //
    let a = public_key.to_bytes();

    println!("pk: {:?}, aaa: {:?}", public_key, a,);
    // EpAffine::from_bytes(bytes)
    let b = EpAffine::from_bytes(&a).unwrap();
    println!("c: {:?}", b);
    println!("re pk: {:?}", b);

    // Generate a valid signature
    // Suppose `m_hash` is the message hash
    let msg_hash = <EpAffine as CurveAffine>::ScalarExt::random(OsRng);

    // Draw arandomness
    let k = <pallas::Affine as CurveAffine>::ScalarExt::random(OsRng);
    let k_inv = k.invert().unwrap();

    // Calculate `r`
    let big_r = g * k;
    let r_point = big_r.to_affine().coordinates().unwrap();
    let x = r_point.x();
    let r = pos_merkle::mod_n::<pallas::Affine>(*x);

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
        let r_candidate = pos_merkle::mod_n::<pallas::Affine>(*x_candidate);

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

    let proof =
        pos_merkle::gen_id_proof::<EpAffine, Fp>(path, leaf, root, pos, public_key, msg_hash, r, s)
            .unwrap();

    println!("proof: {:?}", proof);

    return Ok(proof);
}

// A handler for "/" page.
async fn gen_proof_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    println!("gen proof");
    // Access the app state.
    let state = req.data::<State>().unwrap();

    // let region_provider = RegionProviderChain::default_provider();
    // let config = aws_config::from_env().region(region_provider).load().await;

    // aws rds call
    //

    let proof = gen_proof().await.unwrap();

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

// A middleware which logs an http request.
async fn logger(req: Request<Body>) -> Result<Request<Body>, Infallible> {
    println!(
        "{} {} {}",
        req.remote_addr(),
        req.method(),
        req.uri().path()
    );
    Ok(req)
}

// Define an error handler function which will accept the `routerify::Error`
// and the request information and generates an appropriate response.
async fn error_handler(err: routerify::RouteError, _: RequestInfo) -> Response<Body> {
    eprintln!("{}", err);

    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from(format!("Something went wrong: {}", err)))
        .unwrap()
}

// Create a `Router<Body, Infallible>` for response body type `hyper::Body`
// and for handler error type `Infallible`.
fn router(pg_client: Arc<Client>) -> Router<Body, Infallible> {
    // Create a router and specify the logger middleware and the handlers.
    // Here, "Middleware::pre" means we're adding a pre middleware which will be executed
    // before any route handlers.
    let state = State { pg_client };

    Router::builder()
        .data(state)
        .middleware(Middleware::pre(logger))
        .middleware(enable_cors_all())
        .post("/gen_proof", gen_proof_handler)
        .get("/users/:userId", user_handler)
        .err_handler_with_info(error_handler)
        .build()
        .unwrap()
}

#[tokio::main]
async fn main() {
    let (pg_client, connection) = tokio_postgres::connect(
        "host=database-1.cstgyxdzqynn.ap-northeast-2.rds.amazonaws.com user=postgres password=postgres",
        NoTls,
    )
    .await.unwrap();

    let pg_client = Arc::new(pg_client);
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            println!("connection error: {}", e);
        }
    });

    let router = router(pg_client);

    // Create a Service from the router above to handle incoming requests.
    let service = RouterService::new(router).unwrap();

    // The address on which the server will be listening.
    let addr = SocketAddr::from(([127, 0, 0, 1], 4000));

    // Create a server by passing the created service to `.serve` method.
    let server = Server::bind(&addr).serve(service);

    println!("App is running on: {}", addr);
    if let Err(err) = server.await {
        eprintln!("Server error: {}", err);
    }
}
