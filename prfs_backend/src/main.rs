use group::ff::{Field, PrimeField};
use group::prime::PrimeCurveAffine;
use group::Curve;
use group::Group;
use group::GroupEncoding;
use halo2_gadgets::ecc::NonIdentityPoint;
use halo2_gadgets::poseidon::{PoseidonInstructions, Pow5Chip, Pow5Config, StateWord};
use halo2_gadgets::utilities::i2lebsp;
use halo2_gadgets::utilities::Var;
use halo2_gadgets::{
    poseidon::{
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    },
    utilities::UtilitiesInstructions,
};
use halo2_proofs::halo2curves::bn256::Bn256;
use halo2_proofs::halo2curves::pairing::Engine;
use halo2_proofs::halo2curves::pasta::{pallas, vesta, Ep, EpAffine, EqAffine, Fp, Fq};
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
use prfs_backend::router;
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

// async fn gen_proof() -> Result<Vec<u8>, BackendError> {
//     let g = EpAffine::generator();

//     // Generate a key pair
//     let sk = <EpAffine as CurveAffine>::ScalarExt::random(OsRng);
//     let public_key = (g * sk).to_affine();
//     // println!("public key: {:?}", public_key,);
//     //
//     let a = public_key.to_bytes();

//     println!("pk: {:?}, aaa: {:?}", public_key, a,);
//     // EpAffine::from_bytes(bytes)
//     let b = EpAffine::from_bytes(&a).unwrap();
//     println!("c: {:?}", b);
//     println!("re pk: {:?}", b);

//     // Generate a valid signature
//     // Suppose `m_hash` is the message hash
//     let msg_hash = <EpAffine as CurveAffine>::ScalarExt::random(OsRng);

//     // Draw arandomness
//     let k = <pallas::Affine as CurveAffine>::ScalarExt::random(OsRng);
//     let k_inv = k.invert().unwrap();

//     // Calculate `r`
//     let big_r = g * k;
//     let r_point = big_r.to_affine().coordinates().unwrap();
//     let x = r_point.x();
//     let r = prfs_proofs::mod_n::<pallas::Affine>(*x);

//     // Calculate `s`
//     let s = k_inv * (msg_hash + (r * sk));
//     // println!("r: {:?}, s: {:?}", r, s);

//     // Sanity check. Ensure we construct a valid signature. So lets verify it
//     {
//         let s_inv = s.invert().unwrap();
//         let u_1 = msg_hash * s_inv;
//         let u_2 = r * s_inv;
//         let r_point = ((g * u_1) + (public_key * u_2))
//             .to_affine()
//             .coordinates()
//             .unwrap();
//         let x_candidate = r_point.x();
//         let r_candidate = prfs_proofs::mod_n::<pallas::Affine>(*x_candidate);

//         assert_eq!(r, r_candidate);
//     }

//     // let (t, u) = {
//     //     let r_inv = r.invert().unwrap();
//     //     let t = big_r * r_inv;
//     //     let u = -(g * (r_inv * msg_hash));

//     //     // let u_neg = u.neg();
//     //     // println!("444 u_neg: {:?}", u_neg);

//     //     let pk_candidate = (t * s + u).to_affine();
//     //     assert_eq!(public_key, pk_candidate);

//     //     (t.to_affine(), u.to_affine())
//     // };

//     ////////////////////////////////////////////////////////////
//     //// Merkle proof
//     ////////////////////////////////////////////////////////////
//     let path = [
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//         Fp::from(1),
//     ];

//     let leaf = Fp::from(2);

//     let pos = 0;

//     let pos_bits: [bool; 31] = i2lebsp(pos as u64);

//     let mut root = leaf;
//     for (idx, el) in path.iter().enumerate() {
//         let msg = if pos_bits[idx] {
//             [*el, root]
//         } else {
//             [root, *el]
//         };

//         // println!("idx: {}, msg: {:?}", idx, msg);
//         root = poseidon::Hash::<Fp, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash(msg);
//     }

//     let proof =
//         prfs_proofs::gen_id_proof::<EpAffine, Fp>(path, leaf, root, pos, public_key, msg_hash, r, s)
//             .unwrap();

//     println!("proof: {:?}", proof);

//     return Ok(proof);
// }

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
