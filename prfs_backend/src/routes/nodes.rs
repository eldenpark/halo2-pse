use crate::State;
use eth_types::sign_types::SignData;
use ff::PrimeField;
use halo2_gadgets::poseidon::{
    self,
    primitives::{ConstantLength, P128Pow5T3},
};
use halo2_gadgets::utilities::i2lebsp;
use halo2_proofs::halo2curves::pasta::{Fp as PastaFp, Fq as PastaFq};
use halo2_proofs::halo2curves::secp256k1::{Fp as SecFp, Fq as SecFq, Secp256k1Affine};
use halo2_proofs::halo2curves::CurveAffine;
use hyper::{body, header, Body, Request, Response};
use keccak256::plain::Keccak;
use prfs_db_interface::Node;
use prfs_proofs::asset_proof_1;
use prfs_proofs::asset_proof_1::constants::{POS_RATE, POS_WIDTH};
use prfs_proofs::{pk_bytes_le, pk_bytes_swap_endianness};
use routerify::prelude::*;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;

#[derive(Serialize, Deserialize, Debug)]
struct GetNodesRequest<'a> {
    set_id: &'a str,
    paths: Vec<&'a str>,
}

#[derive(Serialize, Deserialize, Debug)]
struct GetNodesResponse {
    nodes: Vec<Node>,
}

pub async fn get_nodes_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    println!("gen proof request");

    let _state = req.data::<State>().unwrap();

    let bytes = body::to_bytes(req.into_body()).await.unwrap();
    let body_str = String::from_utf8(bytes.to_vec()).unwrap();
    let get_nodes_req = serde_json::from_str::<GetNodesRequest>(&body_str).unwrap();

    let get_nodes_resp = GetNodesResponse { nodes: vec![] };

    let data = serde_json::to_string(&get_nodes_resp).unwrap();

    let res = Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(data))
        .unwrap();

    Ok(res)
}
