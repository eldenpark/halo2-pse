use crate::{BackendError, State};
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
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct MerklePath {
    pub pos_w: Decimal,
    pub pos_h: i32,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct GetNodesRequest<'a> {
    set_id: &'a str,
    merkle_path: Vec<MerklePath>,
}

#[derive(Serialize, Deserialize, Debug)]
struct GetNodesResponse {
    merkle_path: Vec<MerklePath>,
}

pub async fn get_nodes_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    println!("gen proof request");

    let state = req.data::<State>().unwrap();
    let db = state.db.clone();

    let bytes = body::to_bytes(req.into_body()).await.unwrap();
    let body_str = String::from_utf8(bytes.to_vec()).unwrap();
    let get_nodes_req = serde_json::from_str::<GetNodesRequest>(&body_str)
        .expect("get_nodes request should be parsable");

    println!("get_nodes_req: {:?}", get_nodes_req);

    let set_id = get_nodes_req.set_id.to_string();

    let whre: Vec<String> = get_nodes_req
        .merkle_path
        .iter()
        .map(|mp| format!("(pos_w = {} and pos_h = {})", mp.pos_w, mp.pos_h))
        .collect();

    let whre = whre.join(" OR ");

    let where_clause = format!(
        "set_id = '{}' AND ({}) ORDER BY pos_h",
        set_id.to_string(),
        whre,
    );

    println!("where_clause, {}", where_clause);

    let rows = db.get_nodes(&where_clause).await.expect("get nodes fail");

    let merkle_path: Result<Vec<Node>, BackendError> = rows
        .iter()
        .map(|r| {
            let pos_w: Decimal = r.try_get("pos_w").unwrap();
            let pos_h: i32 = r.try_get("pos_h").unwrap();
            let val: String = r.try_get("val").unwrap();
            let set_id: String = r.try_get("set_id").unwrap();

            Ok(Node {
                pos_w,
                pos_h,
                val,
                set_id,
            })
        })
        .collect();
    println!("merkle_path: {:?}", merkle_path);

    let merkle_path = merkle_path.unwrap();

    let get_nodes_resp = GetNodesResponse { merkle_path };

    let data = serde_json::to_string(&get_nodes_resp).unwrap();

    let res = Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(data))
        .unwrap();

    Ok(res)
}
