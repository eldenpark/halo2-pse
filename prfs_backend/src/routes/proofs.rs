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
use prfs_proofs::asset_proof_1;
use prfs_proofs::asset_proof_1::constants::{POS_RATE, POS_WIDTH};
use prfs_proofs::{pk_bytes_le, pk_bytes_swap_endianness};
use routerify::prelude::*;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct GenProofRequest<'a> {
    proof_type: &'a str,
    address: &'a str,
    signature: &'a str,
    leaf_idx: u32,
    path: Vec<&'a str>,
    public_key: &'a str,
    message_raw: &'a str,
    message_hash: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
struct ProofResponse {
    proof: Vec<u8>,
}

pub async fn gen_proof_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    println!("gen proof request");

    let _state = req.data::<State>().unwrap();

    let bytes = body::to_bytes(req.into_body()).await.unwrap();
    let body_str = String::from_utf8(bytes.to_vec()).unwrap();
    let gen_proof_req = serde_json::from_str::<GenProofRequest>(&body_str).unwrap();

    println!("gen_proof_req: {:?}", gen_proof_req);

    // let region_provider = RegionProviderChain::default_provider();
    // let config = aws_config::from_env().region(region_provider).load().await;
    // aws rds call

    let proof = {
        let address = {
            let address_vec = hex::decode(&gen_proof_req.address[2..]).unwrap();
            // address_vec.reverse();
            let mut address = [0u8; 32];
            address[12..].clone_from_slice(&address_vec);
            address
        };
        let addr_str = hex::encode(address);
        println!("address_str: {}", addr_str);

        let pk_be = hex::decode(&gen_proof_req.public_key[4..]).unwrap();
        let pk_le = pk_bytes_swap_endianness(&pk_be);

        let pk_x_le: [u8; 32] = pk_le[..32].try_into().unwrap();
        let pk_x_str = hex::encode(pk_x_le);
        println!("pk_x_str: {}", pk_x_str);

        let pk_x = SecFp::from_bytes(&pk_x_le).unwrap();
        println!("x fp: {:?}", pk_x);

        let pk_y_le: [u8; 32] = pk_le[32..].try_into().unwrap();
        let pk_y = SecFp::from_bytes(&pk_y_le).unwrap();
        println!("y fp: {:?}", pk_y);

        let public_key = Secp256k1Affine::from_xy(pk_x, pk_y).unwrap();
        {
            let pk_le = pk_bytes_le(&public_key);
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
            println!("address_str calculated: {:?}", address_str);
        }

        let signature = {
            let mut sig = hex::decode(&gen_proof_req.signature[2..]).unwrap();
            let r = &mut sig[..32];
            r.reverse();
            let r_le: [u8; 32] = r.try_into().unwrap();
            let r = SecFq::from_bytes(&r_le).unwrap();

            let s = &mut sig[32..64];
            s.reverse();
            let s_le: [u8; 32] = s.try_into().unwrap();
            let s = SecFq::from_bytes(&s_le).unwrap();

            (r, s)
        };
        println!("signature: {:?}", signature);

        let msg_hash = {
            let mut msg_hash = hex::decode(&gen_proof_req.message_hash[2..]).unwrap();
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

        println!("leaf: {:?}", leaf);
        println!("leaf_idx: {:?}", leaf_idx);
        println!("root: {:?}", root);

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
