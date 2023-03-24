mod climb;
mod grow;
mod hexutils;
mod leaves;
mod ledger_query;

use chrono::prelude::*;
use halo2_gadgets::{
    poseidon::{
        // merkle::merkle_path::MerklePath,
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    },
    utilities::UtilitiesInstructions,
};
use halo2_proofs::halo2curves::pasta::Fp;
use hyper::{body::HttpBody as _, Client, Uri};
use hyper::{Body, Method, Request, Response};
use hyper_tls::HttpsConnector;
use log::LevelFilter;
use std::fs::{File, OpenOptions};
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub type TreeMakerError = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), TreeMakerError> {
    println!("Tree maker starts");

    // let a = Fp::from(123123);
    // let b = hexutils::convert_fp_to_string(a);
    // let c = hexutils::convert_string_into_fp(&b);
    // println!("a: {:?}, b: {:?}, c: {:?}", a, b, c);
    // let addr = "0x33d10Ab178924ECb7aD52f4c0C8062C3066607ec";
    // let a = addr.strip_prefix("0x").unwrap().to_string();
    // let a = a + "000000000000000000000000";
    // let b = hexutils::convert_string_into_fp(&a);
    // let c = hexutils::convert_fp_to_string(b);
    // println!("a: {}, b: {:?}, c: {:?}", a, b, c);

    // {
    //     let l_val = "3506267e800be2df6dea26324ccd55b038491816aa7410c8a8cd22ee1a3a2855";
    //     let r_val = "2dd80e420f34f285726d69dbce5850b36693720ecda531196eb95b954ff1ce8c";

    //     let l = hexutils::convert_string_into_fp(l_val)?;
    //     let r = hexutils::convert_string_into_fp(r_val)?;

    //     let hash =
    //         poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash([l, r]);

    //     let parent_val = hexutils::convert_fp_to_string(hash).unwrap();
    //     println!("parent: {:?}, parent val: {}", hash, parent_val);
    // }

    // leaves::make_leaves().await?;

    // grow::grow_tree().await?;
    //
    climb::climb_up().await?;

    Ok(())
}
