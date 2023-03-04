mod climb;
mod grow;
mod hexutils;
mod leaves;

use chrono::prelude::*;
use halo2_gadgets::{
    poseidon::{
        // merkle::merkle_path::MerklePath,
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    },
    utilities::UtilitiesInstructions,
};
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

    // let l_val = "a0936063ef229f5f27c9f2383d98d5483f36524f000000000000000000000000";
    // let r_val = "e82bab520bc6624b06ad0ba914d3a2e1ce14bf1f000000000000000000000000";

    // let l = hexutils::convert_string_into_fp(l_val)?;
    // let r = hexutils::convert_string_into_fp(r_val)?;

    // let hash = poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init().hash([l, r]);

    // let parent_val = hexutils::convert_fp_to_string(hash).unwrap();
    // println!("parent: {:?}, parent val: {}", hash, parent_val);

    // leaves::make_leaves().await?;

    grow::grow_tree().await?;
    //
    // climb::climb_up().await?;

    Ok(())
}
