mod config;
mod dynamodb;
mod genesis;
mod geth;
mod ledger;
mod migrate;

use aws_config::meta::region::RegionProviderChain;
use chrono::prelude::*;
use config::GETH_ENDPOINT;
use config::{END_BLOCK, START_BLOCK};
use log::LevelFilter;
use std::fs::File;
use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

pub type QueryError = Box<dyn std::error::Error + Send + Sync>;

pub async fn run() -> Result<(), QueryError> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let now = Utc::now();
    let log_files_path = project_root.join(format!("log_files/log"));

    println!("start time: {}", now);
    println!("log file path: {:?}", log_files_path);
    println!("geth endpoint: {}", GETH_ENDPOINT);

    println!(
        "start block no: {}, end block no: {}",
        START_BLOCK, END_BLOCK
    );

    if log_files_path.exists() == false {
        File::create(&log_files_path).unwrap();
    }

    simple_logging::log_to_file(log_files_path, LevelFilter::Error)?;

    // {
    //     let region_provider = RegionProviderChain::default_provider();
    //     let config = aws_config::from_env().region(region_provider).load().await;

    //     if let None = config.region() {
    //         return Err("aws config is not properly loaded, region missing".into());
    //     }
    // }

    genesis::run().await?;

    // ledger::run(log_files_path).await?;

    // migrate::run(log_files_path).await?;

    Ok(())
}
