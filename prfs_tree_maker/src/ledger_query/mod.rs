mod dynamodb;
// mod genesis;
mod ledger;
mod migrate;

use crate::config::{END_BLOCK, GETH_ENDPOINT, START_BLOCK};
use chrono::prelude::*;
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

    // simple_logging::log_to_file(log_files_path, LevelFilter::Error)?;

    // genesis::run().await?;

    // ledger::run(log_files_path).await?;

    // migrate::run(log_files_path).await?;

    Ok(())
}
