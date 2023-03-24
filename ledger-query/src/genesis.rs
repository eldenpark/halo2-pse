use crate::{dynamodb, geth, QueryError};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::model::AttributeValue;
use aws_sdk_dynamodb::Client as DynamoClient;
use hyper::client::HttpConnector;
use hyper::{body::HttpBody as _, Client, Uri};
use hyper::{Body, Method, Request, Response};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, json};
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug)]
struct GenesisEntry {
    wei: String,
}

pub async fn run() -> Result<(), QueryError> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);

    get_genesis_block_addresses(&client).await?;
    // get_addresses().await?;

    Ok(())
}

async fn get_genesis_block_addresses(
    client: &Client<HttpsConnector<HttpConnector>>,
) -> Result<(), QueryError> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let genesis_block_path = project_root.join("data/genesis_block.json");

    let data = fs::read_to_string(&genesis_block_path)?;
    let genesis_block: HashMap<String, GenesisEntry> =
        serde_json::from_str(&data).expect("JSON does not have correct format.");

    let region_provider = RegionProviderChain::default_provider();
    let config = aws_config::from_env().region(region_provider).load().await;

    let dynamo_client = DynamoClient::new(&config);

    for (addr, _) in genesis_block {
        let addr = format!("0x{}", addr);

        let wei = geth::get_balance(&client, &addr).await?;

        dynamodb::put_item(&dynamo_client, addr, wei).await;
    }

    Ok(())
}
