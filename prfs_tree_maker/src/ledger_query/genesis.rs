use super::{dynamodb, geth, QueryError};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::model::AttributeValue;
use aws_sdk_dynamodb::Client as DynamoClient;
use hyper::client::HttpConnector;
use hyper::{body::HttpBody as _, Client as HyperClient, Uri};
use hyper::{Body, Method, Request, Response};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, json};
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::PathBuf;
use std::sync::Arc;
use tokio_postgres::{Client as PGClient, NoTls};

#[derive(Serialize, Deserialize, Debug)]
struct GenesisEntry {
    wei: String,
}

pub async fn run() -> Result<(), QueryError> {
    let https = HttpsConnector::new();
    let hyper_client = HyperClient::builder().build::<_, hyper::Body>(https);

    {}

    let (pg_client, connection) = tokio_postgres::connect(
        "host=database-1.cstgyxdzqynn.ap-northeast-2.rds.amazonaws.com user=postgres password=postgres",
        NoTls,
    )
    .await?;

    let pg_client = Arc::new(pg_client);
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            println!("connection error: {}", e);
        }
    });

    get_genesis_block_addresses(&hyper_client, pg_client).await?;
    // get_addresses().await?;

    Ok(())
}

async fn get_genesis_block_addresses(
    hyper_client: &HyperClient<HttpsConnector<HttpConnector>>,
    pg_client: Arc<PGClient>,
) -> Result<(), QueryError> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let genesis_block_path = project_root.join("data/genesis_block.json");

    println!("genesis_block_path: {:?}", genesis_block_path);

    let data = fs::read_to_string(&genesis_block_path)?;
    let genesis_block: HashMap<String, GenesisEntry> =
        serde_json::from_str(&data).expect("JSON does not have correct format.");

    for (idx, (addr, _)) in genesis_block.iter().enumerate() {
        let addr = format!("0x{}", addr);
        let wei = geth::get_balance(&hyper_client, &addr).await?;

        println!("addr: {}, wei: {}", addr, wei);

        // pg_client.batch_execute(query)
    }

    Ok(())
}
