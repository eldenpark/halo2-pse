use crate::geth::{GetBalanceRequest, GethClient};
use crate::{geth, TreeMakerError};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::model::AttributeValue;
use aws_sdk_dynamodb::Client as DynamoClient;
use crypto_bigint::U256;
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

pub async fn run() -> Result<(), TreeMakerError> {
    let postgres_pw = std::env::var("POSTGRES_PW")?;

    let https = HttpsConnector::new();
    let hyper_client = HyperClient::builder().build::<_, hyper::Body>(https);

    let pg_config = format!(
        "host=database-1.cstgyxdzqynn.ap-northeast-2.rds.amazonaws.com user=postgres password={}",
        postgres_pw,
    );
    let (pg_client, connection) = tokio_postgres::connect(&pg_config, NoTls).await?;

    let geth_client = GethClient { hyper_client };

    let pg_client = Arc::new(pg_client);
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            println!("connection error: {}", e);
        }
    });

    process_genesis_block_addresses(geth_client, pg_client).await?;

    Ok(())
}

async fn process_genesis_block_addresses(
    geth_client: GethClient,
    pg_client: Arc<PGClient>,
) -> Result<(), TreeMakerError> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let genesis_block_path = project_root.join("data/genesis_block.json");

    println!("genesis_block_path: {:?}", genesis_block_path);

    let data = fs::read_to_string(&genesis_block_path)?;
    let genesis_block: HashMap<String, GenesisEntry> =
        serde_json::from_str(&data).expect("JSON does not have correct format.");

    let mut values = vec![];
    for (idx, (addr, _)) in genesis_block.iter().enumerate() {
        let addr = format!("0x{}", addr);

        let result = geth_client
            .eth_getBalance(GetBalanceRequest(&addr, "latest"))
            .await?;

        if let Some(r) = result.result {
            let wei_str = r.strip_prefix("0x").unwrap();
            let wei = u128::from_str_radix(wei_str, 16).unwrap();

            // println!("addr: {}, wei: {}", addr, wei);

            let val = format!("('{}', {})", addr, wei);

            values.push(val);

            if idx % 100 == 0 {
                let stmt = format!(
                    "INSERT INTO balances_20230327 (addr, wei) VALUES {}",
                    values.join(",")
                );
                println!("stmt: {}", stmt);

                pg_client.execute(&stmt, &[]).await?;

                values = vec![];
            }
        }
    }

    Ok(())
}
