use crate::config::GETH_ENDPOINT;
use crate::geth::{GetBalanceRequest, GetBlockByNumberRequest, GetBlockResponse, GethClient};
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
use std::time::Duration;
use tokio::fs::OpenOptions;
use tokio_postgres::{Client as PGClient, NoTls};

// #[derive(Serialize, Deserialize, Debug)]
// struct GenesisEntry {
//     wei: String,
// }

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

    scan_ledger_addresses(geth_client, pg_client).await?;

    Ok(())
}

async fn scan_ledger_addresses(
    geth_client: GethClient,
    pg_client: Arc<PGClient>,
) -> Result<(), TreeMakerError> {
    let (start_block, end_block) = {
        let sb: u64 = std::env::var("START_BLOCK").unwrap().parse().unwrap();
        let eb: u64 = std::env::var("END_BLOCK").unwrap().parse().unwrap();

        (sb, eb)
    };

    let mut count = 0;

    let mut addresses = HashMap::<String, bool>::new();

    for no in start_block..end_block {
        let b_no = format!("0x{:x}", no);

        println!("processing block: {} ({})", b_no, no);

        let resp = geth_client
            .eth_getBlockByNumber(GetBlockByNumberRequest(&b_no, true))
            .await?;

        let result = if let Some(r) = resp.result {
            r
        } else {
            log::error!("Get block response failed, block_no: {}", no);

            return Err(format!("get block response failed").into());
        };

        // miner
        get_balance_and_put_item(&geth_client, &mut addresses, result.miner.to_string()).await?;

        for tx in result.transactions {
            // println!("processing tx: {}", tx.hash);

            // from
            get_balance_and_put_item(&geth_client, &mut addresses, tx.from.to_string()).await?;

            match tx.to {
                Some(to) => {
                    // to
                    get_balance_and_put_item(&geth_client, &mut addresses, to.to_string()).await?;
                }
                None => {
                    // let contract_addr = geth::get_contract_addr(tx.hash.to_string()).await?;
                    // // println!("contract_addr: {:?}", contract_addr);

                    // if let Some(addr) = contract_addr {
                    //     // contract
                    //     get_balance_and_put_item(
                    //         &client,
                    //         &dynamo_client,
                    //         &mut addresses,
                    //         addr.to_string(),
                    //     )
                    //     .await?;
                    // }
                }
            };
        }

        if count % 1000 == 0 {
            let mut fd = OpenOptions::new()
                .append(true)
                .open(&log_files_path)
                .unwrap();

            writeln!(fd, "{}", no)?;
        }

        count += 1;

        if count % 100000 == 0 {
            println!("Sleep a little while every 100000");

            tokio::time::sleep(Duration::from_millis(5000)).await;
        }
    }

    Ok(())
}

async fn get_balance_and_put_item(
    geth_client: &GethClient,
    addresses: &mut HashMap<String, bool>,
    addr: String,
) -> Result<(), TreeMakerError> {
    if addresses.contains_key(&addr) {
        // println!("skip, {}", addr);

        return Ok(());
    } else {
        // let wei = geth::get_balance(&client, &addr).await?;
        // dynamodb::put_item(&dynamo_client, addr.to_string(), wei).await;

        // addresses.insert(addr, true);
    }

    Ok(())
}
