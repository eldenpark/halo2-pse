use crate::config::{END_BLOCK, GETH_ENDPOINT, START_BLOCK};
use crate::geth;
use crate::geth::GetBlockResponse;
use crate::TreeMakerError;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::model::AttributeValue;
use aws_sdk_dynamodb::Client as DynamoClient;
use hyper::client::HttpConnector;
use hyper::{body::HttpBody as _, Client, Uri};
use hyper::{Body, Method, Request, Response};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, json};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

pub async fn run(log_files_path: PathBuf) -> Result<(), TreeMakerError> {
    println!("ledger run");

    get_addresses(log_files_path).await?;

    Ok(())
}

async fn get_addresses(log_files_path: PathBuf) -> Result<(), TreeMakerError> {
    let mut count = 0;

    let region_provider = RegionProviderChain::default_provider();
    let config = aws_config::from_env().region(region_provider).load().await;

    if let None = config.region() {
        return Err("aws config is not properly loaded, region missing".into());
    }

    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);
    let dynamo_client = DynamoClient::new(&config);
    let mut addresses = HashMap::<String, bool>::new();

    for no in START_BLOCK..END_BLOCK {
        let b_no = format!("0x{:x}", no);

        println!("processing block: {} ({})", b_no, no);

        let body = json!(
            {
                "jsonrpc": "2.0",
                "method": "eth_getBlockByNumber",
                "params":[b_no, true],
                "id":1,
            }
        )
        .to_string();

        let req = Request::builder()
            .method(Method::POST)
            .uri(GETH_ENDPOINT)
            .header("content-type", "application/json")
            .body(Body::from(body))?;

        let resp = client.request(req).await?;

        let buf = hyper::body::to_bytes(resp).await?;

        let resp: GetBlockResponse = match serde_json::from_slice(&buf) {
            Ok(r) => r,
            Err(err) => {
                println!(
                    "Could not parse block response, buf: {:?}, err: {}",
                    buf, err
                );

                return Err(err.into());
            }
        };

        // miner
        get_balance_and_put_item(
            &client,
            &dynamo_client,
            &mut addresses,
            resp.result.miner.to_string(),
        )
        .await?;

        for tx in resp.result.transactions {
            // println!("processing tx: {}", tx.hash);

            // from
            get_balance_and_put_item(&client, &dynamo_client, &mut addresses, tx.from.to_string())
                .await?;

            match tx.to {
                Some(to) => {
                    // to
                    get_balance_and_put_item(
                        &client,
                        &dynamo_client,
                        &mut addresses,
                        to.to_string(),
                    )
                    .await?;
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
    client: &Client<HttpsConnector<HttpConnector>>,
    dynamo_client: &DynamoClient,
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
