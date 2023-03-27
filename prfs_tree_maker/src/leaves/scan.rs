use crate::config::GETH_ENDPOINT;
use crate::geth::{
    GetBalanceRequest, GetBlockByNumberRequest, GetBlockResponse, GetTransactionReceiptRequest,
    GethClient,
};
use crate::{geth, TreeMakerError};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::model::AttributeValue;
use aws_sdk_dynamodb::Client as DynamoClient;
use hyper::client::HttpConnector;
use hyper::{body::HttpBody as _, Client as HyperClient, Uri};
use hyper::{Body, Method, Request, Response};
use hyper_tls::HttpsConnector;
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, json};
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::OpenOptions;
use tokio_postgres::{Client as PGClient, NoTls};

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
        let sb: u64 = std::env::var("START_BLOCK")
            .expect("env var START_BLOCK missing")
            .parse()
            .unwrap();
        let eb: u64 = std::env::var("END_BLOCK")
            .expect("env var END_BLOCK missing")
            .parse()
            .unwrap();

        (sb, eb)
    };

    let mut count = 0;

    let mut addresses = HashMap::<String, String>::new();

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
        get_balance_and_add_item(&geth_client, &mut addresses, result.miner.to_string()).await?;

        for tx in result.transactions {
            println!("processing tx: {}", tx.hash);

            // from
            get_balance_and_add_item(&geth_client, &mut addresses, tx.from.to_string()).await?;

            match tx.to {
                Some(to) => {
                    // to
                    get_balance_and_add_item(&geth_client, &mut addresses, to.to_string()).await?;
                }
                None => {
                    let resp = &geth_client
                        .eth_getTransactionReceipt(GetTransactionReceiptRequest(&tx.hash))
                        .await?;

                    println!("get transaction receipt resp: {:?}", resp);

                    if let Some(r) = &resp.result {
                        if let Some(contract_addr) = &r.contractAddress {
                            // contract
                            get_balance_and_add_item(
                                &geth_client,
                                &mut addresses,
                                contract_addr.to_string(),
                            )
                            .await?;
                        }
                    }
                }
            };
        }

        for (key, _) in addresses.iter() {
            println!("key: {}", key);
            if key == &"0x33d10Ab178924ECb7aD52f4c0C8062C3066607ec".to_lowercase() {
                println!("11 power");
            }
        }

        if count % 1000 == 0 {
            log::info!("block_no: {}", no);
        }

        count += 1;

        // if count % 100000 == 0 {
        //     println!("Sleep a little while every 100000");

        //     tokio::time::sleep(Duration::from_millis(5000)).await;
        // }
    }

    Ok(())
}

async fn get_balance_and_add_item(
    geth_client: &GethClient,
    addresses: &mut HashMap<String, String>,
    addr: String,
) -> Result<(), TreeMakerError> {
    if addresses.contains_key(&addr) {
        // println!("skip, {}", addr);
        return Ok(());
    } else {
        let resp = geth_client
            .eth_getBalance(GetBalanceRequest(&addr, "latest"))
            .await?;

        if let Some(r) = resp.result {
            let wei = {
                let wei_str = r
                    .strip_prefix("0x")
                    .expect("wei str should contain 0x")
                    .to_string();

                match U256::from_str_radix(&wei_str, 16) {
                    Ok(u) => u,
                    Err(err) => {
                        log::error!(
                            "u256 conversion failed, err: {}, wei_str: {}, addr: {}",
                            err,
                            wei_str,
                            addr
                        );

                        return Err(err.into());
                    }
                }
            };

            addresses.insert(addr, wei.to_string());
        }
    }

    Ok(())
}
