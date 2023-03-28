use crate::config::GETH_ENDPOINT;
use crate::db::Database;
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
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::OpenOptions;
use tokio_postgres::{Client as PGClient, NoTls};

pub async fn run() -> Result<(), TreeMakerError> {
    let https = HttpsConnector::new();
    let hyper_client = HyperClient::builder().build::<_, hyper::Body>(https);

    let geth_client = GethClient { hyper_client };
    let db = Database::connect().await?;

    scan_ledger_addresses(geth_client, db).await?;

    Ok(())
}

async fn scan_ledger_addresses(
    geth_client: GethClient,
    db: Database,
    // pg_client: Arc<PGClient>,
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

    let mut balances = BTreeMap::<String, u128>::new();

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
        get_balance_and_add_item(&geth_client, &mut balances, result.miner.to_string()).await?;

        for tx in result.transactions {
            println!("processing tx: {}", tx.hash);

            // from
            get_balance_and_add_item(&geth_client, &mut balances, tx.from.to_string()).await?;

            match tx.to {
                Some(to) => {
                    // to
                    get_balance_and_add_item(&geth_client, &mut balances, to.to_string()).await?;
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
                                &mut balances,
                                contract_addr.to_string(),
                            )
                            .await?;
                        }
                    }
                }
            };
        }

        for (key, _) in balances.iter() {
            println!("key: {}", key);

            if key == &"0x33d10Ab178924ECb7aD52f4c0C8062C3066607ec".to_lowercase() {
                println!("11 power");
            }
        }

        if count % 500 == 0 {
            log::info!("block_no: {}", no);

            db.insert_balances(balances).await?;
            balances = BTreeMap::new();
        }

        count += 1;
    }

    Ok(())
}

async fn get_balance_and_add_item(
    geth_client: &GethClient,
    addresses: &mut BTreeMap<String, u128>,
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

                match u128::from_str_radix(&wei_str, 16) {
                    Ok(u) => u,
                    Err(err) => {
                        log::error!(
                            "u128 conversion failed, err: {}, wei_str: {}, addr: {}",
                            err,
                            wei_str,
                            addr
                        );

                        return Err(err.into());
                    }
                }
            };
            addresses.insert(addr, wei);
        }
    }

    Ok(())
}
