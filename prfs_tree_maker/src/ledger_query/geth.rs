use super::config::GETH_ENDPOINT;
use super::QueryError;
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
use std::fmt::Display;
use std::fs::{self, File};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug)]
pub struct GetBalanceResponse<'a> {
    pub jsonrpc: &'a str,
    pub id: usize,
    pub result: &'a str,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub struct Block<'a> {
    pub difficulty: &'a str,
    pub extraData: &'a str,
    pub gasLimit: &'a str,
    pub gasUsed: &'a str,
    pub hash: &'a str,
    pub logsBloom: &'a str,
    pub miner: &'a str,
    pub mixHash: &'a str,
    pub nonce: &'a str,
    pub number: &'a str,
    pub parentHash: &'a str,
    pub receiptsRoot: &'a str,
    pub sha3Uncles: &'a str,
    pub size: &'a str,
    pub stateRoot: &'a str,
    pub timestamp: &'a str,
    pub totalDifficulty: &'a str,
    pub transactions: Vec<Transaction<'a>>,
    pub transactionsRoot: &'a str,
    pub uncles: Vec<&'a str>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub struct Transaction<'a> {
    pub blockHash: &'a str,
    pub blockNumber: &'a str,
    pub from: &'a str,
    pub gas: &'a str,
    pub gasPrice: &'a str,
    pub hash: &'a str,
    pub input: &'a str,
    pub nonce: &'a str,
    pub to: Option<&'a str>,
    pub transactionIndex: &'a str,
    pub value: &'a str,

    #[serde(rename = "type")]
    pub kind: &'a str,
    pub v: &'a str,
    pub r: &'a str,
    pub s: &'a str,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub struct TransactionReceipt<'a> {
    blockHash: &'a str,
    blockNumber: &'a str,
    contractAddress: Option<&'a str>,
    cumulativeGasUsed: &'a str,
    effectiveGasPrice: &'a str,
    from: &'a str,
    gasUsed: &'a str,
    logsBloom: &'a str,
    #[serde(skip_deserializing)]
    logs: Option<HashMap<String, String>>,
    root: Option<&'a str>,
    to: Option<&'a str>,
    transactionHash: &'a str,
    transactionIndex: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetBlockResponse<'a> {
    pub jsonrpc: &'a str,
    pub id: usize,
    pub result: Block<'a>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetTransactionReceiptResponse<'a> {
    pub jsonrpc: &'a str,
    pub id: usize,
    pub result: TransactionReceipt<'a>,
}

pub async fn get_contract_addr<S: Into<String> + Serialize + Display>(
    tx_hash: S,
) -> Result<Option<String>, QueryError> {
    let body = json!(
        {
            "jsonrpc":"2.0",
            "method": "eth_getTransactionReceipt",
            "params":[tx_hash],
            "id":1,
        }
    )
    .to_string();

    let req = Request::builder()
        .method(Method::POST)
        .uri(GETH_ENDPOINT)
        .header("content-type", "application/json")
        .body(Body::from(body))?;

    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, hyper::Body>(https);

    let resp = client.request(req).await?;

    let buf = hyper::body::to_bytes(resp).await?;

    let resp: GetTransactionReceiptResponse = match serde_json::from_slice(&buf) {
        Ok(r) => {
            r
            // / return Ok(r.result.contractAddress.map(|s| s.to_string()));
        }
        Err(err) => {
            println!(
                "Error parsing get transaction receipt, buf: {:?}, err: {}",
                buf, err
            );

            return Err(err.into());
        }
    };

    return Ok(resp.result.contractAddress.map(|s| s.to_string()));
}

pub async fn get_balance<S: Into<String> + Serialize + Display>(
    client: &Client<HttpsConnector<HttpConnector>>,
    addr: &S,
) -> Result<String, QueryError> {
    let body = json!(
        {
            "jsonrpc":"2.0",
            "method": "eth_getBalance",
            "params":[addr, "latest"],
            "id":1,
        }
    )
    .to_string();

    let req = Request::builder()
        .method(Method::POST)
        .uri(GETH_ENDPOINT)
        .header("content-type", "application/json")
        .body(Body::from(body))?;

    let mut resp = client.request(req).await?;

    match resp.body_mut().data().await {
        Some(r) => {
            let body = r.unwrap();
            let get_balance_resp: GetBalanceResponse = serde_json::from_slice(&body)?;

            let wei = {
                let w = get_balance_resp.result.strip_prefix("0x").unwrap();
                u128::from_str_radix(w, 16)?
            };

            return Ok(wei.to_string());
        }
        None => {
            return Err(format!("invalid addr, {}", addr).into());
        }
    }
}
