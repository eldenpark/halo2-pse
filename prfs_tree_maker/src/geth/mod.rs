mod apis;
mod geth_types;
mod io_models;

use crate::config::GETH_ENDPOINT;
use crate::TreeMakerError;
pub use apis::*;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::model::AttributeValue;
pub use geth_types::*;
use hyper::client::HttpConnector;
use hyper::{body::HttpBody as _, Client as HyperClient, Uri};
use hyper::{Body, Method, Request, Response};
use hyper_tls::HttpsConnector;
pub use io_models::*;
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, json};
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::{self, File};
use std::path::PathBuf;

// #[derive(Serialize, Deserialize, Debug)]
// pub struct GetTransactionReceiptResponse<'a> {
//     pub jsonrpc: &'a str,
//     pub id: usize,
//     pub result: TransactionReceipt<'a>,
// }

// pub async fn get_contract_addr<S: Into<String> + Serialize + Display>(
//     tx_hash: S,
// ) -> Result<Option<String>, TreeMakerError> {
//     let body = json!(
//         {
//             "jsonrpc":"2.0",
//             "method": "eth_getTransactionReceipt",
//             "params":[tx_hash],
//             "id":1,
//         }
//     )
//     .to_string();

//     let req = Request::builder()
//         .method(Method::POST)
//         .uri(GETH_ENDPOINT)
//         .header("content-type", "application/json")
//         .body(Body::from(body))?;

//     let https = HttpsConnector::new();
//     let client = HyperClient::builder().build::<_, hyper::Body>(https);

//     let resp = client.request(req).await?;

//     let buf = hyper::body::to_bytes(resp).await?;

//     let resp: GetTransactionReceiptResponse = match serde_json::from_slice(&buf) {
//         Ok(r) => {
//             r
//             // / return Ok(r.result.contractAddress.map(|s| s.to_string()));
//         }
//         Err(err) => {
//             println!(
//                 "Error parsing get transaction receipt, buf: {:?}, err: {}",
//                 buf, err
//             );

//             return Err(err.into());
//         }
//     };

//     return Ok(resp.result.contractAddress.map(|s| s.to_string()));
// }

// pub async fn get_balance<S: Into<String> + Serialize + Display>(
//     client: &HyperClient<HttpsConnector<HttpConnector>>,
//     addr: &S,
// ) -> Result<String, TreeMakerError> {
//     let body = json!(
//         {
//             "jsonrpc":"2.0",
//             "method": "eth_getBalance",
//             "params":[addr, "latest"],
//             "id":1,
//         }
//     )
//     .to_string();

//     let req = Request::builder()
//         .method(Method::POST)
//         .uri(GETH_ENDPOINT)
//         .header("content-type", "application/json")
//         .body(Body::from(body))?;

//     let mut resp = client.request(req).await?;

//     match resp.body_mut().data().await {
//         Some(r) => {
//             let body = r.unwrap();
//             let get_balance_resp: GetBalanceResponse = match serde_json::from_slice(&body) {
//                 Ok(r) => r,
//                 Err(err) => {
//                     println!(
//                         "Error deserializing get balance response, original body: {:?}, err: {}",
//                         body, err,
//                     );

//                     return Err(err.into());
//                 }
//             };

//             let wei = {
//                 let w = get_balance_resp.result.strip_prefix("0x").unwrap();
//                 u128::from_str_radix(w, 16)?
//             };

//             return Ok(wei.to_string());
//         }
//         None => {
//             return Err(format!("invalid addr, {}", addr).into());
//         }
//     }
// }
