use crate::config::GETH_ENDPOINT;
use crate::TreeMakerError;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::model::AttributeValue;
use hyper::client::HttpConnector;
use hyper::{body::HttpBody as _, Client as HyperClient, Uri};
use hyper::{Body, Method, Request, Response};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, json};
use std::collections::HashMap;
use std::fmt::Display;
use std::fs::{self, File};
use std::path::PathBuf;

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
