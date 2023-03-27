use super::geth_types::Block;
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

#[derive(Serialize, Deserialize, Debug)]
pub struct GetBlockByNumberRequest<'a>(
    // block_no
    pub &'a str,
    pub bool,
);

#[derive(Serialize, Deserialize, Debug)]
pub struct GetBalanceRequest<'a>(
    // addr
    pub &'a str,
    pub &'a str,
);

#[derive(Serialize, Deserialize, Debug)]
pub struct GetBalanceResponse {
    pub jsonrpc: String,
    pub id: usize,
    pub result: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetBlockResponse {
    pub jsonrpc: String,
    pub id: usize,
    pub result: Option<Block>,
}
