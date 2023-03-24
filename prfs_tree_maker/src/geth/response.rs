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

use super::models::Block;

#[derive(Serialize, Deserialize, Debug)]
pub struct GetBalanceResponse {
    pub jsonrpc: String,
    pub id: usize,
    pub result: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetBlockResponse<'a> {
    pub jsonrpc: &'a str,
    pub id: usize,
    pub result: Block<'a>,
}
