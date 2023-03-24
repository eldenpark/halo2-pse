use super::{geth, QueryError};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::model::AttributeValue;
use aws_sdk_dynamodb::Client as DynamoClient;
use hyper::{body::HttpBody as _, Client, Uri};
use hyper::{Body, Method, Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, json};
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::PathBuf;

pub async fn put_item(client: &DynamoClient, addr: String, wei: String) {
    // println!("putting item, addr: {}, wei: {}", addr, wei);

    let addr_attr = AttributeValue::S(addr.to_string());
    let wei_attr = AttributeValue::S(wei.to_string());

    let request = client
        .put_item()
        .table_name("balances-1")
        .condition_expression("attribute_not_exists(addr)")
        .item("addr", addr_attr)
        .item("wei", wei_attr);

    match request.send().await {
        Ok(_) => {}
        Err(err) => {
            // println!(
            //     "put item failed!, err: {}, addr: {}, wei: {}",
            //     err, addr, wei
            // );

            // log::error!(
            //     "put item failed!, err: {}, addr: {}, wei: {}",
            //     err,
            //     addr,
            //     wei
            // );
        }
    }
}
