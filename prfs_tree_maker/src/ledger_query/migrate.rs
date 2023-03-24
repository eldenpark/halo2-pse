use super::config::{END_BLOCK, GETH_ENDPOINT, START_BLOCK};
use super::geth::GetBlockResponse;
use super::{dynamodb, geth, QueryError};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::model::put_request::{self, Builder};
use aws_sdk_dynamodb::model::{write_request, AttributeValue, PutRequest, WriteRequest};
use aws_sdk_dynamodb::Client as DynamoClient;
use flate2::read::GzDecoder;
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
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokio_stream::StreamExt;

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct Addr<'a> {
    S: &'a str,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct Wei<'a> {
    S: &'a str,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct Item<'a> {
    #[serde(borrow)]
    addr: Addr<'a>,
    wei: Wei<'a>,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct Line<'a> {
    #[serde(borrow)]
    Item: Item<'a>,
}

pub async fn run(log_files_path: PathBuf) -> Result<(), QueryError> {
    println!("migrate run");

    migrate_table(log_files_path).await?;

    Ok(())
}

async fn migrate_table(log_files_path: PathBuf) -> Result<(), QueryError> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let table_path = project_root.join("data/balances-1.json.gz");
    let file = File::open(table_path)?;

    let d = GzDecoder::new(file);

    let region_provider = RegionProviderChain::default_provider();
    let config = aws_config::from_env().region(region_provider).load().await;
    let dynamo_client = DynamoClient::new(&config);

    let mut count = 1;
    let mut write_requests = vec![];

    for line in BufReader::new(d).lines() {
        if count < 9000 {
            count += 1;
            continue;
        }

        let line = line.unwrap();
        // println!("{}", line);

        let line: Line = serde_json::from_str(&line).unwrap();

        let addr_attr = AttributeValue::S(line.Item.addr.S.to_string());
        let wei_attr = AttributeValue::N(line.Item.wei.S.to_string());

        let put_req = PutRequest::builder()
            .item("addr", addr_attr)
            .item("wei", wei_attr)
            .build();

        let write_req = WriteRequest::builder().put_request(put_req).build();
        write_requests.push(write_req);

        if count % 25 == 0 {
            println!("count: {}", count);

            wrap(&dynamo_client, write_requests).await;
            write_requests = vec![];
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        count += 1;
    }

    Ok(())
}

async fn wrap(dynamo_client: &DynamoClient, write_requests: Vec<WriteRequest>) {
    match dynamo_client
        .batch_write_item()
        .request_items("balances-2", write_requests)
        .send()
        .await
    {
        Ok(_) => (),
        Err(err) => {
            println!("Err: {:?}", err.into_source());
        }
    }
}
