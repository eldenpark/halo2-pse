use std::collections::HashMap;

use crate::TreeMakerError;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::{client::fluent_builders, model::AttributeValue, Client as DynamoClient};
use aws_sdk_rds::{Client as RDSClient, Error, Region, PKG_VERSION};

pub async fn make_tree() -> Result<(), TreeMakerError> {
    let region_provider = RegionProviderChain::default_provider();
    let config = aws_config::from_env().region(region_provider).load().await;
    let dynamo_client = DynamoClient::new(&config);
    let rds_client = RDSClient::new(&config);

    let results = get_range_scan_query(&dynamo_client).send().await?;

    println!("result: {:?}", results.count());

    let mut is_remaining = true;
    let mut last_key = results.last_evaluated_key().unwrap().clone();

    while is_remaining {
        println!("last key: {:?}", last_key);

        let last_addr = last_key.get("addr");
        let last_wei = last_key.get("wei");

        match (last_addr, last_wei) {
            (Some(addr), Some(wei)) => {
                let results = get_range_scan_query(&dynamo_client)
                    .exclusive_start_key("addr", addr.clone())
                    .exclusive_start_key("wei", wei.clone())
                    .send()
                    .await?;

                println!("result: {:?}", results.count());

                last_key = results.last_evaluated_key().unwrap().clone();

                if results.count() > 0 {
                    put_in_rds(&rds_client, results.items).await?;
                }
            }
            _ => {
                println!("nothing found!!!");

                is_remaining = false;
            }
        };
    }

    Ok(())
}

async fn put_in_rds(
    rds_client: &RDSClient,
    items: Option<Vec<HashMap<std::string::String, AttributeValue>>>,
) -> Result<(), TreeMakerError> {
    let items = items.unwrap();

    for item in items {
        let addr = item.get("item").unwrap();
        let wei = item.get("wei").unwrap();
    }

    Ok(())
}

fn get_range_scan_query(dynamo_client: &DynamoClient) -> fluent_builders::Scan {
    dynamo_client
        .scan()
        .table_name("balances-2")
        .filter_expression(":wei1 < wei AND wei < :wei2")
        .expression_attribute_values(":wei1", AttributeValue::N("400000000000000000".to_string()))
        .expression_attribute_values(":wei2", AttributeValue::N("500000000000000000".to_string()))
        .limit(200)
}
