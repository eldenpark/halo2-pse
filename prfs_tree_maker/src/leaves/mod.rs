mod genesis;
mod scan;

use crate::{hexutils::convert_string_into_fp, ledger_query, TreeMakerError};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::{client::fluent_builders, model::AttributeValue, Client as DynamoClient};
use ff::PrimeField;
use halo2_proofs::halo2curves::pasta::Fp;
use std::{collections::HashMap, sync::Arc};
use tokio_postgres::{types::ToSql, Client as PgClient, Error, NoTls};

pub async fn make_leaves() -> Result<(), TreeMakerError> {
    // genesis::run().await?;
    scan::run().await?;

    Ok(())
}

async fn put_in_rds(
    pg_client: Arc<PgClient>,
    items: Option<Vec<HashMap<std::string::String, AttributeValue>>>,
    total_count: u64,
) -> Result<(), TreeMakerError> {
    let items = items.unwrap();

    let mut v = vec![];
    for (idx, item) in items.into_iter().enumerate() {
        let pg_client = pg_client.clone();

        let task = tokio::spawn(async move {
            let addr = item.get("addr").expect("addr should be non null");
            let wei = item.get("wei").expect("wei should be non null");

            // println!("rds addr: {:?}, wei: {:?}", addr, wei);

            let pos = format!("0_{}", total_count + idx as u64);
            let table_id = "0".to_string();
            let addr = addr.as_s().expect("addr should be string");
            let wei: i64 = {
                let w = wei.as_n().expect("wei should be number");

                w.parse::<i64>().unwrap()
            };
            let val = {
                // 160 bit
                let v = addr.strip_prefix("0x").unwrap().to_string();
                let v = v + "000000000000000000000000";
                v
            };

            // println!("val: {:?}", val);

            match pg_client
                .execute(
                    "INSERT INTO nodes (pos, table_id, val, wei, addr) VALUES ($1, $2, $3, $4, $5)",
                    &[&pos, &table_id, &val, &wei, &addr],
                )
                .await
            {
                Ok(_) => (),
                Err(err) => {
                    println!("error putting in rds, addr: {}, err: {}", addr, err);
                }
            }
        });

        v.push(task);
    }

    let mut result = vec![];
    for f in v {
        result.push(f.await.unwrap());
    }

    Ok(())
}

fn get_range_scan_query(dynamo_client: &DynamoClient) -> fluent_builders::Scan {
    dynamo_client
        .scan()
        .table_name("balances-2")
        .filter_expression(":wei1 < wei AND wei <= :wei2")
        .expression_attribute_values(":wei1", AttributeValue::N("275000000000000000".to_string()))
        .expression_attribute_values(":wei2", AttributeValue::N("278000000000000000".to_string()))
        .limit(200)
}
