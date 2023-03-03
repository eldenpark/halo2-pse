use crate::TreeMakerError;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::{client::fluent_builders, model::AttributeValue, Client as DynamoClient};
use ff::PrimeField;
use halo2_proofs::halo2curves::pasta::Fp;
use std::{collections::HashMap, sync::Arc};
use tokio_postgres::{types::ToSql, Client as PgClient, Error, NoTls};

pub async fn make_leaves() -> Result<(), TreeMakerError> {
    let region_provider = RegionProviderChain::default_provider();
    let config = aws_config::from_env().region(region_provider).load().await;
    let dynamo_client = DynamoClient::new(&config);

    let (pg_client, connection) = tokio_postgres::connect(
        "host=database-1.cstgyxdzqynn.ap-northeast-2.rds.amazonaws.com user=postgres password=postgres",
        NoTls,
    )
    .await?;

    let pg_client = Arc::new(pg_client);

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            println!("connection error: {}", e);
        }
    });

    let results = get_range_scan_query(&dynamo_client).send().await?;

    let mut is_remaining = true;
    let mut last_key = results.last_evaluated_key().unwrap().clone();
    let mut total_count: u64 = 0;
    let mut attempt = 1;

    while is_remaining {
        println!(
            "last key: {:?}, total_count: {}, attempt: {}",
            last_key, total_count, attempt
        );

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

                last_key = match results.last_evaluated_key() {
                    Some(lk) => lk.clone(),
                    None => {
                        println!("last evaluated key is missing. We've probably reached the end");
                        break;
                    }
                };

                let result_count = results.count();

                if result_count > 0 {
                    put_in_rds(pg_client.clone(), results.items, total_count).await?;
                    total_count += result_count as u64;
                }
            }
            _ => {
                println!("nothing found!!!");

                is_remaining = false;
            }
        };

        attempt += 1;
    }

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

            // Fp::from_repr()

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
        .expression_attribute_values(":wei1", AttributeValue::N("260000000000000000".to_string()))
        .expression_attribute_values(":wei2", AttributeValue::N("280000000000000000".to_string()))
        .limit(200)
}
