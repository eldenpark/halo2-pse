use crate::TreeMakerError;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::{client::fluent_builders, model::AttributeValue, Client as DynamoClient};
use futures_util::pin_mut;
use std::{collections::HashMap, sync::Arc};
// use tokio_postgres::types::ToSql;
use futures_util::TryStreamExt;
use tokio_postgres::{Client as PgClient, Error, GenericClient, NoTls};

pub async fn grow_tree() -> Result<(), TreeMakerError> {
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

    const NO_PARAMS: &[i32; 0] = &[];
    let it = pg_client
        .query_raw("SELECT count(*) as count from nodes", NO_PARAMS)
        .await
        .unwrap();

    pin_mut!(it);

    let total_row_count = match it.try_next().await? {
        Some(row) => {
            let count: i64 = row.get(0);
            count
        }
        None => {
            return Err("Cannot retrieve row count".into());
        }
    };

    println!("total row count: {}", total_row_count);

    for height in 0..31 {
        println!("processing height {}", height);

        let mut curr = 0;

        let rows = pg_client
            .query(
                "SELECT pos, table_id, val FROM nodes WHERE pos in ($1, $2)",
                &[&"0_0", &"0_1"],
            )
            .await?;

        match rows.len() {
            0 => {}
            1 => {}
            2 => {
                let left = rows.get(0).expect("left node");
                let right = rows.get(1).expect("right node");

                let l_val: &str = left.get("val");
                let r_val: &str = right.get("val");
                println!("val: {:?}", l_val);
            }
            _ => {
                return Err("Error! row count is over 2".into());
            }
        };

        // let bb: &str = a.get(0).unwrap().get("table_id");
        // println!("bb: {}", bb);

        return Ok(());

        // while true {
        //     pg_client.query(
        //         "SELECT pos, table_id, val FROM nodes WHERE pos in ($1, $2)",
        //         &[],
        //     );

        //     curr += 2;
        // }
    }

    Ok(())
}
