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

    while let Some(row) = it.try_next().await? {
        println!("222");
        let foo: i64 = row.get(0);

        println!("foo: {}", foo);
    }

    // let count: &str = leaves_count.Box::pin(0);

    // println!("leaves_count: {:?}", count);

    // for height in 0..32 {
    //     let mut curr = 0;
    //     while true {
    //         pg_client.query(
    //             "SELECT pos, table_id, val FROM nodes WHERE pos in ($1, $2)",
    //             &[],
    //         );

    //         curr += 2;
    //     }
    // }
    Ok(())
}
