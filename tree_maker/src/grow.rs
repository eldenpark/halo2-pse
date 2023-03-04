use crate::{
    hexutils::{convert_addr_to_hex, convert_fp_to_string, convert_string_into_fp},
    TreeMakerError,
};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::{client::fluent_builders, model::AttributeValue, Client as DynamoClient};
use ff::PrimeField;
use futures_util::pin_mut;
use halo2_proofs::halo2curves::{pasta::Fp, serde::SerdeObject};
use std::{collections::HashMap, sync::Arc};
// use tokio_postgres::types::ToSql;
use futures_util::TryStreamExt;
use halo2_gadgets::{
    poseidon::{
        // merkle::merkle_path::MerklePath,
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    },
    utilities::UtilitiesInstructions,
};
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

        let mut idx = 0;
        let mut should_loop = true;
        while should_loop {
            let l_pos = format!("{}_{}", height, idx);
            let r_pos = format!("{}_{}", height, idx + 1);

            let l_node = match pg_client
                .query_one(
                    "SELECT pos, table_id, val FROM nodes WHERE pos=$1",
                    &[&l_pos],
                )
                .await
            {
                Ok(r) => {
                    let val: &str = r.get("val");
                    let node = convert_string_into_fp(val);
                    node
                }
                Err(err) => {
                    println!(
                        "error fetching the rows, we might be done for this height, pos: {}",
                        l_pos,
                    );
                    break;
                    // panic!();
                }
            };

            let r_node = match pg_client
                .query_one(
                    "SELECT pos, table_id, val FROM nodes WHERE pos=$1",
                    &[&r_pos],
                )
                .await
            {
                Ok(r) => {
                    let val: &str = r.get("val");
                    let node = convert_string_into_fp(val);
                    node
                }
                Err(err) => {
                    should_loop = false;
                    Fp::zero()
                }
            };

            let parent_node =
                poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init()
                    .hash([l_node, r_node]);

            let parent_node_val = convert_fp_to_string(parent_node);

            let parent_pos = format!("{}_{}", height + 1, idx / 2);

            println!(
                "parent node (fp): {:?}, parent_pos: {}",
                parent_node, parent_pos
            );

            match pg_client
                .execute(
                    "INSERT INTO nodes (pos, table_id, val) VALUES ($1, $2, $3)",
                    &[&parent_pos, &"0", &parent_node_val],
                )
                .await
            {
                Ok(_) => (),
                Err(err) => {
                    println!("error executing stmt, {}", err);
                }
            };

            idx += 2;
        }

        println!("done!!!");

        // return Ok(());
    }

    Ok(())
}
