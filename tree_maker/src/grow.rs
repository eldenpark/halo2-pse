use crate::{
    hexutils::{convert_addr_to_hex, convert_fp_to_string},
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

    let mut curr_cardinality = total_row_count;

    for height in 0..31 {
        println!(
            "processing height {}, cardinality: {}",
            height, curr_cardinality
        );

        // let mut tasks = vec![];

        for idx in (0..=curr_cardinality - 1).step_by(2) {
            println!("idx: {}", idx);
            let pg_client = pg_client.clone();

            // let task = tokio::spawn(async move {
            let l_pos = format!("{}_{}", height, idx);
            let r_pos = format!("{}_{}", height, idx + 1);

            let rows = match pg_client
                .query(
                    "SELECT pos, table_id, val FROM nodes WHERE pos in ($1, $2)",
                    &[&l_pos, &r_pos],
                )
                .await
            {
                Ok(r) => r,
                Err(err) => {
                    println!(
                        "error fetching the rows, l_pos: {}, r_pos: {}, err: {}",
                        l_pos, r_pos, err,
                    );
                    panic!();
                }
            };

            let parent_pos = format!("{}_{}", height + 1, idx / 2);

            match rows.len() {
                0 => {
                    // we are done looping
                }
                1 => {
                    let left = rows.get(0).expect("left node (last node)");
                    let l_val: &str = left.get("val");

                    let l_node = if l_val.len() == 20 {
                        convert_addr_to_hex(&l_val[2..]).unwrap()
                    } else {
                        let a: [u8; 32] = l_val.as_bytes().try_into().unwrap();
                        Fp::from_repr(a).unwrap()
                    };

                    let r_node = Fp::from(0);

                    let hash =
                        poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init()
                            .hash([l_node, r_node]);

                    let val = convert_fp_to_string(hash);

                    pg_client
                        .execute(
                            "INSERT INTO nodes (pos, table_id, val) VALUES ($1, $2, $3)",
                            &[&parent_pos, &"0", &val],
                        )
                        .await;

                    println!("val: {:?}, parent_pos: {}", val, parent_pos);
                }
                2 => {
                    let left = rows.get(0).expect("left node");
                    let right = rows.get(1).expect("right node");

                    let l_val: &str = left.get("val");
                    let r_val: &str = right.get("val");

                    // println!("f, l_val: {}, r_val: {}", l_val, r_val);

                    let l_node = if l_val.len() == 42 {
                        convert_addr_to_hex(&l_val[2..]).unwrap()
                    } else {
                        println!("l_val: {}, {}", l_val, l_val.len());
                        let mut a = hex::decode(l_val).unwrap();
                        println!("aa: {:?}, {}", a, a.len());
                        a.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
                        // let a: Vec<u8> = l_val.as_bytes().try_into().unwrap();
                        // let b = a.as_slice();
                        let c: &[u64] = bytemuck::try_cast_slice(&a).unwrap();
                        println!("c: {:?}, c len: {}", c, c.len());
                        let c: [u64; 4] = c.try_into().unwrap();

                        // byteorder::LittleEndian
                        // println!("a: {:?}, {}", a, a.len());
                        let b = Fp::from_raw(c);
                        println!("b: {:?}", b);
                        Fp::from(11)
                    };
                    // 31edc964ea080e4e8381ae22d01366e72028b8cb

                    let r_node = if r_val.len() == 42 {
                        convert_addr_to_hex(&r_val[2..]).unwrap()
                    } else {
                        let a: [u8; 32] = r_val.as_bytes().try_into().unwrap();
                        Fp::from_repr(a).unwrap()
                    };

                    let hash =
                        poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init()
                            .hash([l_node, r_node]);

                    let val = convert_fp_to_string(hash);

                    pg_client
                        .execute(
                            "INSERT INTO nodes (pos, table_id, val) VALUES ($1, $2, $3)",
                            &[&parent_pos, &"0", &val],
                        )
                        .await;

                    println!("val: {:?}, parent_pos: {}", val, parent_pos);
                }
                _ => {
                    panic!("Error! row count is over 2");
                }
            }

            // Ok::<_, TreeMakerError>(())
            // });

            // tasks.push(task);
        }

        // let mut result = vec![];
        // for t in tasks {
        //     result.push(t.await.unwrap());
        // }

        println!("done!!!");

        curr_cardinality = if curr_cardinality % 2 == 1 {
            (curr_cardinality + 1) / 2
        } else {
            curr_cardinality / 2
        };

        return Ok(());
    }

    Ok(())
}
