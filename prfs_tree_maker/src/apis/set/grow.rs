use crate::{
    hexutils::{convert_fp_to_string, convert_string_into_fp},
    TreeMakerError,
};
use ff::PrimeField;
use halo2_proofs::halo2curves::{pasta::Fp as PastaFp, serde::SerdeObject};
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
    println!("grow tree()");
    let addrs = [
        "0x33d10ab178924ecb7ad52f4c0c8062c3066607ec",
        "0xf3e28453c74609cd275de994bc5bbae3ccbcfa56",
        "0x8be09401bfc531f5442e81cc13ead61b83ee20f8",
        "0x402b7d5aa4ecc29c55baae44493d0f1e74eaea2c",
        "0xed45c44e9a6ee4bc86c1b58c3e777528edb74e3b",
        "0xb0768fd406350becf576f8b8ec06e51a4dfb22ef",
        "0x4b6c8ce2f1c4f0b0b3a7eca2843991b6c2d6b313",
        "0x30532d90d19d2b01dfeb9bb5e9a0f9608ecde1c6",
        "0xe8651db4ecfc78cffc43e2baa69f64f67cd894f3",
        "0x267e3b6b33665f21962ed4077962826b618e7377",
        "0xa480bb750ba4c90d45a64918fbe48fd73d816d7c",
        "0x59b0d76d95e037587bfa7eb8f06969968028d753",
        "0xf2dcb1e6aefa3c2e3bee92d153d53fafe7c8392f",
        "0x1e8256c1709cecd969708bb22b7318e55636e5b0",
        "0x43989edc84067a5738c9fc0096e31262aa7b2c4f",
        "0xd3ac7cf14f3ec2729ff6d8eba6b9b59533ca29f7",
        "0xc7846db42a04093df40c64eded2360454ac2e75b",
        "0xae7dc1be1bad41326a31bc92debc7b528e834efa",
        "0x7649c1f1d7117547d3162386a3d730f926689961",
        "0x207d8d3f74da805f5fba61dedd3ff0de09c49f4e",
        "0xc51f4126ccf4e83b199589b6f15989f285f47221",
        "0x6d9937705db03597ddae5ee1936e1e30b0f5c438",
        "0xd5e634d714e2f6795f43d367b5d78a550241b472",
        "0x133f40bbef1ac0c66683cb06ba88bff57e3b50a7",
        "0xaa846f4f64e60cefc02ee3b735ea957c590ce114",
        "0x9d1a13ec01f5b645b4617092016609f7431c22c9",
        "0x834ab3cbbf57f81a835fe43df06ff83503bebe87",
        "0x969b962abbb46cd2cf5b426de3dcaf25d9ab58eb",
        "0x06347e297f223ce76022fcba3959ad43f9cd3050",
        "0x63c3b6aa59f18e0554a93903680a5869818065dc",
        "0x5d198f19860e20c94db0674c9d4ba2ea3bb31f70",
        "0x97500419ac2d6c3fa70f0f4b86235e2559208e4b",
        "0xe55c91e0e585fa9339a363a6c94403f5295b6434",
        "0x85e82a4568d8565eff1159ce53c8a1da990b9523",
        "0xc8bb018fa4de396565482eca52df72bdc5227ced",
        "0x6e0623012129282514aabc7030fcd40cdccdd0b7",
        "0xf8826c92b709bbb9739bc07523152a9dc9ac61d6",
        "0x791e7de2a858a789b4c5ef4b659cc4192c03f968",
        "0xd16639f413a16edd7067cf6d253c788a18a18804",
        "0x31abe0a54ed6bea12fd21961051e40d049dcbb67",
        "0xeb2a9f97dc01ed5574bd6cb9a1121d5bd8a596ed",
        "0xe8abdc7454cb38b3b951cc2bc1815d481b5b7300",
        "0x8cff411ab75fb45c29dea29643b1c5f95aecd1df",
        "0x50f8c08b0124092e1001b355f4b8ae2df85f715c",
        "0xf4b9c8d5c37374b0eafbcb0b09abb717612f372f",
    ];

    for addr in addrs {
        let mut addr_vec = hex::decode(&addr[2..]).unwrap();
        // addr_vec.reverse();
        // let addr_v: [u8; 20] = addr_vec.try_into().unwrap();
        let mut addr_v = [0; 32];
        addr_v[12..].clone_from_slice(&addr_vec);

        println!("addr_v: {:?}", addr_v);

        addr_v.reverse();
        let fp = PastaFp::from_repr(addr_v).unwrap();

        println!("fp: {:?}", fp);
    }

    // let (pg_client, connection) = tokio_postgres::connect(
    //     "host=database-1.cstgyxdzqynn.ap-northeast-2.rds.amazonaws.com user=postgres password=postgres",
    //     NoTls,
    // )
    // .await?;

    // let pg_client = Arc::new(pg_client);
    // tokio::spawn(async move {
    //     if let Err(e) = connection.await {
    //         println!("connection error: {}", e);
    //     }
    // });

    // const NO_PARAMS: &[i32; 0] = &[];
    // let it = pg_client
    //     .query_raw("SELECT count(*) as count from nodes", NO_PARAMS)
    //     .await
    //     .unwrap();

    // pin_mut!(it);

    // let total_row_count = match it.try_next().await? {
    //     Some(row) => {
    //         let count: i64 = row.get(0);
    //         count
    //     }
    //     None => {
    //         return Err("Cannot retrieve row count".into());
    //     }
    // };

    // println!("total row count: {}", total_row_count);

    // for height in 0..31 {
    //     println!("processing height {}", height);

    //     let mut idx = 0;
    //     let mut should_loop = true;
    //     while should_loop {
    //         let l_pos = format!("{}_{}", height, idx);
    //         let r_pos = format!("{}_{}", height, idx + 1);

    //         let l_node = match pg_client
    //             .query_one(
    //                 "SELECT pos, table_id, val FROM nodes WHERE pos=$1",
    //                 &[&l_pos],
    //             )
    //             .await
    //         {
    //             Ok(r) => {
    //                 let val: &str = r.get("val");
    //                 let node = convert_string_into_fp(val);
    //                 node
    //             }
    //             Err(err) => {
    //                 println!(
    //                     "error fetching the rows, we might be done for this height, pos: {}",
    //                     l_pos,
    //                 );
    //                 break;
    //                 // panic!();
    //             }
    //         };

    //         let r_node = match pg_client
    //             .query_one(
    //                 "SELECT pos, table_id, val FROM nodes WHERE pos=$1",
    //                 &[&r_pos],
    //             )
    //             .await
    //         {
    //             Ok(r) => {
    //                 let val: &str = r.get("val");
    //                 let node = convert_string_into_fp(val);
    //                 node
    //             }
    //             Err(err) => {
    //                 should_loop = false;
    //                 Fp::zero()
    //             }
    //         };

    //         let parent_node =
    //             poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init()
    //                 .hash([l_node, r_node]);

    //         let parent_node_val = convert_fp_to_string(parent_node);

    //         let parent_pos = format!("{}_{}", height + 1, idx / 2);

    //         println!(
    //             "parent node (fp): {:?}, parent_pos: {}",
    //             parent_node, parent_pos
    //         );

    //         match pg_client
    //             .execute(
    //                 "INSERT INTO nodes (pos, table_id, val) VALUES ($1, $2, $3)",
    //                 &[&parent_pos, &"0", &parent_node_val],
    //             )
    //             .await
    //         {
    //             Ok(_) => (),
    //             Err(err) => {
    //                 println!("error executing stmt, {}", err);
    //             }
    //         };

    //         idx += 2;
    //     }

    //     println!("done!!!");

    //     // return Ok(());
    // }

    Ok(())
}
