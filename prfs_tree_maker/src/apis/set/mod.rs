mod grow;

use crate::{
    db::{Account, Database, Node},
    TreeMakerError,
};
use rust_decimal::Decimal;

use self::grow::grow_tree;

pub struct SetType {
    pub table_label: String,
    pub query: String,
}

lazy_static::lazy_static! {
    static ref WEI_200: SetType = SetType {
        table_label: "balances_20230327".to_string(),
        query: "wei >= 277200000000000000 and wei < 277300000000000000".to_string(),
    };
}

pub async fn run(db: Database) -> Result<(), TreeMakerError> {
    make_set(db, &*WEI_200).await?;

    Ok(())
}

pub async fn make_set(db: Database, set_type: &SetType) -> Result<(), TreeMakerError> {
    // let account_rows = db.get_accounts(&set_type.query).await?;

    // let nodes: Vec<Node> = account_rows
    //     .iter()
    //     .enumerate()
    //     .map(|(idx, r)| {
    //         let addr: String = r.try_get("addr").expect("addr should be present");
    //         let pos = format!("{}_0", idx);

    //         Node {
    //             pos,
    //             val: addr,
    //             set_id: "1".to_string(),
    //         }
    //     })
    //     .collect();

    // let rows_affected = db.insert_nodes("1".to_string(), nodes, true).await?;
    // println!("rows affected: {}", rows_affected);
    //
    grow_tree().await?;

    Ok(())
}
