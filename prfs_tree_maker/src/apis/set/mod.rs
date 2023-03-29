use crate::{db::Database, TreeMakerError};

pub struct SetType {
    pub table_label: String,
    pub query: String,
}

lazy_static::lazy_static! {
    static ref WEI_200: SetType = SetType {
        table_label: "balances_20230327".to_string(),
        query: "wei >= 277229987272358786 and wei < 277329987272358786".to_string(),
    };
}

pub async fn run(db: Database) -> Result<(), TreeMakerError> {
    make_set(db, &*WEI_200).await?;

    Ok(())
}

pub async fn make_set(db: Database, set_type: &SetType) -> Result<(), TreeMakerError> {
    let accounts = db.get_accounts(&set_type.query).await?;
    for acc in accounts {
        println!("acc: {:?}", acc);
    }

    Ok(())
}
