mod genesis;
mod scan;

use crate::{db::Database, geth::GethClient, TreeMakerError};

pub async fn get_accounts(geth_client: GethClient, db: Database) -> Result<(), TreeMakerError> {
    // genesis::run(geth_client, db).await?;
    scan::run(geth_client, db).await?;

    Ok(())
}
