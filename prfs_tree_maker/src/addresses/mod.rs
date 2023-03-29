mod genesis;
mod scan;

use crate::{db::Database, geth::GethClient, TreeMakerError};

pub async fn get_addresses(geth_client: GethClient, db: Database) -> Result<(), TreeMakerError> {
    // genesis::run().await?;
    scan::run(geth_client, db).await?;

    Ok(())
}
