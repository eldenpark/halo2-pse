mod genesis;
mod scan;

use crate::TreeMakerError;

pub async fn get_addresses() -> Result<(), TreeMakerError> {
    // genesis::run().await?;
    scan::run().await?;

    Ok(())
}
