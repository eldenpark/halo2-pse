mod genesis;
mod scan;

use crate::TreeMakerError;

pub async fn make_leaves() -> Result<(), TreeMakerError> {
    // genesis::run().await?;
    scan::run().await?;

    Ok(())
}
