use crate::{dynamodb, TreeMakerError};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_rds::{Client, Error, Region, PKG_VERSION};

pub async fn make_tree() -> Result<(), TreeMakerError> {
    let region_provider = RegionProviderChain::default_provider();
    let config = aws_config::from_env().region(region_provider).load().await;
    let rds_client = Client::new(&config);

    // show_instances(&client).await;

    Ok(())
}
