use crate::TreeMakerError;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_dynamodb::{model::AttributeValue, Client as DynamoClient};

pub async fn retrieve_addresses_in_range() -> Result<(), TreeMakerError> {
    let region_provider = RegionProviderChain::default_provider();
    let config = aws_config::from_env().region(region_provider).load().await;
    let dynamo_client = DynamoClient::new(&config);

    let results = dynamo_client
        .scan()
        .table_name("balances-2")
        .filter_expression(":wei1 < wei AND wei < :wei2")
        .expression_attribute_values(":wei1", AttributeValue::N("0".to_string()))
        .expression_attribute_values(":wei2", AttributeValue::N("500000000000000000".to_string()))
        .limit(50)
        .send()
        .await?;

    println!("result: {:?}", results.items());

    let last_key = results.last_evaluated_key().unwrap();
    println!("last key: {:?}", last_key);
    let last_addr = last_key.get("addr");
    let last_wei = last_key.get("wei");

    match (last_addr, last_wei) {
        (Some(addr), Some(wei)) => {
            // println!(", {:?}", lk);

            let results = dynamo_client
                .scan()
                .table_name("balances-2")
                .exclusive_start_key("addr", addr.clone())
                .exclusive_start_key("wei", wei.clone())
                .filter_expression(":wei1 < wei AND wei < :wei2")
                .expression_attribute_values(":wei1", AttributeValue::N("0".to_string()))
                .expression_attribute_values(
                    ":wei2",
                    AttributeValue::N("500000000000000000".to_string()),
                )
                .limit(50)
                .send()
                .await?;

            println!("result222: {:?}", results.items());
        }
        _ => {
            println!("nothing found!!!");
        }
    };

    // last_key.unwrap
    // println!("111, {:?}", last_key);

    // for item in results.items() {
    //     println!("item: {:?}", item);
    // }

    // let results = dynamo_client
    //     .scan()
    //     .table_name("balances-2")
    //     .exclusive_start_key(k, v)
    //     .filter_expression("wei > :wei")
    //     .expression_attribute_values(":wei", AttributeValue::N("0".to_string()))
    //     .limit(50)
    //     .send()
    //     .await?;

    Ok(())
}
