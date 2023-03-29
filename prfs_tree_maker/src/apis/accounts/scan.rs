use crate::db::{Account, Database};
use crate::geth::{
    GetBalanceRequest, GetBlockByNumberRequest, GetBlockResponse, GetTransactionReceiptRequest,
    GethClient,
};
use crate::TreeMakerError;
use rust_decimal::Decimal;
use std::collections::BTreeMap;

pub async fn run(geth_client: GethClient, db: Database) -> Result<(), TreeMakerError> {
    scan_ledger_accounts(geth_client, db).await?;

    Ok(())
}

async fn scan_ledger_accounts(geth_client: GethClient, db: Database) -> Result<(), TreeMakerError> {
    let (start_block, end_block) = {
        let sb: u64 = std::env::var("START_BLOCK")
            .expect("env var START_BLOCK missing")
            .parse()
            .unwrap();
        let eb: u64 = std::env::var("END_BLOCK")
            .expect("env var END_BLOCK missing")
            .parse()
            .unwrap();

        (sb, eb)
    };

    let mut balances = BTreeMap::<String, Account>::new();

    for no in start_block..end_block {
        let b_no = format!("0x{:x}", no);

        tracing::info!(
            "processing block: {} ({}), #balance in bucket: {}",
            b_no,
            no,
            balances.len()
        );

        let resp = geth_client
            .eth_getBlockByNumber(GetBlockByNumberRequest(&b_no, true))
            .await?;

        let result = if let Some(r) = resp.result {
            r
        } else {
            let msg = format!("Get block response failed, block_no: {}", no);
            tracing::error!("{}", msg);

            return Err(msg.into());
        };

        // miner
        get_balance_and_add_item(&geth_client, &mut balances, result.miner.to_string()).await?;

        for tx in result.transactions {
            // from
            get_balance_and_add_item(&geth_client, &mut balances, tx.from.to_string()).await?;

            match tx.to {
                Some(to) => {
                    // to
                    get_balance_and_add_item(&geth_client, &mut balances, to.to_string()).await?;
                }
                None => {
                    let resp = &geth_client
                        .eth_getTransactionReceipt(GetTransactionReceiptRequest(&tx.hash))
                        .await?;

                    // println!("get transaction receipt resp: {:?}", resp);

                    if let Some(r) = &resp.result {
                        if let Some(contract_addr) = &r.contractAddress {
                            // contract
                            get_balance_and_add_item(
                                &geth_client,
                                &mut balances,
                                contract_addr.to_string(),
                            )
                            .await?;
                        }
                    }
                }
            };
        }

        let balances_count = balances.len();
        if balances.len() >= 500 {
            match db.insert_balances(balances, false).await {
                Ok(r) => {
                    tracing::info!(
                        "Writing balances, balances_count: {}, block_no: {}, rows_affected: {}",
                        balances_count,
                        no,
                        r
                    );
                }
                Err(err) => {
                    tracing::info!("Balance insertion failed, err: {}, block_no: {}", err, no);
                }
            }

            balances = BTreeMap::new();
        }
    }

    if balances.len() > 0 {
        tracing::info!(
            "Writing (last) remaining balances, balances_count: {}, end block_no (excl): {}",
            balances.len(),
            end_block
        );

        db.insert_balances(balances, false).await?;
    } else {
        tracing::info!(
            "Balances are empty. Closing 'scan', balances_count: {}, end block_no (excl): {}",
            balances.len(),
            end_block
        );
    }

    Ok(())
}

async fn get_balance_and_add_item(
    geth_client: &GethClient,
    addresses: &mut BTreeMap<String, Account>,
    addr: String,
) -> Result<(), TreeMakerError> {
    if addresses.contains_key(&addr) {
        // println!("skip, {}", addr);
        return Ok(());
    } else {
        let resp = match geth_client
            .eth_getBalance(GetBalanceRequest(&addr, "latest"))
            .await
        {
            Ok(r) => r,
            Err(err) => {
                let msg = format!("Geth get balance failed, err: {}, addr: {}", err, addr);
                tracing::error!("{}", msg);

                return Err(msg.into());
            }
        };

        if let Some(r) = resp.result {
            let wei = {
                let wei_str = r
                    .strip_prefix("0x")
                    .expect("wei str should contain 0x")
                    .to_string();

                match Decimal::from_str_radix(&wei_str, 16) {
                    Ok(u) => u,
                    Err(err) => {
                        let msg = format!(
                            "u128 conversion failed, err: {}, wei_str: {}, addr: {}",
                            err, wei_str, addr
                        );

                        tracing::error!("{}", msg);

                        return Err(msg.into());
                    }
                }
            };

            let acc = Account {
                addr: addr.to_string(),
                wei,
            };

            addresses.insert(addr, acc);
        }
    }

    Ok(())
}
