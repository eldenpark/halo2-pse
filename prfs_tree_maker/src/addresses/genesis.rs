use crate::config::GETH_ENDPOINT;
use crate::db::Database;
use crate::geth::{GetBalanceRequest, GethClient};
use crate::{geth, TreeMakerError};
use hyper::client::HttpConnector;
use hyper::{body::HttpBody as _, Client as HyperClient, Uri};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use serde_json::{from_slice, json};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug)]
struct GenesisEntry {
    wei: String,
}

pub async fn run() -> Result<(), TreeMakerError> {
    let https = HttpsConnector::new();
    let hyper_client = HyperClient::builder().build::<_, hyper::Body>(https);

    let geth_client = GethClient { hyper_client };
    let db = Database::connect().await?;

    process_genesis_block_addresses(geth_client, db).await?;

    Ok(())
}

async fn process_genesis_block_addresses(
    geth_client: GethClient,
    db: Database,
) -> Result<(), TreeMakerError> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let genesis_block_path = project_root.join("data/genesis_block.json");

    println!("genesis_block_path: {:?}", genesis_block_path);

    let data = fs::read_to_string(&genesis_block_path)?;
    let genesis_block: HashMap<String, GenesisEntry> =
        serde_json::from_str(&data).expect("JSON does not have correct format.");

    let mut balances = BTreeMap::new();
    for (idx, (addr, _)) in genesis_block.iter().enumerate() {
        let addr = format!("0x{}", addr);

        let resp = geth_client
            .eth_getBalance(GetBalanceRequest(&addr, "latest"))
            .await?;

        if let Some(r) = resp.result {
            let wei_str = r.strip_prefix("0x").unwrap();
            let wei = u128::from_str_radix(wei_str, 16).unwrap();

            balances.insert(addr, wei);

            if idx % 200 == 0 {
                let rows_updated = db.insert_balances(balances, false).await?;
                println!("idx: {}, rows_updated: {}", idx, rows_updated);

                balances = BTreeMap::new();
            }
        }
    }

    Ok(())
}
