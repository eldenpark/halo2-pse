use crate::TreeMakerError;
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use tokio_postgres::{Client as PGClient, NoTls};

pub struct Database {
    pub pg_client: PGClient,
}

impl Database {
    pub async fn connect() -> Result<Database, TreeMakerError> {
        let postgres_pw = std::env::var("POSTGRES_PW")?;

        let pg_config = format!(
            "host=database-1.cstgyxdzqynn.ap-northeast-2.rds.amazonaws.com user=postgres password={}",
            postgres_pw,
        );

        let (pg_client, connection) = tokio_postgres::connect(&pg_config, NoTls).await?;

        let d = Database { pg_client };

        tokio::spawn(async move {
            if let Err(e) = connection.await {
                println!("connection error: {}", e);
            }
        });

        return Ok(d);
    }
}

impl Database {
    pub async fn insert_balances(
        &self,
        balances: BTreeMap<String, u128>,
    ) -> Result<u64, TreeMakerError> {
        let mut values = Vec::with_capacity(balances.len());
        for (addr, wei) in balances {
            let val = format!("('{}', {})", addr, wei);
            values.push(val);
        }

        let stmt = format!(
            "INSERT INTO balances_20230327 (addr, wei) VALUES {} ON CONFLICT DO NOTHING",
            values.join(",")
        );
        println!("stmt: {}", stmt);

        let rows_updated = self.pg_client.execute(&stmt, &[]).await?;
        println!("rows_updated: {}", rows_updated);

        Ok(rows_updated)
    }
}
