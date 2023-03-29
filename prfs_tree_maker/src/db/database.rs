use crate::TreeMakerError;
use rust_decimal::Decimal;
use std::collections::BTreeMap;
use tokio_postgres::{Client as PGClient, NoTls};

use super::models::Account;

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
    pub async fn get_accounts(&self, where_clause: &str) -> Result<Vec<Account>, TreeMakerError> {
        let stmt = format!("SELECT * from balances_20230327 where {}", where_clause);
        println!("stmt: {}", stmt);

        let rows = self.pg_client.query(&stmt, &[]).await?;
        let mut v = Vec::with_capacity(rows.len());

        for row in rows {
            let addr: String = row.try_get("addr")?;
            let wei: Decimal = row.try_get("wei")?;

            println!("wei: {}", wei);

            let acc = Account { addr, wei };
            v.push(acc);
        }

        // let stmt = if update_on_conflict {
        //     format!(
        //         "INSERT INTO balances_20230327 (addr, wei) VALUES {} ON CONFLICT(addr) {}",
        //         values.join(","),
        //         "DO UPDATE SET wei = excluded.wei, updated_at = now()",
        //     )
        // } else {
        //     format!(
        //         "INSERT INTO balances_20230327 (addr, wei) VALUES {} ON CONFLICT DO NOTHING",
        //         values.join(",")
        //     )
        // };
        //
        Ok(v)
    }

    pub async fn insert_balances(
        &self,
        balances: BTreeMap<String, Account>,
        update_on_conflict: bool,
    ) -> Result<u64, TreeMakerError> {
        let mut values = Vec::with_capacity(balances.len());
        for (_, acc) in balances {
            let val = format!("('{}', {})", acc.addr, acc.wei);
            values.push(val);
        }

        let stmt = if update_on_conflict {
            format!(
                "INSERT INTO balances_20230327 (addr, wei) VALUES {} ON CONFLICT(addr) {}",
                values.join(","),
                "DO UPDATE SET wei = excluded.wei, updated_at = now()",
            )
        } else {
            format!(
                "INSERT INTO balances_20230327 (addr, wei) VALUES {} ON CONFLICT DO NOTHING",
                values.join(",")
            )
        };
        // println!("stmt: {}", stmt);

        let rows_updated = match self.pg_client.execute(&stmt, &[]).await {
            Ok(r) => r,
            Err(err) => {
                tracing::error!("Error executing stmt, err: {}, stmt: {}", err, stmt);

                return Err(err.into());
            }
        };

        Ok(rows_updated)
    }
}
