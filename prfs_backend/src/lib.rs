mod middleware;
mod routes;

pub use routes::*;
use std::sync::Arc;
use tokio_postgres::Client;

pub type BackendError = Box<dyn std::error::Error + Send + Sync>;

pub struct State {
    pub pg_client: Arc<Client>,
}
