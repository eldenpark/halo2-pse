mod nodes;
mod proofs;

use crate::{middleware, State};
use hyper::Body;
use prfs_db_interface::db::Database;
use routerify::{Middleware, Router};
use routerify_cors::enable_cors_all;
use std::convert::Infallible;
use std::sync::Arc;
use tokio_postgres::Client;

pub fn build_router(db: Database) -> Router<Body, Infallible> {
    let db = Arc::new(db);
    let state = State { db };

    Router::builder()
        .data(state)
        .middleware(Middleware::pre(middleware::logger))
        .middleware(enable_cors_all())
        .post("/get_nodes", nodes::get_nodes_handler)
        .post("/gen_proof", proofs::gen_proof_handler)
        .err_handler_with_info(middleware::error_handler)
        .build()
        .unwrap()
}
