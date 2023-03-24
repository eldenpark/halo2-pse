mod proofs;

use crate::{middleware, State};
use hyper::Body;
use routerify::{Middleware, Router};
use routerify_cors::enable_cors_all;
use std::convert::Infallible;
use std::sync::Arc;
use tokio_postgres::Client;

pub fn router(pg_client: Arc<Client>) -> Router<Body, Infallible> {
    let state = State { pg_client };

    Router::builder()
        .data(state)
        .middleware(Middleware::pre(middleware::logger))
        .middleware(enable_cors_all())
        .post("/gen_proof", proofs::gen_proof_handler)
        .err_handler_with_info(middleware::error_handler)
        .build()
        .unwrap()
}
