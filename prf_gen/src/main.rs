use hyper::{header, Body, Request, Response, Server, StatusCode};
// Import the routerify prelude traits.
use routerify::prelude::*;
use routerify::{Middleware, RequestInfo, Router, RouterService};
use routerify_cors::enable_cors_all;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{convert::Infallible, net::SocketAddr};
use tokio_postgres::{Client, NoTls};

// Define an app state to share it across the route handlers and middlewares.
struct State {}

#[derive(Serialize, Deserialize, Debug)]
struct Proof {
    power: usize,
}

// A handler for "/" page.
async fn gen_proof_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    // Access the app state.
    let state = req.data::<State>().unwrap();

    let proof = Proof { power: 1 };

    let proofs = vec![proof];

    let data = serde_json::to_string(&proofs).unwrap();

    let res = Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(data))
        .unwrap();

    Ok(res)
}

// // A handler for "/users/:userId" page.
// async fn user_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
//     let user_id = req.param("userId").unwrap();
//     Ok(Response::new(Body::from(format!("Hello {}", user_id))))
// }

// A middleware which logs an http request.
async fn logger(req: Request<Body>) -> Result<Request<Body>, Infallible> {
    println!(
        "{} {} {}",
        req.remote_addr(),
        req.method(),
        req.uri().path()
    );
    Ok(req)
}

// Define an error handler function which will accept the `routerify::Error`
// and the request information and generates an appropriate response.
async fn error_handler(err: routerify::RouteError, _: RequestInfo) -> Response<Body> {
    eprintln!("{}", err);

    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Body::from(format!("Something went wrong: {}", err)))
        .unwrap()
}

// Create a `Router<Body, Infallible>` for response body type `hyper::Body`
// and for handler error type `Infallible`.
fn router(pg_client: Arc<Client>) -> Router<Body, Infallible> {
    // Create a router and specify the logger middleware and the handlers.
    // Here, "Middleware::pre" means we're adding a pre middleware which will be executed
    // before any route handlers.
    let state = State {};

    Router::builder()
        .data(state)
        .middleware(Middleware::pre(logger))
        .middleware(enable_cors_all())
        .get("/gen_proof", gen_proof_handler)
        .err_handler_with_info(error_handler)
        .build()
        .unwrap()
}
#[tokio::main]
async fn main() {
    let (pg_client, connection) = tokio_postgres::connect(
        "host=database-1.cstgyxdzqynn.ap-northeast-2.rds.amazonaws.com user=postgres password=postgres",
        NoTls,
    )
    .await.unwrap();

    let pg_client = Arc::new(pg_client);
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            println!("connection error: {}", e);
        }
    });

    let router = router(pg_client);

    // Create a Service from the router above to handle incoming requests.
    let service = RouterService::new(router).unwrap();

    // The address on which the server will be listening.
    let addr = SocketAddr::from(([127, 0, 0, 1], 4000));

    // Create a server by passing the created service to `.serve` method.
    let server = Server::bind(&addr).serve(service);

    println!("App is running on: {}", addr);
    if let Err(err) = server.await {
        eprintln!("Server error: {}", err);
    }
}
