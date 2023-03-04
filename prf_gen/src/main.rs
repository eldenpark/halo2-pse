mod hexutils;

use halo2_gadgets::{
    poseidon::{
        // merkle::merkle_path::MerklePath,
        primitives::{self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier, Spec},
        Hash,
    },
    utilities::UtilitiesInstructions,
};
use halo2_proofs::halo2curves::pasta::Fp;
use hyper::{header, Body, Request, Response, Server, StatusCode};
use routerify::prelude::*;
use routerify::{Middleware, RequestInfo, Router, RouterService};
use routerify_cors::enable_cors_all;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{convert::Infallible, net::SocketAddr};
use tokio_postgres::{Client, NoTls};

pub type PrfGenError = Box<dyn std::error::Error + Send + Sync>;

// Define an app state to share it across the route handlers and middlewares.
struct State {
    pg_client: Arc<Client>,
}

#[derive(Serialize, Deserialize, Debug)]
struct Proof {
    power: usize,
}

// A handler for "/" page.
async fn gen_proof_handler(req: Request<Body>) -> Result<Response<Body>, Infallible> {
    let state = req.data::<State>().unwrap();

    let addr = "0x33d10Ab178924ECb7aD52f4c0C8062C3066607ec".to_lowercase();

    let addr = state
        .pg_client
        .query_one(
            "SELECT pos, table_id, val FROM nodes WHERE addr=$1",
            &[&addr],
        )
        .await
        .expect("addr should be found");

    let addr: &str = addr.get("val");

    let addr_val = hexutils::convert_string_into_fp(addr);

    println!("STARTING addr: {}, addr_val (fp): {:?}", addr, addr_val);

    let auth_paths = generate_auth_paths(385);

    let mut curr = addr_val;

    for (height, path) in auth_paths.iter().enumerate() {
        println!("");
        let curr_idx = path.idx;
        let pos = &path.node_loc;

        let node = match state
            .pg_client
            .query_one("SELECT pos, table_id, val FROM nodes WHERE pos=$1", &[&pos])
            .await
        {
            Ok(row) => {
                let val: &str = row.get("val");
                let pos: &str = row.get("pos");

                println!("sibling node, pos: {}, val: {}", pos, val);

                let node = hexutils::convert_string_into_fp(val);

                node
            }
            Err(err) => {
                println!("value doesn't exist, pos: {}", pos,);

                let node = Fp::zero();
                node
            }
        };

        if path.direction {
            let l = hexutils::convert_fp_to_string(node);
            let r = hexutils::convert_fp_to_string(curr);

            println!("l (fp): {:?}, r (fp): {:?}", node, curr);
            println!("l : {:?}, r : {:?}", l, r);

            let hash = poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init()
                .hash([node, curr]);

            curr = hash;
        } else {
            let l = hexutils::convert_fp_to_string(curr);
            let r = hexutils::convert_fp_to_string(node);

            // println!("l: {:?}, r: {:?}", l, r);
            println!("l (fp): {:?}, r (fp): {:?}", curr, node);
            println!("l: {:?}, r : {:?}", l, r);
            let hash = poseidon::Hash::<_, OrchardNullifier, ConstantLength<2>, 3, 2>::init()
                .hash([curr, node]);

            curr = hash;
        }

        let c = hexutils::convert_fp_to_string(curr);

        println!(
            "curr (fp): {:?}, string: {}, parent_pos: {}",
            curr,
            c,
            format!("{}_{}", height + 1, curr_idx / 2)
        );
    }

    let c = hexutils::convert_fp_to_string(curr);

    // pos_merkle::gen_id_proof();
    // path: [Fp; 32],
    // msg_hash: Fq,
    // leaf: Fp,
    // root: Fp,
    // pos: u32,
    // public_key: EpAffine,
    // r: Fq,
    // s: Fq,
    let proof = Proof { power: 1 };

    let proofs = vec![proof];

    let data = serde_json::to_string(&proofs).unwrap();

    let res = Response::builder()
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(data))
        .unwrap();

    Ok(res)
}

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
    let state = State { pg_client };

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

#[derive(Debug, Clone)]
pub struct MerklePath {
    // Node idx at height
    pub idx: u128,

    // Relative position of sibling to curr node. e.g. 0_0 has 0_1 sibling with
    // direction "false"
    pub direction: bool,

    // Node location, e.g. 0_1 refers to the second node in the lowest height
    pub node_loc: String,
}

fn generate_auth_paths(idx: u128) -> Vec<MerklePath> {
    let height = 32;
    let mut auth_path = vec![];
    let mut curr_idx = idx;

    for h in 0..height {
        let sibling_idx = get_sibling_idx(curr_idx);

        let sibling_dir = if sibling_idx % 2 == 0 { true } else { false };

        let p = MerklePath {
            idx: sibling_idx,
            direction: sibling_dir,
            node_loc: format!("{}_{}", h, sibling_idx),
        };

        auth_path.push(p);

        let parent_idx = get_parent_idx(curr_idx);
        curr_idx = parent_idx;
    }

    auth_path
}

fn get_sibling_idx(idx: u128) -> u128 {
    if idx % 2 == 0 {
        idx + 1
    } else {
        idx - 1
    }
}

pub fn get_parent_idx(idx: u128) -> u128 {
    idx / 2
}
