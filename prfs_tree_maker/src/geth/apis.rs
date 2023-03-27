use crate::geth::io_models::{GetBalanceRequest, GetBalanceResponse};
use crate::make_request_type;
use crate::{config::GETH_ENDPOINT, TreeMakerError};
use hyper::body::HttpBody;
use hyper::{client::HttpConnector, Body, Client as HyperClient, Method, Request};
use hyper_tls::HttpsConnector;
use serde_json::json;

use super::{GetBlockByNumberRequest, GetBlockResponse};

pub struct GethClient {
    pub hyper_client: HyperClient<HttpsConnector<HttpConnector>>,
}

#[allow(non_snake_case)]
impl GethClient {
    make_request_type!(eth_getBalance, GetBalanceRequest, GetBalanceResponse);
    make_request_type!(
        eth_getBlockByNumber,
        GetBlockByNumberRequest,
        GetBlockResponse
    );
}

#[macro_export]
macro_rules! make_request_type {
    ($fn_name:ident, $req_type:ident, $resp_type:ident) => {
        pub async fn $fn_name<'a>(
            &self,
            req_type: $req_type<'a>,
        ) -> Result<$resp_type, crate::TreeMakerError> {
            let method = stringify!($fn_name);

            let body = serde_json::json!(
                {
                    "jsonrpc":"2.0",
                    "method": method,
                    "params": req_type,
                    "id":1,
                }
            )
            .to_string();

            let req = Request::builder()
                .method(Method::POST)
                .uri($crate::config::GETH_ENDPOINT)
                .header("content-type", "application/json")
                .body(Body::from(body))?;

            let mut resp = self.hyper_client.request(req).await?;

            match resp.body_mut().data().await {
                Some(r) => {
                    let body = r.unwrap();
                    let res: $resp_type = match serde_json::from_slice(&body) {
                        Ok(r) => r,
                        Err(err) => {
                            println!(
                                "Error deserializing {}, original body: {:?}, err: {}",
                                stringify!($resp_type), body, err,
                            );

                            return Err(err.into());
                        }
                    };

                    return Ok(res);
                }
                None => {
                    return Err("no data in body".into());
                }
            };

        }
    };
}
