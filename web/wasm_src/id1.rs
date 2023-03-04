use rand::Rng;
use wasm_bindgen::{prelude::*, Clamped};

use crate::WasmError;

// #[wasm_bindgen()]
// pub fn gen_id_proof() -> Clamped<Vec<u8>> {
//     // Clamped(
//     //     Generator::new(width, height, max_iterations)
//     //         .iter_bytes()
//     //         .collect(),
//     // )
//     //
//     //
//     let window = web_sys::window().expect("should have a window in this context");

//     return Clamped(vec![]);

//     let performance = window
//         .performance()
//         .expect("performance should be available");

//     console_log!("the current time (in ms) is {}", performance.now());
//     let b = pos_merkle::gen_id_proof();

//     Clamped(b)
// }

#[wasm_bindgen]
pub fn gen_id_proof() -> Clamped<Vec<u8>> {
    // let b = pos_merkle::gen_id_proof().unwrap();
    let v = vec![0];

    Clamped(v)
}
