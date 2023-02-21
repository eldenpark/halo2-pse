use rand::Rng;
use wasm_bindgen::{prelude::*, Clamped};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[cfg(feature = "parallel")]
pub use wasm_bindgen_rayon::init_thread_pool;

#[wasm_bindgen]
pub fn gen_id_proof() -> Clamped<Vec<u8>> {
    // Clamped(
    //     Generator::new(width, height, max_iterations)
    //         .iter_bytes()
    //         .collect(),
    // )
    //
    let b = pos_merkle::gen_id_proof();

    Clamped(b)
}
