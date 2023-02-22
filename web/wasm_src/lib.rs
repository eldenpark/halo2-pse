mod id1;

pub use id1::*;

// /*
//  * Copyright 2022 Google Inc. All Rights Reserved.
//  * Licensed under the Apache License, Version 2.0 (the "License");
//  * you may not use this file except in compliance with the License.
//  * You may obtain a copy of the License at
//  *     http://www.apache.org/licenses/LICENSE-2.0
//  * Unless required by applicable law or agreed to in writing, software
//  * distributed under the License is distributed on an "AS IS" BASIS,
//  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  * See the License for the specific language governing permissions and
//  * limitations under the License.
//  */
// use hsl::HSL;
// use num_complex::Complex64;
// use rand::Rng;
// use wasm_bindgen::{prelude::*, Clamped};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[cfg(feature = "parallel")]
pub use wasm_bindgen_rayon::init_thread_pool;

pub type WasmError = Box<dyn std::error::Error + Send + Sync>;

use std::time::{Duration, SystemTime, UNIX_EPOCH};
use wasm_bindgen::prelude::*;

// lifted from the `console_log` example
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(a: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

// #[wasm_bindgen]
// pub fn run() {
//     let b = js_sys::global().dyn_into::<Window>().ok();

//     let window = web_sys::window().expect("should have a window in this context");

//     console_log!("ssss {:?}", b);

//     let performance = window
//         .performance()
//         .expect("performance should be available");

//     console_log!("the current time (in ms) is {}", performance.now());

//     let start = perf_to_system(performance.timing().request_start());
//     let end = perf_to_system(performance.timing().response_end());

//     console_log!("request started at {}", humantime::format_rfc3339(start));
//     console_log!("request ended at {}", humantime::format_rfc3339(end));
// }

fn perf_to_system(amt: f64) -> SystemTime {
    let secs = (amt as u64) / 1_000;
    let nanos = (((amt as u64) % 1_000) as u32) * 1_000_000;
    UNIX_EPOCH + Duration::new(secs, nanos)
}
