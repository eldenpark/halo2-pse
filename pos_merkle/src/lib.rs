// mod ecdsa;
mod merkle;
mod utils;

pub use merkle::*;
pub use utils::*;

pub type ProofError = Box<dyn std::error::Error + Send + Sync>;
