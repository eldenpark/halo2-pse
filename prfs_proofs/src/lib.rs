// mod ecdsa;
mod merkle;
mod utils;
mod zkevm_circuits;

pub use merkle::*;
pub use utils::*;

pub type ProofError = Box<dyn std::error::Error + Send + Sync>;
