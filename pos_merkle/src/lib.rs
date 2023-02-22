mod ecdsa;
mod merkle;

pub use merkle::*;

pub type ProofError = Box<dyn std::error::Error + Send + Sync>;
