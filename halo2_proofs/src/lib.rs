//! # halo2_proofs

#![cfg_attr(docsrs, feature(doc_cfg))]
// The actual lints we want to disable.
#![allow(clippy::op_ref, clippy::many_single_char_names)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod arithmetic;
pub mod circuit;
pub use halo2curves;
pub use pasta_curves as pasta;
mod multicore;
pub mod plonk;
pub mod poly;
pub mod transcript;

pub mod dev;
mod helpers;

pub use ff;
pub use group;

// pub mod arithmetic_pse;
// pub mod helpers_pse;
// pub mod poly_pse;
// pub mod transcript_pse;
