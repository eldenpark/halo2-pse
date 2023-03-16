mod chip;
mod expr1;
mod expr2;
mod merkle_path;
mod sign_verify;
mod test1;
mod zkevm;

pub use expr1::*;
use halo2_proofs::halo2curves::CurveAffine;
use maingate::{big_to_fe, fe_to_big};

pub fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
    let x_big = fe_to_big(x);
    big_to_fe(x_big)
}
