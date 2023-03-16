use std::fmt::Debug;

pub trait MultiMillerLoop: halo2curves::pairing::MultiMillerLoop + Debug {}

impl<M: halo2curves::pairing::MultiMillerLoop + Debug> MultiMillerLoop for M {}
