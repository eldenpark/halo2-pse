use ff::PrimeField;
use halo2_proofs::halo2curves::pasta::Fp;

use crate::TreeMakerError;

pub fn convert_addr_to_hex(addr: &str) -> Result<Fp, TreeMakerError> {
    let mut v = hex::decode(addr).unwrap();
    v.extend([0; 12]);

    let arr: [u8; 32] = v.try_into().unwrap();
    Ok(Fp::from_repr(arr).unwrap())
}
