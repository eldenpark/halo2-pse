// /// Recover the public key from a secp256k1 signature and the message hash.
// pub fn recover_pk(
//     v: u8,
//     r: &Word,
//     s: &Word,
//     msg_hash: &[u8; 32],
// ) -> Result<Secp256k1Affine, libsecp256k1::Error> {
//     let mut sig_bytes = [0u8; 64];
//     sig_bytes[..32].copy_from_slice(&r.to_be_bytes());
//     sig_bytes[32..].copy_from_slice(&s.to_be_bytes());
//     let signature = libsecp256k1::Signature::parse_standard(&sig_bytes)?;
//     let msg_hash = libsecp256k1::Message::parse_slice(msg_hash.as_slice())?;
//     let recovery_id = libsecp256k1::RecoveryId::parse(v)?;
//     let pk = libsecp256k1::recover(&msg_hash, &signature, &recovery_id)?;
//     let pk_be = pk.serialize();
//     let pk_le = pk_bytes_swap_endianness(&pk_be[1..]);
//     let x = ct_option_ok_or(
//         secp256k1::Fp::from_bytes(pk_le[..32].try_into().unwrap()),
//         libsecp256k1::Error::InvalidPublicKey,
//     )?;
//     let y = ct_option_ok_or(
//         secp256k1::Fp::from_bytes(pk_le[32..].try_into().unwrap()),
//         libsecp256k1::Error::InvalidPublicKey,
//     )?;
//     ct_option_ok_or(
//         Secp256k1Affine::from_xy(x, y),
//         libsecp256k1::Error::InvalidPublicKey,
//     )
// }

// lazy_static! {
//     /// Secp256k1 Curve Scalar.  Referece: Section 2.4.1 (parameter `n`) in "SEC 2: Recommended
//     /// Elliptic Curve Domain Parameters" document at http://www.secg.org/sec2-v2.pdf
//     pub static ref SECP256K1_Q: BigUint = BigUint::from_bytes_le(&(secp256k1::Fq::zero() - secp256k1::Fq::one()).to_repr()) + 1u64;
// }

use halo2_proofs::halo2curves::{secp256k1::Secp256k1Affine, Coordinates, CurveAffine};

/// Return a copy of the serialized public key with swapped Endianness.
pub fn pk_bytes_swap_endianness<T: Clone>(pk: &[T]) -> [T; 64] {
    assert_eq!(pk.len(), 64);
    let mut pk_swap = <&[T; 64]>::try_from(pk)
        .map(|r| r.clone())
        .expect("pk.len() != 64");
    pk_swap[..32].reverse();
    pk_swap[32..].reverse();
    pk_swap
}

/// Return the secp256k1 public key (x, y) coordinates in little endian bytes.
pub fn pk_bytes_le(pk: &Secp256k1Affine) -> [u8; 64] {
    let pk_coord = Option::<Coordinates<_>>::from(pk.coordinates()).expect("point is the identity");
    let mut pk_le = [0u8; 64];
    pk_le[..32].copy_from_slice(&pk_coord.x().to_bytes());
    pk_le[32..].copy_from_slice(&pk_coord.y().to_bytes());
    pk_le
}
