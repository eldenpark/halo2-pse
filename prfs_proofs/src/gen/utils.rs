use eth_types::sign_types::sign;
use ff::Field as FiniteField;
use group::Curve;
use halo2_proofs::halo2curves::secp256k1;
use halo2_proofs::halo2curves::secp256k1::Secp256k1Affine;
use rand::RngCore;

pub fn gen_key_pair(rng: impl RngCore) -> (secp256k1::Fq, Secp256k1Affine) {
    let generator = Secp256k1Affine::generator();
    let sk = secp256k1::Fq::random(rng);
    let pk = generator * sk;
    let pk = pk.to_affine();

    (sk, pk)
}

pub fn gen_msg_hash(rng: impl RngCore) -> secp256k1::Fq {
    secp256k1::Fq::random(rng)
}

pub fn sign_with_rng(
    rng: impl RngCore,
    sk: secp256k1::Fq,
    msg_hash: secp256k1::Fq,
) -> (secp256k1::Fq, secp256k1::Fq) {
    let randomness = secp256k1::Fq::random(rng);
    sign(randomness, sk, msg_hash)
}
