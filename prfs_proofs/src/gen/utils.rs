use eth_types::sign_types::sign;
use ethers_core::k256::elliptic_curve::subtle::CtOption;
use ethers_core::utils::keccak256;
use ff::Field as FiniteField;
use group::Curve;
use halo2_proofs::halo2curves::secp256k1;
use halo2_proofs::halo2curves::secp256k1::Secp256k1Affine;
use rand::RngCore;

const MSG_PREFIX: &str = "\x19Ethereum Signed Message:\n";

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

pub fn gen_msg_hash2(str: String) -> CtOption<secp256k1::Fq> {
    let len = str.len().to_string();
    let bytes = [MSG_PREFIX.as_bytes(), len.as_bytes(), str.as_bytes()].concat();
    let digest = keccak256(bytes);
    secp256k1::Fq::from_bytes(&digest)
}

pub fn sign_with_rng(
    // rng: impl RngCore,
    randomness: secp256k1::Fq,
    sk: secp256k1::Fq,
    msg_hash: secp256k1::Fq,
) -> (secp256k1::Fq, secp256k1::Fq) {
    // let randomness = secp256k1::Fq::random(rng);
    sign(randomness, sk, msg_hash)
}
