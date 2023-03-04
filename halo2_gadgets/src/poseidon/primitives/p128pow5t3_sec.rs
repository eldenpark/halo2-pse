use halo2_proofs::arithmetic::Field;
// use halo2curves::pasta::{pallas::Base as Fp, vesta::Base as Fq};
use halo2_proofs::halo2curves::{
    // pasta::{pallas, Fp},
    secp256k1::Fp as SecFp,
    secp256k1::Fq as SecFq,
    // secp256k1::Fp as SecFp,
};

use super::{Mds, Spec};

/// Poseidon-128 using the $x^5$ S-box, with a width of 3 field elements, and the
/// standard number of rounds for 128-bit security "with margin".
///
/// The standard specification for this set of parameters (on either of the Pasta
/// fields) uses $R_F = 8, R_P = 56$. This is conveniently an even number of
/// partial rounds, making it easier to construct a Halo 2 circuit.
#[derive(Debug)]
pub struct P128Pow5T3Sec;

impl Spec<SecFp, 3, 2> for P128Pow5T3Sec {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: SecFp) -> SecFp {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        unimplemented!()
    }

    fn constants() -> (Vec<[SecFp; 3]>, Mds<SecFp, 3>, Mds<SecFp, 3>) {
        (
            super::fp_sec::ROUND_CONSTANTS[..].to_vec(),
            super::fp_sec::MDS,
            super::fp_sec::MDS_INV,
        )
    }
}

impl Spec<SecFq, 3, 2> for P128Pow5T3Sec {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: SecFq) -> SecFq {
        val.pow_vartime(&[5])
    }

    fn secure_mds() -> usize {
        unimplemented!()
    }

    fn constants() -> (Vec<[SecFq; 3]>, Mds<SecFq, 3>, Mds<SecFq, 3>) {
        (
            super::fq_sec::ROUND_CONSTANTS[..].to_vec(),
            super::fq_sec::MDS,
            super::fq_sec::MDS_INV,
        )
    }
}

#[cfg(test)]
mod tests {
    use ff::PrimeField;
    use std::marker::PhantomData;

    use halo2_proofs::halo2curves::FieldExt;

    use super::{
        // super::{fp, fq},
        super::{fp_sec, fq_sec},
        // Fp, Fq,
        SecFp,
        SecFq,
    };
    use crate::poseidon::primitives::{permute, ConstantLength, Hash, Spec};

    /// The same Poseidon specification as poseidon::P128Pow5T3, but constructed
    /// such that its constants will be generated at runtime.
    #[derive(Debug)]
    pub struct P128Pow5T3Gen<F: FieldExt, const SECURE_MDS: usize>(PhantomData<F>);

    impl<F: FieldExt, const SECURE_MDS: usize> P128Pow5T3Gen<F, SECURE_MDS> {
        pub fn new() -> Self {
            P128Pow5T3Gen(PhantomData::default())
        }
    }

    impl<F: FieldExt, const SECURE_MDS: usize> Spec<F, 3, 2> for P128Pow5T3Gen<F, SECURE_MDS> {
        fn full_rounds() -> usize {
            8
        }

        fn partial_rounds() -> usize {
            56
        }

        fn sbox(val: F) -> F {
            val.pow_vartime(&[5])
        }

        fn secure_mds() -> usize {
            SECURE_MDS
        }
    }

    #[test]
    fn verify_constants() {
        fn verify_constants_helper<F: FieldExt>(
            expected_round_constants: [[F; 3]; 64],
            expected_mds: [[F; 3]; 3],
            expected_mds_inv: [[F; 3]; 3],
        ) {
            let (round_constants, mds, mds_inv) = P128Pow5T3Gen::<F, 0>::constants();

            for (actual, expected) in round_constants
                .iter()
                .flatten()
                .zip(expected_round_constants.iter().flatten())
            {
                assert_eq!(actual, expected);
            }

            for (actual, expected) in mds.iter().flatten().zip(expected_mds.iter().flatten()) {
                assert_eq!(actual, expected);
            }

            for (actual, expected) in mds_inv
                .iter()
                .flatten()
                .zip(expected_mds_inv.iter().flatten())
            {
                assert_eq!(actual, expected);
            }
        }

        verify_constants_helper(fp_sec::ROUND_CONSTANTS, fp_sec::MDS, fp_sec::MDS_INV);
        verify_constants_helper(fq_sec::ROUND_CONSTANTS, fq_sec::MDS, fq_sec::MDS_INV);
    }

    #[test]
    fn test_against_reference() {
        {
            // <https://github.com/daira/pasta-hadeshash>, using parameters from
            // `generate_parameters_grain.sage 1 0 255 3 8 56 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`.
            // The test vector is generated by `sage poseidonperm_x5_pallas_3.sage --rust`

            let mut input = [
                SecFp::from_raw([
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                SecFp::from_raw([
                    0x0000_0000_0000_0001,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                SecFp::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
            ];

            let expected_output = [
                SecFp::from_raw([
                    0xaeb1_bc02_4aec_a456,
                    0xf7e6_9a71_d0b6_42a0,
                    0x94ef_b364_f966_240f,
                    0x2a52_6acd_0b64_b453,
                ]),
                SecFp::from_raw([
                    0x012a_3e96_28e5_b82a,
                    0xdcd4_2e7f_bed9_dafe,
                    0x76ff_7dae_343d_5512,
                    0x13c5_d156_8b4a_a430,
                ]),
                SecFp::from_raw([
                    0x3590_29a1_d34e_9ddd,
                    0xf7cf_dfe1_bda4_2c7b,
                    0x256f_cd59_7984_561a,
                    0x0a49_c868_c697_6544,
                ]),
            ];

            permute::<SecFp, P128Pow5T3Gen<SecFp, 0>, 3, 2>(
                &mut input,
                &fp_sec::MDS,
                &fp_sec::ROUND_CONSTANTS,
            );
            assert_eq!(input, expected_output);
        }

        {
            // <https://github.com/daira/pasta-hadeshash>, using parameters from
            // `generate_parameters_grain.sage 1 0 255 3 8 56 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001`.
            // The test vector is generated by `sage poseidonperm_x5_vesta_3.sage --rust`

            let mut input = [
                SecFq::from_raw([
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                SecFq::from_raw([
                    0x0000_0000_0000_0001,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
                SecFq::from_raw([
                    0x0000_0000_0000_0002,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                    0x0000_0000_0000_0000,
                ]),
            ];

            let expected_output = [
                SecFq::from_raw([
                    0x0eb0_8ea8_13be_be59,
                    0x4d43_d197_3dd3_36c6,
                    0xeddd_74f2_2f8f_2ff7,
                    0x315a_1f4c_db94_2f7c,
                ]),
                SecFq::from_raw([
                    0xf9f1_26e6_1ea1_65f1,
                    0x413e_e0eb_7bbd_2198,
                    0x642a_dee0_dd13_aa48,
                    0x3be4_75f2_d764_2bde,
                ]),
                SecFq::from_raw([
                    0x14d5_4237_2a7b_a0d9,
                    0x5019_bfd4_e042_3fa0,
                    0x117f_db24_20d8_ea60,
                    0x25ab_8aec_e953_7168,
                ]),
            ];

            permute::<SecFq, P128Pow5T3Gen<SecFq, 0>, 3, 2>(
                &mut input,
                &fq_sec::MDS,
                &fq_sec::ROUND_CONSTANTS,
            );
            assert_eq!(input, expected_output);
        }
    }

    #[test]
    fn permute_test_vectors() {
        {
            let (round_constants, mds, _) = super::P128Pow5T3Sec::constants();

            for tv in crate::poseidon::primitives::test_vectors::fp::permute() {
                let mut state = [
                    SecFp::from_repr(tv.initial_state[0]).unwrap(),
                    SecFp::from_repr(tv.initial_state[1]).unwrap(),
                    SecFp::from_repr(tv.initial_state[2]).unwrap(),
                ];

                permute::<SecFp, super::P128Pow5T3Sec, 3, 2>(&mut state, &mds, &round_constants);

                for (expected, actual) in tv.final_state.iter().zip(state.iter()) {
                    assert_eq!(&actual.to_repr(), expected);
                }
            }
        }

        {
            let (round_constants, mds, _) = super::P128Pow5T3Sec::constants();

            for tv in crate::poseidon::primitives::test_vectors::fq::permute() {
                let mut state = [
                    SecFq::from_repr(tv.initial_state[0]).unwrap(),
                    SecFq::from_repr(tv.initial_state[1]).unwrap(),
                    SecFq::from_repr(tv.initial_state[2]).unwrap(),
                ];

                permute::<SecFq, super::P128Pow5T3Sec, 3, 2>(&mut state, &mds, &round_constants);

                for (expected, actual) in tv.final_state.iter().zip(state.iter()) {
                    assert_eq!(&actual.to_repr(), expected);
                }
            }
        }
    }

    #[test]
    fn hash_test_vectors333() {
        for tv in crate::poseidon::primitives::test_vectors::fp::hash() {
            let message = [
                SecFp::from_repr(tv.input[0]).unwrap(),
                SecFp::from_repr(tv.input[1]).unwrap(),
            ];

            let result =
                Hash::<_, super::P128Pow5T3Sec, ConstantLength<2>, 3, 2>::init().hash(message);

            assert_eq!(result.to_repr(), tv.output);
        }

        for tv in crate::poseidon::primitives::test_vectors::fq::hash() {
            let message = [
                SecFq::from_repr(tv.input[0]).unwrap(),
                SecFq::from_repr(tv.input[1]).unwrap(),
            ];

            let result =
                Hash::<_, super::P128Pow5T3Sec, ConstantLength<2>, 3, 2>::init().hash(message);

            assert_eq!(result.to_repr(), tv.output);
        }
    }
}
