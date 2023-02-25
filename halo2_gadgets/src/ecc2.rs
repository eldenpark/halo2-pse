#[cfg(test)]
pub mod test22 {
    use group::{prime::PrimeCurveAffine, Curve, Group};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::pasta::pallas,
        plonk::{Circuit, ConstraintSystem, Error},
    };

    use crate::{
        ecc::{
            chip::{self, EccChip, EccConfig},
            tests::TestFixedBases,
            NonIdentityPoint, Point,
        },
        utilities::lookup_range_check::LookupRangeCheckConfig,
    };

    struct MyCircuit2 {
        test_errors: bool,
    }

    #[allow(non_snake_case)]
    impl Circuit<pallas::Base> for MyCircuit2 {
        type Config = EccConfig<TestFixedBases>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            MyCircuit2 { test_errors: false }
        }

        fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
            let advices = [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column(),
            ];
            let lookup_table = meta.lookup_table_column();
            let lagrange_coeffs = [
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
                meta.fixed_column(),
            ];
            // Shared fixed column for loading constants
            let constants = meta.fixed_column();
            meta.enable_constant(constants);

            let range_check = LookupRangeCheckConfig::configure(meta, advices[9], lookup_table);
            EccChip::<TestFixedBases>::configure(meta, advices, lagrange_coeffs, range_check)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<pallas::Base>,
        ) -> Result<(), Error> {
            let chip = EccChip::construct(config.clone());

            // Load 10-bit lookup table. In the Action circuit, this will be
            // provided by the Sinsemilla chip.
            config.lookup_config.load(&mut layouter)?;

            // Generate a random non-identity point P
            let p_val = pallas::Point::random(rand::rngs::OsRng).to_affine(); // P
            let p = NonIdentityPoint::new(
                chip.clone(),
                layouter.namespace(|| "P"),
                Value::known(p_val),
            )?;
            let p_neg = -p_val;
            let p_neg = NonIdentityPoint::new(
                chip.clone(),
                layouter.namespace(|| "-P"),
                Value::known(p_neg),
            )?;

            // Generate a random non-identity point Q
            let q_val = pallas::Point::random(rand::rngs::OsRng).to_affine(); // Q
            let q = NonIdentityPoint::new(
                chip.clone(),
                layouter.namespace(|| "Q"),
                Value::known(q_val),
            )?;

            // Make sure P and Q are not the same point.
            assert_ne!(p_val, q_val);

            // Test that we can witness the identity as a point, but not as a non-identity point.
            {
                let _ = Point::new(
                    chip.clone(),
                    layouter.namespace(|| "identity"),
                    Value::known(pallas::Affine::identity()),
                )?;

                NonIdentityPoint::new(
                    chip.clone(),
                    layouter.namespace(|| "identity"),
                    Value::known(pallas::Affine::identity()),
                )
                .expect_err("Trying to witness the identity should return an error");
            }

            // Test witness non-identity point
            {
                chip::witness_point::tests::test_witness_non_id(
                    chip.clone(),
                    layouter.namespace(|| "witness non-identity point"),
                )
            }

            // Test complete addition
            {
                chip::add::tests::test_add(
                    chip.clone(),
                    layouter.namespace(|| "complete addition"),
                    p_val,
                    &p,
                    q_val,
                    &q,
                    &p_neg,
                )?;
            }

            // Test incomplete addition
            {
                chip::add_incomplete::tests::test_add_incomplete(
                    chip.clone(),
                    layouter.namespace(|| "incomplete addition"),
                    p_val,
                    &p,
                    q_val,
                    &q,
                    &p_neg,
                    self.test_errors,
                )?;
            }

            // Test variable-base scalar multiplication
            {
                chip::mul::tests::test_mul(
                    chip.clone(),
                    layouter.namespace(|| "variable-base scalar mul"),
                    &p,
                    p_val,
                )?;
            }

            // Test full-width fixed-base scalar multiplication
            {
                chip::mul_fixed::full_width::tests::test_mul_fixed(
                    chip.clone(),
                    layouter.namespace(|| "full-width fixed-base scalar mul"),
                )?;
            }

            // Test signed short fixed-base scalar multiplication
            {
                chip::mul_fixed::short::tests::test_mul_fixed_short(
                    chip.clone(),
                    layouter.namespace(|| "signed short fixed-base scalar mul"),
                )?;
            }

            // Test fixed-base scalar multiplication with a base field element
            {
                chip::mul_fixed::base_field_elem::tests::test_mul_fixed_base_field(
                    chip,
                    layouter.namespace(|| "fixed-base scalar mul with base field element"),
                )?;
            }

            Ok(())
        }
    }

    #[test]
    fn ecc_chip2() {
        let k = 13;
        let circuit = MyCircuit2 { test_errors: true };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()))
    }
}
