#[cfg(test)]
pub mod test22 {
    use group::{prime::PrimeCurveAffine, Curve, Group, ScalarMul};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::pasta::{pallas, Fp, Fq},
        plonk::{Circuit, ConstraintSystem, Error},
    };

    use crate::{
        ecc::{
            chip::{self, EccChip, EccConfig, FixedPoint},
            tests::TestFixedBases,
            BaseFitsInScalarInstructions, EccInstructions, NonIdentityPoint, Point, ScalarFixed,
            ScalarVar,
        },
        utilities::{lookup_range_check::LookupRangeCheckConfig, UtilitiesInstructions},
    };

    struct MyCircuit2 {
        test_errors: bool,
        b: Value<pallas::Affine>,
        c: Value<pallas::Affine>,
        d: Value<pallas::Affine>,
        e: Value<pallas::Scalar>,
        res: Value<pallas::Affine>,
        mul_res: Value<pallas::Affine>,
    }

    #[allow(non_snake_case)]
    impl Circuit<pallas::Base> for MyCircuit2 {
        type Config = EccConfig<TestFixedBases>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            MyCircuit2 {
                test_errors: false,
                b: Value::unknown(),
                c: Value::unknown(),
                d: Value::unknown(),
                e: Value::unknown(),
                res: Value::unknown(),
                mul_res: Value::unknown(),
            }
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

            let b = NonIdentityPoint::new(chip.clone(), layouter.namespace(|| "P"), self.b)?;
            let c = NonIdentityPoint::new(chip.clone(), layouter.namespace(|| "P"), self.c)?;
            let d = NonIdentityPoint::new(chip.clone(), layouter.namespace(|| "P"), self.d)?;

            let res = NonIdentityPoint::new(chip.clone(), layouter.namespace(|| "P"), self.res)?;
            let res2 = b.add(layouter.namespace(|| "b + c"), &c)?;

            // d.mul()

            {
                println!("111111111");
                let scalar = ScalarVar::new(chip, layouter.namespace(|| "pp"), self.e)?;
                println!("222222222");

                let (p, sc) = d.mul(layouter.namespace(|| "a"), scalar)?;
                println!(
                    "- mul_res (d*e): p: {:?}, sc: {:?}",
                    p.inner().x().value(),
                    sc
                )
            }

            println!("- b: {:?}", b.inner().x());
            println!("- c: {:?}", c.inner().x());
            println!("- res: {:?}", res.inner().x());
            println!("- res2: {:?}", res2.inner().x());

            Ok(())
        }
    }

    #[test]
    fn ecc_chip2() {
        let k = 13;

        let a = pallas::Affine::generator();
        let b = a * Fq::from(2);
        let c = a * Fq::from(3);

        let d = a * Fq::from(5);
        let e = Fq::from(6);

        let res = b + c;
        let res = res.to_affine();

        let mul_res = d * e;
        let mul_res = mul_res.to_affine();

        println!("b: {:?}", b);
        println!("c: {:?}", c);
        println!("d: {:?}", d);
        println!("e: {:?}", e);
        println!("res: {:?}", res);
        println!("mul res (d*e): {:?}", mul_res);

        let circuit = MyCircuit2 {
            test_errors: true,
            b: Value::known(b.to_affine()),
            c: Value::known(c.to_affine()),
            d: Value::known(d.to_affine()),
            e: Value::known(e),
            res: Value::known(res),
            mul_res: Value::known(mul_res),
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(prover.verify(), Ok(()))
    }
}
