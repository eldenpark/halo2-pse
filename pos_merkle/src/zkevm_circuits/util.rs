use bus_mapping::evm::OpcodeId;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Value},
    plonk::{
        Challenge, ConstraintSystem, Error, Expression, FirstPhase, SecondPhase, VirtualCells,
    },
};
use keccak256::plain::Keccak;

use crate::zkevm_circuits::evm_circuit::util::rlc;
use crate::zkevm_circuits::witness;
use eth_types::{Field, ToAddress, Word};
pub use ethers_core::types::{Address, U256};
pub use gadgets::util::Expr;

pub(crate) fn random_linear_combine_word<F: FieldExt>(bytes: [u8; 32], randomness: F) -> F {
    rlc::value(&bytes, randomness)
}

pub(crate) fn query_expression<F: FieldExt, T>(
    meta: &mut ConstraintSystem<F>,
    mut f: impl FnMut(&mut VirtualCells<F>) -> T,
) -> T {
    let mut expr = None;
    meta.create_gate("Query expression", |meta| {
        expr = Some(f(meta));
        Some(0.expr())
    });
    expr.unwrap()
}

/// All challenges used in `SuperCircuit`.
#[derive(Default, Clone, Copy, Debug)]
pub struct Challenges<T = Challenge> {
    evm_word: T,
    keccak_input: T,
    lookup_input: T,
}

impl Challenges {
    /// Construct `Challenges` by allocating challenges in specific phases.
    pub fn construct<F: FieldExt>(meta: &mut ConstraintSystem<F>) -> Self {
        #[cfg(any(feature = "test", test, feature = "test-circuits"))]
        let _dummy_cols = [
            meta.advice_column(),
            meta.advice_column_in(SecondPhase),
            meta.advice_column_in(halo2_proofs::plonk::ThirdPhase),
        ];

        Self {
            evm_word: meta.challenge_usable_after(FirstPhase),
            keccak_input: meta.challenge_usable_after(FirstPhase),
            lookup_input: meta.challenge_usable_after(SecondPhase),
        }
    }

    /// Returns `Expression` of challenges from `ConstraintSystem`.
    pub fn exprs<F: FieldExt>(&self, meta: &mut ConstraintSystem<F>) -> Challenges<Expression<F>> {
        let [evm_word, keccak_input, lookup_input] = query_expression(meta, |meta| {
            [self.evm_word, self.keccak_input, self.lookup_input]
                .map(|challenge| meta.query_challenge(challenge))
        });
        Challenges {
            evm_word,
            keccak_input,
            lookup_input,
        }
    }

    /// Returns `Value` of challenges from `Layouter`.
    pub fn values<F: FieldExt>(&self, layouter: &mut impl Layouter<F>) -> Challenges<Value<F>> {
        Challenges {
            evm_word: layouter.get_challenge(self.evm_word),
            keccak_input: layouter.get_challenge(self.keccak_input),
            lookup_input: layouter.get_challenge(self.lookup_input),
        }
    }
}

impl<T: Clone> Challenges<T> {
    /// Returns challenge of `evm_word`.
    pub fn evm_word(&self) -> T {
        self.evm_word.clone()
    }

    /// Returns challenge of `keccak_input`.
    pub fn keccak_input(&self) -> T {
        self.keccak_input.clone()
    }

    /// Returns challenge of `lookup_input`.
    pub fn lookup_input(&self) -> T {
        self.lookup_input.clone()
    }

    /// Returns the challenges indexed by the challenge index
    pub fn indexed(&self) -> [&T; 3] {
        [&self.evm_word, &self.keccak_input, &self.lookup_input]
    }

    pub(crate) fn mock(evm_word: T, keccak_input: T, lookup_input: T) -> Self {
        Self {
            evm_word,
            keccak_input,
            lookup_input,
        }
    }
}

impl<F: Field> Challenges<Expression<F>> {
    /// Returns powers of randomness
    fn powers_of<const S: usize>(base: Expression<F>) -> [Expression<F>; S] {
        std::iter::successors(base.clone().into(), |power| {
            (base.clone() * power.clone()).into()
        })
        .take(S)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
    }

    /// Returns powers of randomness for word RLC encoding
    pub fn evm_word_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.evm_word.clone())
    }

    /// Returns powers of randomness for keccak circuit's input
    pub fn keccak_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.keccak_input.clone())
    }

    /// Returns powers of randomness for lookups
    pub fn lookup_input_powers_of_randomness<const S: usize>(&self) -> [Expression<F>; S] {
        Self::powers_of(self.lookup_input.clone())
    }
}
