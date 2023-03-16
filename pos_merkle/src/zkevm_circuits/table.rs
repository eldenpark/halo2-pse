// use crate::copy_circuit::number_or_hash_to_field;
use crate::zkevm_circuits::evm_circuit::util::rlc;
// use crate::zkevm_circuits::exp_circuit::{OFFSET_INCREMENT, ROWS_PER_STEP};
// use crate::zkevm_circuits::impl_expr;
// use crate::zkevm_circuits::util::build_tx_log_address;
use crate::zkevm_circuits::util::Challenges;
// use crate::zkevm_circuits::witness::{
//     Block, BlockContext, Bytecode, MptUpdateRow, MptUpdates, Rw, RwMap, RwRow, Transaction,
// };
use bus_mapping::circuit_input_builder::{CopyDataType, CopyEvent, CopyStep, ExpEvent};
use core::iter::once;
use eth_types::{Field, ToLittleEndian, ToScalar, Word, U256};
use gadgets::binary_number::{BinaryNumberChip, BinaryNumberConfig};
use gadgets::util::{split_u256, split_u256_limb64};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error},
};
use halo2_proofs::{circuit::Layouter, plonk::*, poly::Rotation};
use itertools::Itertools;
use keccak256::plain::Keccak;
use std::array;
use strum_macros::{EnumCount, EnumIter};

/// Trait used to define lookup tables
pub trait LookupTable<F: Field> {
    /// Returns the list of ALL the table columns following the table order.
    fn columns(&self) -> Vec<Column<Any>>;

    /// Returns the list of ALL the table advice columns following the table
    /// order.
    fn advice_columns(&self) -> Vec<Column<Advice>> {
        self.columns()
            .iter()
            .map(|&col| col.try_into())
            .filter_map(|res| res.ok())
            .collect()
    }

    /// Returns the String annotations associated to each column of the table.
    fn annotations(&self) -> Vec<String>;

    /// Return the list of expressions used to define the lookup table.
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.columns()
            .iter()
            .map(|&column| meta.query_any(column, Rotation::cur()))
            .collect()
    }

    /// Annotates a lookup table by passing annotations for each of it's
    /// columns.
    fn annotate_columns(&self, cs: &mut ConstraintSystem<F>) {
        self.columns()
            .iter()
            .zip(self.annotations().iter())
            .for_each(|(&col, ann)| cs.annotate_lookup_any_column(col, || ann))
    }

    /// Annotates columns of a table embedded within a circuit region.
    fn annotate_columns_in_region(&self, region: &mut Region<F>) {
        self.columns()
            .iter()
            .zip(self.annotations().iter())
            .for_each(|(&col, ann)| region.name_column(|| ann, col))
    }
}

impl<F: Field, C: Into<Column<Any>> + Copy, const W: usize> LookupTable<F> for [C; W] {
    fn table_exprs(&self, meta: &mut VirtualCells<F>) -> Vec<Expression<F>> {
        self.iter()
            .map(|column| meta.query_any(*column, Rotation::cur()))
            .collect()
    }

    fn columns(&self) -> Vec<Column<Any>> {
        self.iter().map(|&col| col.into()).collect()
    }

    fn annotations(&self) -> Vec<String> {
        vec![]
    }
}

#[derive(Clone, Debug)]
pub struct KeccakTable {
    /// True when the row is enabled
    pub is_enabled: Column<Advice>,
    /// Byte array input as `RLC(reversed(input))`
    pub input_rlc: Column<Advice>, // RLC of input bytes
    /// Byte array input length
    pub input_len: Column<Advice>,
    /// RLC of the hash result
    pub output_rlc: Column<Advice>, // RLC of hash of input bytes
}

impl<F: Field> LookupTable<F> for KeccakTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.is_enabled.into(),
            self.input_rlc.into(),
            self.input_len.into(),
            self.output_rlc.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("is_enabled"),
            String::from("input_rlc"),
            String::from("input_len"),
            String::from("output_rlc"),
        ]
    }
}

impl KeccakTable {
    /// Construct a new KeccakTable
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        Self {
            is_enabled: meta.advice_column(),
            input_rlc: meta.advice_column_in(SecondPhase),
            input_len: meta.advice_column(),
            output_rlc: meta.advice_column_in(SecondPhase),
        }
    }

    /// Generate the keccak table assignments from a byte array input.
    pub fn assignments<F: Field>(
        input: &[u8],
        challenges: &Challenges<Value<F>>,
    ) -> Vec<[Value<F>; 4]> {
        let input_rlc = challenges
            .keccak_input()
            .map(|challenge| rlc::value(input.iter().rev(), challenge));
        let input_len = F::from(input.len() as u64);
        let mut keccak = Keccak::default();
        keccak.update(input);
        let output = keccak.digest();
        let output_rlc = challenges.evm_word().map(|challenge| {
            rlc::value(
                &Word::from_big_endian(output.as_slice()).to_le_bytes(),
                challenge,
            )
        });

        vec![[
            Value::known(F::one()),
            input_rlc,
            Value::known(input_len),
            output_rlc,
        ]]
    }

    /// Assign a table row for keccak table
    pub fn assign_row<F: Field>(
        &self,
        region: &mut Region<F>,
        offset: usize,
        values: [Value<F>; 4],
    ) -> Result<(), Error> {
        for (&column, value) in <KeccakTable as LookupTable<F>>::advice_columns(self)
            .iter()
            .zip(values.iter())
        {
            region.assign_advice(|| format!("assign {}", offset), column, offset, || *value)?;
        }
        Ok(())
    }

    /// Provide this function for the case that we want to consume a keccak
    /// table but without running the full keccak circuit
    pub fn dev_load<'a, F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        inputs: impl IntoIterator<Item = &'a Vec<u8>> + Clone,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "keccak table",
            |mut region| {
                let mut offset = 0;
                for column in <KeccakTable as LookupTable<F>>::advice_columns(self) {
                    region.assign_advice(
                        || "keccak table all-zero row",
                        column,
                        offset,
                        || Value::known(F::zero()),
                    )?;
                }
                offset += 1;

                let keccak_table_columns = <KeccakTable as LookupTable<F>>::advice_columns(self);
                for input in inputs.clone() {
                    for row in Self::assignments(input, challenges) {
                        // let mut column_index = 0;
                        for (&column, value) in keccak_table_columns.iter().zip_eq(row) {
                            region.assign_advice(
                                || format!("keccak table row {}", offset),
                                column,
                                offset,
                                || value,
                            )?;
                        }
                        offset += 1;
                    }
                }
                Ok(())
            },
        )
    }

    /// returns matchings between the circuit columns passed as parameters and
    /// the table collumns
    pub fn match_columns(
        &self,
        value_rlc: Column<Advice>,
        length: Column<Advice>,
        code_hash: Column<Advice>,
    ) -> Vec<(Column<Advice>, Column<Advice>)> {
        vec![
            (value_rlc, self.input_rlc),
            (length, self.input_len),
            (code_hash, self.output_rlc),
        ]
    }
}
