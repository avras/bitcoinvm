use halo2_proofs::plonk::{Column, Advice, TableColumn, ConstraintSystem, Error};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Value},
    poly::Rotation,
};
use std::marker::PhantomData;

use super::constants::*;

#[derive(Clone, Debug)]
pub(super) struct OpcodeInputs {
    pub(super) opcode: Column<Advice>,
    pub(super) is_opcode_enabled: Column<Advice>,
    pub(super) is_opcode_op0: Column<Advice>,
    pub(super) is_opcode_op1_to_op16: Column<Advice>,
    pub(super) is_opcode_push1_to_push75: Column<Advice>,
    pub(super) is_opcode_pushdata1: Column<Advice>,
    pub(super) is_opcode_pushdata2: Column<Advice>,
    pub(super) is_opcode_pushdata4: Column<Advice>,
}

#[derive(Clone, Debug)]
pub(super) struct OpcodeTable {
    pub(super) opcode: TableColumn,
    pub(super) is_opcode_enabled: TableColumn,
    pub(super) is_opcode_op0: TableColumn,
    pub(super) is_opcode_op1_to_op16: TableColumn,
    pub(super) is_opcode_push1_to_push75: TableColumn,
    pub(super) is_opcode_pushdata1: TableColumn,
    pub(super) is_opcode_pushdata2: TableColumn,
    pub(super) is_opcode_pushdata4: TableColumn,
}

#[derive(Clone, Debug)]
pub(super) struct OpcodeTableConfig {
    pub input: OpcodeInputs,
    pub table: OpcodeTable,
}

#[derive(Clone, Debug)]
pub(super) struct OpcodeTableChip<F: FieldExt> {
    config: OpcodeTableConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for OpcodeTableChip<F> {
    type Config = OpcodeTableConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> OpcodeTableChip<F> {
    pub(super) fn configure(
        meta: &mut ConstraintSystem<F>,
        opcode: Column<Advice>,
        is_opcode_enabled: Column<Advice>,
        is_opcode_op0: Column<Advice>,
        is_opcode_op1_to_op16: Column<Advice>,
        is_opcode_push1_to_push75: Column<Advice>,
        is_opcode_pushdata1: Column<Advice>,
        is_opcode_pushdata2: Column<Advice>,
        is_opcode_pushdata4: Column<Advice>,
    ) -> <Self as Chip<F>>::Config {
        let table_opcode = meta.lookup_table_column();
        let table_is_opcode_enabled = meta.lookup_table_column();
        let table_is_opcode_op0 = meta.lookup_table_column();
        let table_is_opcode_op1_to_op16 = meta.lookup_table_column();
        let table_is_opcode_push1_to_push75 = meta.lookup_table_column();
        let table_is_opcode_pushdata1 = meta.lookup_table_column();
        let table_is_opcode_pushdata2 = meta.lookup_table_column();
        let table_is_opcode_pushdata4 = meta.lookup_table_column();

        meta.lookup("Parity byte and pk prefix lookup", |meta| {
            let input_opcode_cur = meta.query_advice(opcode, Rotation::cur());
            let is_opcode_enabled_cur = meta.query_advice(is_opcode_enabled, Rotation::cur());
            let is_opcode_op0_cur = meta.query_advice(is_opcode_op0, Rotation::cur());
            let is_opcode_op1_to_op16_cur = meta.query_advice(is_opcode_op1_to_op16, Rotation::cur());
            let is_opcode_push1_to_push75_cur = meta.query_advice(is_opcode_push1_to_push75, Rotation::cur());
            let is_opcode_pushdata1_cur = meta.query_advice(is_opcode_pushdata1, Rotation::cur());
            let is_opcode_pushdata2_cur = meta.query_advice(is_opcode_pushdata2, Rotation::cur());
            let is_opcode_pushdata4_cur = meta.query_advice(is_opcode_pushdata4, Rotation::cur());
            vec![
                (input_opcode_cur, table_opcode),
                (is_opcode_enabled_cur, table_is_opcode_enabled),
                (is_opcode_op0_cur, table_is_opcode_op0),
                (is_opcode_op1_to_op16_cur, table_is_opcode_op1_to_op16),
                (is_opcode_push1_to_push75_cur, table_is_opcode_push1_to_push75),
                (is_opcode_pushdata1_cur, table_is_opcode_pushdata1),
                (is_opcode_pushdata2_cur, table_is_opcode_pushdata2),
                (is_opcode_pushdata4_cur, table_is_opcode_pushdata4),
            ]
        });

        OpcodeTableConfig {
            input: OpcodeInputs {
                opcode,
                is_opcode_enabled,
                is_opcode_op0,
                is_opcode_op1_to_op16,
                is_opcode_push1_to_push75,
                is_opcode_pushdata1,
                is_opcode_pushdata2,
                is_opcode_pushdata4 
            }, 
            table: OpcodeTable {
                opcode: table_opcode,
                is_opcode_enabled: table_is_opcode_enabled,
                is_opcode_op0: table_is_opcode_op0,
                is_opcode_op1_to_op16: table_is_opcode_op1_to_op16,
                is_opcode_push1_to_push75: table_is_opcode_push1_to_push75,
                is_opcode_pushdata1: table_is_opcode_pushdata1,
                is_opcode_pushdata2: table_is_opcode_pushdata2,
                is_opcode_pushdata4: table_is_opcode_pushdata4
            }
        }
    }

    pub(super) fn load(
        config: OpcodeTableConfig,
        layouter: &mut impl Layouter<F>,
    ) -> Result<<Self as Chip<F>>::Loaded, Error> {
        layouter.assign_table(
            || "Opcode table",
            |mut table| {

                // Run through all possible values of an opcode
                for opcode in 0..256 {

                    table.assign_cell(
                        || "opcode",
                        config.table.opcode,
                        opcode,
                        || Value::known(F::from(opcode as u64)),
                    )?;

                    if opcode <= OP_16 && opcode != OP_1NEGATE && opcode != OP_RESERVED {
                        table.assign_cell(
                            || "opcode enabled",
                            config.table.is_opcode_enabled,
                            opcode,
                            || Value::known(F::one()),
                        )?;
                    }
                    else {
                        table.assign_cell(
                            || "opcode disabled",
                            config.table.is_opcode_enabled,
                            opcode,
                            || Value::known(F::zero()),
                        )?;
                    }

                    let mut assign_is_opcode = |opcode_val: usize, t: TableColumn| -> Result<(), Error> {
                        if opcode == opcode_val {
                            table.assign_cell(
                                || "opcode match",
                                t,
                                opcode,
                                || Value::known(F::one()),
                            )
                        }
                        else {
                            table.assign_cell(
                                || "opcode mismatch",
                                t,
                                opcode,
                                || Value::known(F::zero()),
                            )
                        }

                    };

                    assign_is_opcode(OP_0, config.table.is_opcode_op0)?;
                    assign_is_opcode(OP_PUSHDATA1, config.table.is_opcode_pushdata1)?;
                    assign_is_opcode(OP_PUSHDATA2, config.table.is_opcode_pushdata2)?;
                    assign_is_opcode(OP_PUSHDATA4, config.table.is_opcode_pushdata4)?;

                    let mut assign_is_opcode_in_range
                        = |min_val: usize, max_val: usize, t: TableColumn| -> Result<(), Error> {
                        if opcode >= min_val && opcode <= max_val {
                            table.assign_cell(
                                || "opcode match",
                                t,
                                opcode,
                                || Value::known(F::one()),
                            )
                        }
                        else {
                            table.assign_cell(
                                || "opcode mismatch",
                                t,
                                opcode,
                                || Value::known(F::zero()),
                            )
                        }

                    };

                    assign_is_opcode_in_range(OP_1, OP_16, config.table.is_opcode_op1_to_op16)?;
                    assign_is_opcode_in_range(OP_PUSH_NEXT1, OP_PUSH_NEXT75, config.table.is_opcode_push1_to_push75)?;

                }

                Ok(())
            },
        )
    }
}