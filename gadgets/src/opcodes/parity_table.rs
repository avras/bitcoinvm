use halo2_proofs::plonk::{Column, Advice, TableColumn, ConstraintSystem, Error};
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter, Value},
    poly::Rotation,
};
use super::constants::{
    PREFIX_PK_UNCOMPRESSED,
    PREFIX_PK_COMPRESSED_EVEN_Y,
    PREFIX_PK_COMPRESSED_ODD_Y
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub(super) struct ParityInputs {
    pub(super) pk_prefix: Column<Advice>,
    pub(super) parity_byte: Column<Advice>,
}

#[derive(Clone, Debug)]
pub(super) struct ParityTable {
    pub(super) pk_prefix: TableColumn,
    pub(super) parity_byte: TableColumn,
}

#[derive(Clone, Debug)]
pub(super) struct ParityTableConfig {
    pub input: ParityInputs,
    pub table: ParityTable,
}

#[derive(Clone, Debug)]
pub(super) struct ParityTableChip<F: FieldExt> {
    config: ParityTableConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> Chip<F> for ParityTableChip<F> {
    type Config = ParityTableConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt> ParityTableChip<F> {
    pub(super) fn configure(
        meta: &mut ConstraintSystem<F>,
        input_pk_prefix: Column<Advice>,
        input_parity_byte: Column<Advice>,
    ) -> <Self as Chip<F>>::Config {
        let table_pk_prefix = meta.lookup_table_column();
        let table_parity_byte = meta.lookup_table_column();

        meta.lookup("Parity byte and pk prefix lookup", |meta| {
            let pk_prefix_cur = meta.query_advice(input_pk_prefix, Rotation::cur());
            let parity_byte_cur = meta.query_advice(input_parity_byte, Rotation::cur());

            vec![
                (pk_prefix_cur, table_pk_prefix),
                (parity_byte_cur, table_parity_byte),
            ]
        });

        ParityTableConfig {
            input: ParityInputs { pk_prefix: input_pk_prefix, parity_byte: input_parity_byte },
            table: ParityTable { pk_prefix: table_pk_prefix, parity_byte: table_parity_byte },
        }
    }

    pub(super) fn load(
        config: ParityTableConfig,
        layouter: &mut impl Layouter<F>,
    ) -> Result<<Self as Chip<F>>::Loaded, Error> {
        layouter.assign_table(
            || "PK prefix and y coordinate parity table",
            |mut table| {

                // If prefix byte is 0x04, the parity byte can be anything
                for index in 0..256 {
                    table.assign_cell(
                        || "pk_prefix uncompressed",
                        config.table.pk_prefix,
                        index,
                        || Value::known(F::from(PREFIX_PK_UNCOMPRESSED)),
                    )?;
                    table.assign_cell(
                        || "parity byte",
                        config.table.parity_byte,
                        index,
                        || Value::known(F::from(index as u64)),
                    )?;
                }
                // If parity byte is even, prefix is 0x02
                for index in 0..256 {
                    if index % 2 == 0 {
                        table.assign_cell(
                            || "pk_prefix even y coordinate",
                            config.table.pk_prefix,
                            index,
                            || Value::known(F::from(PREFIX_PK_COMPRESSED_EVEN_Y)),
                        )?;
                    }
                    else {
                        table.assign_cell(
                            || "pk_prefix odd y coordinate",
                            config.table.pk_prefix,
                            index,
                            || Value::known(F::from(PREFIX_PK_COMPRESSED_ODD_Y)),
                        )?;
                    }
                    table.assign_cell(
                        || "parity byte",
                        config.table.parity_byte,
                        index,
                        || Value::known(F::from(index as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }
}