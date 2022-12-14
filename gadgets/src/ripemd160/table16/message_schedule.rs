/*
Based on code from https://github.com/privacy-scaling-explorations/halo2/blob/8c945507ceca5f4ed6e52da3672ea0308bcac812/halo2_gadgets/src/sha256/table16/message_schedule.rs
*/

use std::convert::TryInto;

use super::gates::Gate;
use super::{AssignedBits, SpreadInputs, Table16Assignment, NUM_ADVICE_COLS, BlockWord};
use super::BLOCK_SIZE;
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use halo2_proofs::halo2curves::pasta::pallas;

mod schedule_util;

#[derive(Clone, Debug)]
pub(super) struct MessageWord(AssignedBits<32>);

impl std::ops::Deref for MessageWord {
    type Target = AssignedBits<32>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub(super) struct MessageScheduleConfig {
    lookup: SpreadInputs,
    advice: [Column<Advice>; NUM_ADVICE_COLS],

    /// Decomposition gate for X[0..16]
    s_decompose_word: Selector,
}

impl Table16Assignment for MessageScheduleConfig {}

impl MessageScheduleConfig {
    /// Configures the message schedule.
    ///
    /// `advice` contains columns that the message schedule will only use for internal
    /// gates, and will not place any constraints on (such as lookup constraints) outside
    /// itself.
    #[allow(clippy::many_single_char_names)]
    pub(super) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        lookup: SpreadInputs,
        advice: [Column<Advice>; NUM_ADVICE_COLS],
        s_decompose_word: Selector,
    ) -> Self {
        // Rename these here for ease of matching the gates to the specification.
        let a_3 = advice[0];
        let a_4 = advice[1];
        let a_5 = advice[2];

        // s_decompose_word for all words
        meta.create_gate("s_decompose_word", |meta| {
            let s_decompose_word = meta.query_selector(s_decompose_word);
            let lo = meta.query_advice(a_3, Rotation::cur());
            let hi = meta.query_advice(a_4, Rotation::cur());
            let word = meta.query_advice(a_5, Rotation::cur());

            Gate::s_decompose_word(s_decompose_word, lo, hi, word)
        });

        MessageScheduleConfig {
            lookup,
            advice,
            s_decompose_word,
        }
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn process(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        input: [BlockWord; BLOCK_SIZE],
    ) -> Result<
        (
            [MessageWord; BLOCK_SIZE],
            [(AssignedBits<16>, AssignedBits<16>); BLOCK_SIZE],
        ),
        Error,
    > {
        let mut w = Vec::<MessageWord>::with_capacity(BLOCK_SIZE);
        let mut w_halves = Vec::<(AssignedBits<16>, AssignedBits<16>)>::with_capacity(BLOCK_SIZE);

        layouter.assign_region(
            || "process message block",
            |mut region| {
                w = Vec::<MessageWord>::with_capacity(BLOCK_SIZE);
                w_halves = Vec::<(AssignedBits<16>, AssignedBits<16>)>::with_capacity(BLOCK_SIZE);

                // Assign X[0..16]
                for (row, word) in input.iter().enumerate() {
                    let (word, halves) = self.assign_msgblk_word_and_halves(&mut region, word.0, row)?;
                    w.push(MessageWord(word));
                    w_halves.push(halves);
                }

                Ok(())
            },
        )?;

        Ok((w.try_into().unwrap(), w_halves.try_into().unwrap()))
    }
}