/*
Based on code from https://github.com/privacy-scaling-explorations/halo2/blob/8c945507ceca5f4ed6e52da3672ea0308bcac812/halo2_gadgets/src/sha256/table16/message_schedule.rs
*/

use std::convert::TryInto;

use super::{AssignedBits, BlockWord, SpreadInputs, /* Table16Assignment,*/ NUM_EXTRA_ADVICE_COLS};
use super::{BLOCK_SIZE, ROUNDS};
use halo2::{
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use halo2::halo2curves::pasta::pallas;

mod schedule_gates;
mod schedule_util;
//mod subregion1;
//mod subregion2;
//mod subregion3;

use schedule_gates::ScheduleGate;


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
    message_schedule: Column<Advice>,
    extras: [Column<Advice>; NUM_EXTRA_ADVICE_COLS],

    /// Decomposition gate for X[0..16]
    s_decompose_0: Selector,
}

//impl Table16Assignment for MessageScheduleConfig {}

impl MessageScheduleConfig {
    /// Configures the message schedule.
    ///
    /// `message_schedule` is the column into which the message schedule will be placed.
    /// The caller must create appropriate permutations in order to load schedule words
    /// into the compression rounds.
    ///
    /// `extras` contains columns that the message schedule will only use for internal
    /// gates, and will not place any constraints on (such as lookup constraints) outside
    /// itself.
    #[allow(clippy::many_single_char_names)]
    pub(super) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        lookup: SpreadInputs,
        message_schedule: Column<Advice>,
        extras: [Column<Advice>; NUM_EXTRA_ADVICE_COLS],
    ) -> Self {
        // Create fixed columns for the selectors we will require.
        let s_decompose_0 = meta.selector();

        // Rename these here for ease of matching the gates to the specification.
        let a_3 = extras[0];
        let a_4 = extras[1];
        let a_5 = message_schedule;

        // s_decompose_0 for all words
        meta.create_gate("s_decompose_0", |meta| {
            let s_decompose_0 = meta.query_selector(s_decompose_0);
            let lo = meta.query_advice(a_3, Rotation::cur());
            let hi = meta.query_advice(a_4, Rotation::cur());
            let word = meta.query_advice(a_5, Rotation::cur());

            ScheduleGate::s_decompose_0(s_decompose_0, lo, hi, word)
        });

        MessageScheduleConfig {
            lookup,
            message_schedule,
            extras,
            s_decompose_0,
        }
    }

    #[allow(clippy::type_complexity)]
    pub(super) fn process(
        &self,
        layouter: &mut impl Layouter<pallas::Base>,
        input: [BlockWord; BLOCK_SIZE],
    ) -> Result<
        (
            [MessageWord; ROUNDS],
            [(AssignedBits<16>, AssignedBits<16>); ROUNDS],
        ),
        Error,
    > {
        let mut w = Vec::<MessageWord>::with_capacity(ROUNDS);
        let mut w_halves = Vec::<(AssignedBits<16>, AssignedBits<16>)>::with_capacity(ROUNDS);

        layouter.assign_region(
            || "process message block",
            |mut region| {
                w = Vec::<MessageWord>::with_capacity(ROUNDS);
                w_halves = Vec::<(AssignedBits<16>, AssignedBits<16>)>::with_capacity(ROUNDS);

                // Assign X[0..16]
                for (row, word) in input.iter().enumerate() {
                    self.s_decompose_0.enable(&mut region, row)?;
                    let (word, halves) = self.assign_word_and_halves(&mut region, word.0, row)?;
                    w.push(MessageWord(word));
                    w_halves.push(halves);
                }

                Ok(())
            },
        )?;

        Ok((w.try_into().unwrap(), w_halves.try_into().unwrap()))
    }
}