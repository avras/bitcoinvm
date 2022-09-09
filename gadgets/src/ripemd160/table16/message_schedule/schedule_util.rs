use std::fmt::format;

use crate::ripemd160::table16::{util::i2lebsp, spread_table::{SpreadWord, SpreadVar}, Table16Assignment};

use super::super::AssignedBits;
use super::MessageScheduleConfig;

use halo2::{
    circuit::{Region, Value},
    plonk::Error,
};

use halo2::halo2curves::pasta::pallas;
use super::super::message_schedule::BLOCK_SIZE;


// Rows needed for each decompose gate
pub const DECOMPOSE_WORD_ROWS: usize = 2;

/// Returns row number of a word
pub fn get_word_row(word_idx: usize) -> usize {
    assert!(word_idx <= BLOCK_SIZE);
    word_idx * DECOMPOSE_WORD_ROWS
}

impl MessageScheduleConfig {
    // Assign a word and its hi and lo halves
    pub fn assign_msgblk_word_and_halves(
        &self,
        region: &mut Region<'_, pallas::Base>,
        word: Value<u32>,
        word_idx: usize,
    ) -> Result<(AssignedBits<32>, (AssignedBits<16>, AssignedBits<16>)), Error> {
        // Rename these here for ease of matching the gates to the specification.
        let a_3 = self.advice[0];
        let a_4 = self.advice[1];
        let a_5 = self.advice[2];

        let row = get_word_row(word_idx);
        self.s_decompose_word.enable(region, row)?;

        let (word, (spread_var_lo, spread_var_hi)) =
        self.assign_word_and_halves(
            || format!("X_{}", row),
            region,
            &self.lookup,
            a_3,
            a_4,
            a_5,
            word,
            row
        )?;

        Ok((word, (spread_var_lo.dense, spread_var_hi.dense)))
    }
}
