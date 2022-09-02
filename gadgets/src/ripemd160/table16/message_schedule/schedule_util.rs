use super::super::AssignedBits;
use super::MessageScheduleConfig;

use halo2::{
    circuit::{Region, Value},
    plonk::Error,
};

use halo2::halo2curves::pasta::pallas;
use super::super::message_schedule::BLOCK_SIZE;


// Rows needed for each decompose gate
pub const DECOMPOSE_0_ROWS: usize = 2;

/// Returns row number of a word
pub fn get_word_row(word_idx: usize) -> usize {
    assert!(word_idx <= BLOCK_SIZE);
    word_idx * DECOMPOSE_0_ROWS
}

impl MessageScheduleConfig {
    // Assign a word and its hi and lo halves
    pub fn assign_word_and_halves(
        &self,
        region: &mut Region<'_, pallas::Base>,
        word: Value<u32>,
        word_idx: usize,
    ) -> Result<(AssignedBits<32>, (AssignedBits<16>, AssignedBits<16>)), Error> {
        // Rename these here for ease of matching the gates to the specification.
        let a_3 = self.extras[0];
        let a_4 = self.extras[1];

        let row = get_word_row(word_idx);

        let w_lo = {
            let w_lo_val = word.map(|word| word as u16);
            AssignedBits::<16>::assign(region, || format!("W_{}_lo", word_idx), a_3, row, w_lo_val)?
        };
        let w_hi = {
            let w_hi_val = word.map(|word| (word >> 16) as u16);
            AssignedBits::<16>::assign(region, || format!("W_{}_hi", word_idx), a_4, row, w_hi_val)?
        };

        let word = AssignedBits::<32>::assign(
            region,
            || format!("W_{}", word_idx),
            self.message_schedule,
            row,
            word,
        )?;

        Ok((word, (w_lo, w_hi)))
    }
}
