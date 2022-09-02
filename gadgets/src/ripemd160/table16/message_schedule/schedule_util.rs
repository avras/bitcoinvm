use crate::ripemd160::table16::{util::i2lebsp, spread_table::{SpreadWord, SpreadVar}};

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

        let x_lo_val = word.map(|word| word as u16);
        let x_lo_bvec: Value<[bool; 16]> = x_lo_val.map(|x| i2lebsp(x.into()));
        let spread_x_lo = x_lo_bvec.map(SpreadWord::<16,32>::new);
        let spread_x_lo = SpreadVar::with_lookup(region, &self.lookup, row, spread_x_lo)?;
        spread_x_lo.dense.copy_advice(|| format!("X_{}_lo", word_idx), region, a_3, row)?;

        let x_hi_val = word.map(|word| (word >> 16) as u16);
        let x_hi_bvec: Value<[bool; 16]> = x_hi_val.map(|x| i2lebsp(x.into()));
        let spread_x_hi = x_hi_bvec.map(SpreadWord::<16,32>::new);
        let spread_x_hi = SpreadVar::with_lookup(region, &self.lookup, row+1, spread_x_hi)?;
        spread_x_hi.dense.copy_advice(|| format!("X_{}_hi", word_idx), region, a_4, row)?;

        let word = AssignedBits::<32>::assign(
            region,
            || format!("X_{}", word_idx),
            self.message_schedule,
            row,
            word,
        )?;

        Ok((word, (spread_x_lo.dense, spread_x_hi.dense)))
    }
}
