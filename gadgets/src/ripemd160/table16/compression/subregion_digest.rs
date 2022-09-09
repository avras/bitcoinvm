use super::super::BlockWord;
use super::{CompressionConfig, State, DIGEST_SIZE};
use super::compression_util::*;
use halo2::{
    circuit::Region,
    plonk::Error, halo2curves::pasta::pallas,
};

impl CompressionConfig {
    #[allow(clippy::many_single_char_names)]
    pub fn assign_digest(
        &self,
        region: &mut Region<'_, pallas::Base>,
        state: State,
    ) -> Result<[BlockWord; DIGEST_SIZE], Error> {
        let (a, b, c, d, e) = match_state(state);

        let mut row: usize = 0;
        self.assign_decompose_0_dense(region, row, a.clone())?;
        row += 1;
        self.assign_decompose_0_dense(region, row, b.clone().dense_halves)?;
        row += 1;
        self.assign_decompose_0_dense(region, row, c.clone().dense_halves)?;
        row += 1;
        self.assign_decompose_0_dense(region, row, d.clone().dense_halves)?;
        row += 1;
        self.assign_decompose_0_dense(region, row, e.clone())?;

        Ok([
            BlockWord(a.value()),
            BlockWord(b.dense_halves.value()),
            BlockWord(c.dense_halves.value()),
            BlockWord(d.dense_halves.value()),
            BlockWord(e.value()),
        ])
    }
}