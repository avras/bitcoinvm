use crate::ripemd160::ref_impl::constants::{BLOCK_SIZE, MSG_SEL_IDX_LEFT, ROUND_PHASE_SIZE, ROL_AMOUNT_LEFT};
use super::super::{AssignedBits, StateWord, ROUND_CONSTANTS_LEFT};
use super::{compression_util::*, CompressionConfig, State, RoundWordDense};
use halo2::{circuit::Region, plonk::Error};
use halo2::halo2curves::pasta::pallas;

impl CompressionConfig {
    #[allow(clippy::many_single_char_names)]
    pub fn assign_left_round(
        &self,
        region: &mut Region<'_, pallas::Base>,
        round_idx: usize,
        state: State,
        message_word_halves: [(AssignedBits<16>, AssignedBits<16>); BLOCK_SIZE],
    ) -> Result<State, Error> {
        let (a, b, c, d, e ) = match_state(state);
        let mut row: usize = 0;

        // f1(B, C, D)
        let fout = self.assign_f1(
            region,
            row,
            b.clone().spread_halves,
            c.spread_halves,
            d.spread_halves,
        )?;
        row += 4; // f1 requires 4 rows

        // A + f1(B,C,D) + X[r(idx)] + K(idx/16)
        let x = RoundWordDense(
            message_word_halves[MSG_SEL_IDX_LEFT[round_idx]].clone().0,
            message_word_halves[MSG_SEL_IDX_LEFT[round_idx]].clone().1,
        );
        let sum_afxk = self.assign_sum_afxk(
            region,
            row,
            a,
            fout.into(),
            x,
            ROUND_CONSTANTS_LEFT[round_idx/ROUND_PHASE_SIZE],
        )?;
        row += 3; // sum_afxk requires 3 rows

        // rol = rol_s(j) ( A + f1(B,C,D) + X[r(idx)] + K(idx/16) )
        let rol_shift = ROL_AMOUNT_LEFT[round_idx];
        let rol = self.assign_rotate_left(
            region,
            row,
            sum_afxk,
            rol_shift,
        )?;
        row += 2; // rotate_left requires 2 rows

        // T = rol_s(j) ( A + f1(B,C,D) + X[r(idx)] + K(idx/16) ) + E
        let t = self.assign_sum_re(
            region,
            row,
            rol.into(),
            e.clone(),
        )?;
        row += 2; // sum_re requires 2 rows

        let rol10_c_dense = self.assign_rotate_left(
            region,
            row,
            c.dense_halves,
            10,
        )?;
        row += 2; // rotate_left requires 2 rows

        let rol10_c = self.assign_spread_dense_word(
            region,
            &self.lookup,
            row,
            rol10_c_dense,
        )?;
        //row += 2; // getting the spread version of rol10_c requires 2 rows

        Ok(State::new(
            StateWord::A(e),
            StateWord::B(t),
            StateWord::C(b),
            StateWord::D(rol10_c),
            StateWord::E(d.dense_halves),
        ))
    }
}