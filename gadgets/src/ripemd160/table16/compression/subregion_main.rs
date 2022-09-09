use crate::ripemd160::ref_impl::constants::{BLOCK_SIZE, MSG_SEL_IDX_LEFT, ROUND_PHASE_SIZE, ROL_AMOUNT_LEFT, MSG_SEL_IDX_RIGHT, ROUND_CONSTANTS_RIGHT, ROL_AMOUNT_RIGHT};
use super::super::{AssignedBits, StateWord, ROUND_CONSTANTS_LEFT};
use super::RoundSide::{self, Left, Right};
use super::{compression_util::*, CompressionConfig, State, RoundWordDense};
use halo2::{circuit::Region, plonk::Error};
use halo2::halo2curves::pasta::pallas;

impl CompressionConfig {
    #[allow(clippy::many_single_char_names)]
    pub fn assign_round(
        &self,
        region: &mut Region<'_, pallas::Base>,
        round_idx: usize,
        state: State,
        message_word_halves: [(AssignedBits<16>, AssignedBits<16>); BLOCK_SIZE],
        row: &mut usize,
        round_side: RoundSide,
    ) -> Result<State, Error> {
        let (a, b, c, d, e ) = match_state(state);

        let phase_idx = 1 + round_idx/ROUND_PHASE_SIZE;

        let fout =
        if (phase_idx == 1 && round_side == Left) || (phase_idx == 5 && round_side == Right) {
            // f1(B, C, D)
            let f1_out = self.assign_f1(
                region,
                *row,
                b.clone().spread_halves,
                c.spread_halves,
                d.spread_halves,
            )?;
            *row += 4; // f1 requires 4 rows
            f1_out
        } 
        else if (phase_idx == 2 && round_side == Left) || (phase_idx == 4 && round_side == Right) {
            // f2(B, C, D)
            let f2_out = self.assign_f2(
                region,
                *row,
                b.clone().spread_halves,
                c.spread_halves,
                d.spread_halves,
            )?;
            *row += 8; // f2 requires 8 rows
            f2_out
        } 
        else if phase_idx == 3 {
            // f3(B, C, D)
            let f3_out = self.assign_f3(
                region,
                *row,
                b.clone().spread_halves,
                c.spread_halves,
                d.spread_halves,
            )?;
            *row += 10; // f3 requires 10 rows
            f3_out
        } 
        else if (phase_idx == 4 && round_side == Left) || (phase_idx == 2 && round_side == Right) {
            // f4(B, C, D)
            let f4_out = self.assign_f4(
                region,
                *row,
                b.clone().spread_halves,
                c.spread_halves,
                d.spread_halves,
            )?;
            *row += 8; // f4 requires 8 rows
            f4_out
        } 
        else {
            // f5(B, C, D)
            let f5_out = self.assign_f5(
                region,
                *row,
                b.clone().spread_halves,
                c.spread_halves,
                d.spread_halves,
            )?;
            *row += 10; // f5 requires 10 rows
            f5_out
        };

        // A + f1(B,C,D) + X[r(idx)] + K(idx/16)
        let x = if round_side == Left {
            RoundWordDense(
                message_word_halves[MSG_SEL_IDX_LEFT[round_idx]].clone().0,
                message_word_halves[MSG_SEL_IDX_LEFT[round_idx]].clone().1,
            )
        }
        else {
            RoundWordDense(
                message_word_halves[MSG_SEL_IDX_RIGHT[round_idx]].clone().0,
                message_word_halves[MSG_SEL_IDX_RIGHT[round_idx]].clone().1,
            )
        };
        let sum_afxk = self.assign_sum_afxk(
            region,
            *row,
            a,
            fout.into(),
            x,
            if round_side == Left {
                ROUND_CONSTANTS_LEFT[phase_idx-1]
            } else {
                ROUND_CONSTANTS_RIGHT[phase_idx-1]
            },
        )?;
        *row += 3; // sum_afxk requires 3 rows

        // rol = rol_s(j) ( A + f1(B,C,D) + X[r(idx)] + K(idx/16) )
        let rol_shift = if round_side == Left {
          ROL_AMOUNT_LEFT[round_idx]
        }
        else {
          ROL_AMOUNT_RIGHT[round_idx]
        };
        
        let rol = self.assign_rotate_left(
            region,
            *row,
            sum_afxk,
            rol_shift,
        )?;
        *row += 2; // rotate_left requires 2 rows

        // T = rol_s(j) ( A + f1(B,C,D) + X[r(idx)] + K(idx/16) ) + E
        let t = self.assign_sum_re(
            region,
            *row,
            rol.into(),
            e.clone(),
        )?;
        *row += 2; // sum_re requires 2 rows

        let rol10_c_dense = self.assign_rotate_left(
            region,
            *row,
            c.dense_halves,
            10,
        )?;
        *row += 2; // rotate_left requires 2 rows

        let rol10_c = self.assign_spread_dense_word(
            region,
            &self.lookup,
            *row,
            rol10_c_dense,
        )?;
        *row += 2; // getting the spread version of rol10_c requires 2 rows

        Ok(State::new(
            StateWord::A(e),
            StateWord::B(t),
            StateWord::C(b),
            StateWord::D(rol10_c),
            StateWord::E(d.dense_halves),
        ))
    }
}