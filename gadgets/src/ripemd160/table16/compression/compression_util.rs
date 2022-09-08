use crate::ripemd160::ref_impl::helper_functions::rol;
use crate::ripemd160::table16::AssignedBits;
use crate::ripemd160::table16::spread_table::{SpreadInputs, SpreadVar, SpreadWord};
use crate::ripemd160::table16::util::{i2lebsp, even_bits, odd_bits, lebs2ip, negate_spread, sum_with_carry};

use super::{CompressionConfig, RoundWordSpread, RoundWordDense};

use halo2::{
    circuit::{Region, Value},
    plonk::{Advice, Column, Error},
};
use halo2::halo2curves::pasta::pallas;
use std::convert::TryInto;





impl CompressionConfig {

    // s_f1 | a_0 |   a_1    |       a_2       |    a_3      |    a_4      |    a_5      |
    //   1  |     | R_0_even | spread_R_0_even | spread_B_lo | spread_C_lo | spread_D_lo | 
    //      |     | R_0_odd  | spread_R_0_odd  | spread_B_hi | spread_C_hi | spread_D_hi | 
    //      |     | R_1_even | spread_R_1_even |             |             |             | 
    //      |     | R_1_odd  | spread_R_1_odd  |             |             |             | 
    // 
    pub(super) fn assign_f1(
        &self,
        region: &mut Region<'_, pallas::Base>,
        row: usize,
        spread_halves_b: RoundWordSpread,
        spread_halves_c: RoundWordSpread,
        spread_halves_d: RoundWordSpread,
    ) -> Result<(AssignedBits<16>, AssignedBits<16>), Error> {
        let a_3 = self.advice[0];
        let a_4 = self.advice[1];
        let a_5 = self.advice[2];
        
        self.s_f1.enable(region, row)?;

        // Assign and copy spread_b_lo, spread_b_hi
        spread_halves_b.0.copy_advice(|| "spread_b_lo", region, a_3, row)?;
        spread_halves_b.1.copy_advice(|| "spread_b_hi", region, a_3, row + 1)?;

        // Assign and copy spread_c_lo, spread_c_hi
        spread_halves_c.0.copy_advice(|| "spread_c_lo", region, a_4, row)?;
        spread_halves_c.1.copy_advice(|| "spread_c_hi", region, a_4, row + 1)?;

        // Assign and copy spread_d_lo, spread_d_hi
        spread_halves_d.0.copy_advice(|| "spread_d_lo", region, a_5, row)?;
        spread_halves_d.1.copy_advice(|| "spread_d_hi", region, a_5, row + 1)?;

        let m: Value<[bool; 64]> = spread_halves_b
            .value()
            .zip(spread_halves_c.value())
            .zip(spread_halves_d.value())
            .map(|((a, b), c)| i2lebsp(a + b + c));

        let r_0: Value<[bool; 32]> = m.map(|m| m[..32].try_into().unwrap());
        let r_0_even = r_0.map(even_bits);
        let r_0_odd = r_0.map(odd_bits);

        let r_1: Value<[bool; 32]> = m.map(|m| m[32..].try_into().unwrap());
        let r_1_even = r_1.map(even_bits);
        let r_1_odd = r_1.map(odd_bits);

        self.assign_f1_outputs(region, row, r_0_even, r_0_odd, r_1_even, r_1_odd)
    }

    fn assign_f1_outputs(
        &self,
        region: &mut Region<'_, pallas::Base>,
        row: usize,
        r_0_even: Value<[bool; 16]>,
        r_0_odd: Value<[bool; 16]>,
        r_1_even: Value<[bool; 16]>,
        r_1_odd: Value<[bool; 16]>,
    ) -> Result<(AssignedBits<16>, AssignedBits<16>), Error> {
        let (even, _odd) = self.assign_spread_outputs(
            region,
            &self.lookup,
            row,
            r_0_even,
            r_0_odd,
            r_1_even,
            r_1_odd,
        )?;

        Ok(even)
    }

    // s_f2f4 | a_0 |   a_1    |       a_2       |    a_3       |    a_4      |    a_5           |
    //   1    |     | P_0_even | spread_P_0_even | spread_X_lo  | spread_Y_lo |                  | 
    //        |     | P_0_odd  | spread_P_0_odd  | spread_X_hi  | spread_Y_hi |                  | 
    //        |     | P_1_even | spread_P_1_even |              |             |                  | 
    //        |     | P_1_odd  | spread_P_1_odd  |              |             |                  | 
    //        |     | Q_0_even | spread_Q_0_even |              | spread_Z_lo | spread_neg_X_lo  | 
    //        |     | Q_0_odd  | spread_Q_0_odd  |              | spread_Z_hi | spread_neg_X_hi  | 
    //        |     | Q_1_even | spread_Q_1_even | sum_lo       | carry       |                  | 
    //        |     | Q_1_odd  | spread_Q_1_odd  | sum_hi       |             |                  | 
    // 
    // Output is sum_lo, sum_hi
    pub(super) fn assign_f2(
        &self,
        region: &mut Region<'_, pallas::Base>,
        row: usize,
        spread_halves_x: RoundWordSpread,
        spread_halves_y: RoundWordSpread,
        spread_halves_z: RoundWordSpread,
    ) -> Result<(AssignedBits<16>, AssignedBits<16>), Error> {
        let a_3 = self.advice[0];
        let a_4 = self.advice[1];
        let a_5 = self.advice[2];

        self.s_f2f4.enable(region, row)?;

        // Assigning top four rows
        // Assign and copy spread_x_lo, spread_x_hi
        spread_halves_x.0.copy_advice(|| "spread_x_lo", region, a_3, row)?;
        spread_halves_x.1.copy_advice(|| "spread_x_hi", region, a_3, row + 1)?;

        // Assign and copy spread_y_lo, spread_y_hi
        spread_halves_y.0.copy_advice(|| "spread_y_lo", region, a_4, row)?;
        spread_halves_y.1.copy_advice(|| "spread_y_hi", region, a_4, row + 1)?;

        let p: Value<[bool; 64]> = spread_halves_x
            .value()
            .zip(spread_halves_y.value())
            .map(|(e, f)| i2lebsp(e + f));

        let p_0: Value<[bool; 32]> = p.map(|p| p[..32].try_into().unwrap());
        let p_0_even = p_0.map(even_bits);
        let p_0_odd = p_0.map(odd_bits);

        let p_1: Value<[bool; 32]> = p.map(|p| p[32..].try_into().unwrap());
        let p_1_even = p_1.map(even_bits);
        let p_1_odd = p_1.map(odd_bits);

        let p_odd_halves = self.assign_ch_outputs(region, row, p_0_even, p_0_odd, p_1_even, p_1_odd)?;

        // Assigning bottom four rows
        // Assign and copy spread_z_lo, spread_z_hi
        spread_halves_z.0.copy_advice(|| "spread_z_lo", region, a_4, row + 4)?;
        spread_halves_z.1.copy_advice(|| "spread_z_hi", region, a_4, row + 5)?;

        // Calculate neg_x_lo
        let spread_neg_x_lo = spread_halves_x
            .0
            .value()
            .map(|spread_x_lo| negate_spread(spread_x_lo.0));
        // Assign spread_neg_x_lo
        AssignedBits::<32>::assign_bits(
            region,
            || "spread_neg_x_lo",
            a_5,
            row + 4,
            spread_neg_x_lo,
        )?;

        // Calculate neg_x_hi
        let spread_neg_x_hi = spread_halves_x
            .1
            .value()
            .map(|spread_x_hi| negate_spread(spread_x_hi.0));
        // Assign spread_neg_x_hi
        AssignedBits::<32>::assign_bits(
            region,
            || "spread_neg_x_hi",
            a_5,
            row + 5,
            spread_neg_x_hi,
        )?;

        let q: Value<[bool; 64]> = {
            let spread_neg_x = spread_neg_x_lo
                .zip(spread_neg_x_hi)
                .map(|(lo, hi)| lebs2ip(&lo) + (1 << 32) * lebs2ip(&hi));
            spread_neg_x
                .zip(spread_halves_z.value())
                .map(|(neg_x, z)| i2lebsp(neg_x + z))
        };

        let q_0: Value<[bool; 32]> = q.map(|q| q[..32].try_into().unwrap());
        let q_0_even = q_0.map(even_bits);
        let q_0_odd = q_0.map(odd_bits);

        let q_1: Value<[bool; 32]> = q.map(|q| q[32..].try_into().unwrap());
        let q_1_even = q_1.map(even_bits);
        let q_1_odd = q_1.map(odd_bits);

        let q_odd_halves = self.assign_ch_outputs(region, row + 4, q_0_even, q_0_odd, q_1_even, q_1_odd)?;

        let (sum, carry) = sum_with_carry(vec![
            (p_odd_halves.0.value_u16(), p_odd_halves.1.value_u16()),
            (q_odd_halves.0.value_u16(), q_odd_halves.1.value_u16()),
        ]);
        
        let sum: Value<[bool; 32]> = sum.map(|w| i2lebsp(w.into()));
        let sum_lo: Value<[bool; 16]> = sum.map(|w| w[..16].try_into().unwrap());
        let sum_hi: Value<[bool; 16]> = sum.map(|w| w[16..].try_into().unwrap());

        let sum_lo = AssignedBits::<16>::assign_bits(region, || "sum_lo", a_3, row + 6, sum_lo)?;
        let sum_hi = AssignedBits::<16>::assign_bits(region, || "sum_hi", a_3, row + 7, sum_hi)?;

        region.assign_advice(
            || "f2f4_carry",
            a_4,
            row + 6,
            || carry.map(|value| pallas::Base::from(value as u64)),
        )?;

        Ok((sum_lo, sum_hi))
    }

    // s_f2f4 | a_0 |   a_1    |       a_2       |    a_3       |    a_4      |    a_5           |
    //   1    |     | P_0_even | spread_P_0_even | spread_Z_lo  | spread_X_lo |                  | 
    //        |     | P_0_odd  | spread_P_0_odd  | spread_Z_hi  | spread_X_hi |                  | 
    //        |     | P_1_even | spread_P_1_even |              |             |                  | 
    //        |     | P_1_odd  | spread_P_1_odd  |              |             |                  | 
    //        |     | Q_0_even | spread_Q_0_even |              | spread_Y_lo | spread_neg_Z_lo  | 
    //        |     | Q_0_odd  | spread_Q_0_odd  |              | spread_Y_hi | spread_neg_Z_hi  | 
    //        |     | Q_1_even | spread_Q_1_even | sum_lo       | carry       |                  | 
    //        |     | Q_1_odd  | spread_Q_1_odd  | sum_hi       |             |                  | 
    // 
    // Output is sum_lo, sum_hi
    pub(super) fn assign_f4(
        &self,
        region: &mut Region<'_, pallas::Base>,
        row: usize,
        spread_halves_x: RoundWordSpread,
        spread_halves_y: RoundWordSpread,
        spread_halves_z: RoundWordSpread,
    ) -> Result<(AssignedBits<16>, AssignedBits<16>), Error> {
        self.assign_f2(region, row, spread_halves_z, spread_halves_x, spread_halves_y)
    }

    fn assign_ch_outputs(
        &self,
        region: &mut Region<'_, pallas::Base>,
        row: usize,
        p_0_even: Value<[bool; 16]>,
        p_0_odd: Value<[bool; 16]>,
        p_1_even: Value<[bool; 16]>,
        p_1_odd: Value<[bool; 16]>,
    ) -> Result<(AssignedBits<16>, AssignedBits<16>), Error> {
        let (_even, odd) = self.assign_spread_outputs(
            region,
            &self.lookup,
            row,
            p_0_even,
            p_0_odd,
            p_1_even,
            p_1_odd,
        )?;

        Ok(odd)
    }

    // s_f3f5 | a_0 |   a_1       |       a_2         |    a_3          |    a_4      |    a_5      |
    //   1    |     | sum_0_even  | spread_sum_0_even | spread_neg_Y_lo | spread_X_lo | spread_Y_lo | 
    //        |     | sum_0_odd   | spread_sum_0_odd  | spread_neg_Y_hi | spread_X_hi | spread_Y_hi | 
    //        |     | sum_1_even  | spread_sum_1_even |                 |             |             | 
    //        |     | sum_1_odd   | spread_sum_1_odd  |                 |             |             | 
    //        |     | or_lo       | spread_or_lo      | spread_Z_lo     |             |             | 
    //        |     | or_hi       | spread_or_hi      | spread_Z_hi     |             |             | 
    //        |     | R_0_even    |                   |                 |             |             | 
    //        |     | R_0_odd     |                   |                 |             |             | 
    //        |     | R_1_even    |                   |                 |             |             | 
    //        |     | R_1_odd     |                   |                 |             |             | 
    //
    pub(super) fn assign_f3(
        &self,
        region: &mut Region<'_, pallas::Base>,
        row: usize,
        spread_halves_x: RoundWordSpread,
        spread_halves_y: RoundWordSpread,
        spread_halves_z: RoundWordSpread,
    ) -> Result<(AssignedBits<16>, AssignedBits<16>), Error> {
        let a_3 = self.advice[0];
        let a_4 = self.advice[1];
        let a_5 = self.advice[2];

        self.s_f3f5.enable(region, row)?;

        // Assign and copy spread_x_lo, spread_x_hi
        spread_halves_x.0.copy_advice(|| "spread_x_lo", region, a_4, row)?;
        spread_halves_x.1.copy_advice(|| "spread_x_hi", region, a_4, row + 1)?;

        // Assign and copy spread_y_lo, spread_y_hi
        spread_halves_y.0.copy_advice(|| "spread_y_lo", region, a_5, row)?;
        spread_halves_y.1.copy_advice(|| "spread_y_hi", region, a_5, row + 1)?;

        // Assign and copy spread_z_lo, spread_z_hi
        spread_halves_z.0.copy_advice(|| "spread_z_lo", region, a_3, row + 4)?;
        spread_halves_z.1.copy_advice(|| "spread_z_hi", region, a_3, row + 5)?;

        // Calculate neg_y_lo
        let spread_neg_y_lo = spread_halves_y
            .0
            .value()
            .map(|spread_y_lo| negate_spread(spread_y_lo.0));
        // Assign spread_neg_y_lo
        let assigned_neg_y_lo = AssignedBits::<32>::assign_bits(
            region,
            || "spread_neg_y_lo",
            a_3,
            row,
            spread_neg_y_lo,
        )?;

        // Calculate neg_y_hi
        let spread_neg_y_hi = spread_halves_y
            .1
            .value()
            .map(|spread_y_hi| negate_spread(spread_y_hi.0));
        // Assign spread_neg_y_hi
       let assigned_neg_y_hi = AssignedBits::<32>::assign_bits(
            region,
            || "spread_neg_y_hi",
            a_3,
            row + 1,
            spread_neg_y_hi,
        )?;
        let spread_halves_neg_y = RoundWordSpread::from((assigned_neg_y_lo, assigned_neg_y_hi));

        let sum: Value<[bool; 64]> = spread_halves_x
            .value()
            .zip(spread_halves_neg_y.value())
            .map(|(e, f)| i2lebsp(e + f));

        let sum_0: Value<[bool; 32]> = sum.map(|q| q[..32].try_into().unwrap());
        let sum_0_even = sum_0.map(even_bits);
        let sum_0_odd = sum_0.map(odd_bits);

        let sum_1: Value<[bool; 32]> = sum.map(|q| q[32..].try_into().unwrap());
        let sum_1_even = sum_1.map(even_bits);
        let sum_1_odd = sum_1.map(odd_bits);

        self.assign_spread_outputs(region, &self.lookup, row, sum_0_even, sum_0_odd, sum_1_even, sum_1_odd)?;

        let or: Value<[bool; 64]> =
            spread_halves_x.value()
                .zip(spread_halves_neg_y.value())
                .map(|(a, b)| a | b)
                .map(i2lebsp);

        let or_lo = or.map(|q| q[..32].try_into().unwrap()).map(even_bits::<32, 16>);
        let or_hi = or.map(|q| q[32..].try_into().unwrap()).map(even_bits::<32, 16>);

        self.assign_spread_word(region, &self.lookup, row + 4, or_lo, or_hi)?;

        let or_not_xor = or
            .map(|a| lebs2ip::<64>(&a))
            .zip(spread_halves_z.value())
            .map(|(a,b)| a + b)
            .map(i2lebsp::<64>);

        let or_not_xor_0: Value<[bool; 32]> = or_not_xor.map(|q| q[..32].try_into().unwrap());
        let or_not_xor_0_even = or_not_xor_0.map(even_bits);
        let or_not_xor_0_odd = or_not_xor_0.map(odd_bits);

        let or_not_xor_1: Value<[bool; 32]> = or_not_xor.map(|q| q[32..].try_into().unwrap());
        let or_not_xor_1_even = or_not_xor_1.map(even_bits);
        let or_not_xor_1_odd = or_not_xor_1.map(odd_bits);

        let (even, _odd) = self.assign_spread_outputs(
            region,
            &self.lookup,
            row + 6,
            or_not_xor_0_even,
            or_not_xor_0_odd,
            or_not_xor_1_even,
            or_not_xor_1_odd
        )?;

        Ok(even)
    }


    // The f5 gate is the same as the f3 gate with arguments (C, D, B) instead of (B, C, D)
    // f3(X, Y, Z) = (X | !Y) ^ Z  
    // f5(X, Y, Z) = X ^ (Y | !Z) = f3(Y, Z, X)
    pub(super) fn assign_f5(
        &self,
        region: &mut Region<'_, pallas::Base>,
        row: usize,
        spread_halves_x: RoundWordSpread,
        spread_halves_y: RoundWordSpread,
        spread_halves_z: RoundWordSpread,
    ) -> Result<(AssignedBits<16>, AssignedBits<16>), Error> {
        self.assign_f3(region, row, spread_halves_y, spread_halves_z, spread_halves_x)
    }

    // For shift = 5..9
    // s_rotate_left | a_0 |   a_1       | a_2 |  a_3 |    a_4  |    a_5      |
    //   1           |     | b(16-shift) |     | a_lo | word_lo | rol_word_lo | 
    //               |     | c(16)       |     | a_hi | word_hi | rol_word_hi | 
    // OR 
    // For shift = 9..13
    // s_rotate_left | a_0 |   a_1    | a_2 |  a_3 |    a_4  |    a_5      |
    //   1           |     | a(shift) |     | b_lo | word_lo | rol_word_lo | 
    //               |     | c(16)    |     | b_hi | word_hi | rol_word_hi | 
    // OR 
    // For shift = 13..16
    // s_rotate_left | a_0 |   a_1    | a_2 |  a_3 |    a_4  |    a_5      |
    //   1           |     | a(shift) |     |   b  | word_lo | rol_word_lo | 
    //               |     | c(16)    |     |      | word_hi | rol_word_hi | 
    pub(super) fn assign_rotate_left(
        &self,
        region: &mut Region<'_, pallas::Base>,
        row: usize,
        word: RoundWordDense,
        shift: u8,
    ) -> Result<(AssignedBits<16>, AssignedBits<16>), Error> {
        assert!(shift > 4 && shift < 16);
        let a_3 = self.advice[0];
        let a_4 = self.advice[1];
        let a_5 = self.advice[2];
        
        self.s_rotate_left[shift as usize - 5].enable(region, row)?;

        // Assign and copy word_lo, word_hi
        word.0.copy_advice(|| "word_lo", region, a_4, row)?;
        word.1.copy_advice(|| "word_hi", region, a_4, row + 1)?;
        
        let rol_word = word.value().map(|w| rol(w, shift)).map(|a| i2lebsp::<32>(a.into()));

        let rol_word_lo: Value<[bool; 16]> = rol_word.map(|q| q[..16].try_into().unwrap());
        let rol_word_hi: Value<[bool; 16]> = rol_word.map(|q| q[16..].try_into().unwrap());
        
        let rol_word_lo = AssignedBits::<16>::assign_bits(region, || "rol_word_lo", a_5, row, rol_word_lo)?;
        let rol_word_hi = AssignedBits::<16>::assign_bits(region, || "rol_word_hi", a_5, row + 1, rol_word_hi)?;

        let word_hi = word.1.value_u16().map(|a| i2lebsp::<16>(a.into()));
        let c: Value<[bool; 16]>= word.0.value_u16().map(|a| i2lebsp(a.into()).try_into().unwrap());

        if shift == 5 {
            let b: Value<[bool; 11]> = word_hi.map(|q| q[..11].try_into().unwrap());
            let b: Value<[bool; 16]> = b.map(|x| lebs2ip::<11>(&x)).map(|y| i2lebsp::<16>(y));
            let a_lo: Value<[bool; 2]> = word_hi.map(|q| q[11..13].try_into().unwrap());
            let a_hi: Value<[bool; 3]> = word_hi.map(|q| q[13..].try_into().unwrap());
            self.assign_spread_word(region, &self.lookup, row, b, c)?;

            AssignedBits::<2>::assign_bits(region, || "a_lo(2)", a_3, row, a_lo)?;
            AssignedBits::<3>::assign_bits(region, || "a_hi(3)", a_3, row + 1, a_hi)?;
        }
        else if shift == 6 {
            let b: Value<[bool; 10]> = word_hi.map(|q| q[..10].try_into().unwrap());
            let b: Value<[bool; 16]> = b.map(|x| lebs2ip::<10>(&x)).map(|y| i2lebsp::<16>(y));
            let a_lo: Value<[bool; 3]> = word_hi.map(|q| q[10..13].try_into().unwrap());
            let a_hi: Value<[bool; 3]> = word_hi.map(|q| q[13..].try_into().unwrap());
            self.assign_spread_word(region, &self.lookup, row, b, c)?;

            AssignedBits::<3>::assign_bits(region, || "a_lo(3)", a_3, row, a_lo)?;
            AssignedBits::<3>::assign_bits(region, || "a_hi(3)", a_3, row + 1, a_hi)?;
        }
        else if shift == 7 {
            let b: Value<[bool; 9]> = word_hi.map(|q| q[..9].try_into().unwrap());
            let b: Value<[bool; 16]> = b.map(|x| lebs2ip::<9>(&x)).map(|y| i2lebsp::<16>(y));
            let a_lo: Value<[bool; 3]> = word_hi.map(|q| q[9..12].try_into().unwrap());
            let a_hi: Value<[bool; 4]> = word_hi.map(|q| q[12..].try_into().unwrap());
            self.assign_spread_word(region, &self.lookup, row, b, c)?;

            AssignedBits::<3>::assign_bits(region, || "a_lo(3)", a_3, row, a_lo)?;
            AssignedBits::<4>::assign_bits(region, || "a_hi(4)", a_3, row + 1, a_hi)?;
        }
        else if shift == 8 {
            let b: Value<[bool; 8]> = word_hi.map(|q| q[..8].try_into().unwrap());
            let b: Value<[bool; 16]> = b.map(|x| lebs2ip::<8>(&x)).map(|y| i2lebsp::<16>(y));
            let a_lo: Value<[bool; 4]> = word_hi.map(|q| q[8..12].try_into().unwrap());
            let a_hi: Value<[bool; 4]> = word_hi.map(|q| q[12..].try_into().unwrap());
            self.assign_spread_word(region, &self.lookup, row, b, c)?;

            AssignedBits::<4>::assign_bits(region, || "a_lo(4)", a_3, row, a_lo)?;
            AssignedBits::<4>::assign_bits(region, || "a_hi(4)", a_3, row + 1, a_hi)?;
        }
        else if shift == 9 {
            let a: Value<[bool; 9]> = word_hi.map(|q| q[7..].try_into().unwrap());
            let a: Value<[bool; 16]> = a.map(|x| lebs2ip::<9>(&x)).map(|y| i2lebsp::<16>(y));
            let b_lo: Value<[bool; 3]> = word_hi.map(|q| q[0..3].try_into().unwrap());
            let b_hi: Value<[bool; 4]> = word_hi.map(|q| q[3..7].try_into().unwrap());
            self.assign_spread_word(region, &self.lookup, row, a, c)?;

            AssignedBits::<3>::assign_bits(region, || "b_lo(3)", a_3, row, b_lo)?;
            AssignedBits::<4>::assign_bits(region, || "b_hi(4)", a_3, row + 1, b_hi)?;
        }
        else if shift == 10 {
            let a: Value<[bool; 10]> = word_hi.map(|q| q[6..].try_into().unwrap());
            let a: Value<[bool; 16]> = a.map(|x| lebs2ip::<10>(&x)).map(|y| i2lebsp::<16>(y));
            let b_lo: Value<[bool; 3]> = word_hi.map(|q| q[0..3].try_into().unwrap());
            let b_hi: Value<[bool; 3]> = word_hi.map(|q| q[3..6].try_into().unwrap());
            self.assign_spread_word(region, &self.lookup, row, a, c)?;

            AssignedBits::<3>::assign_bits(region, || "b_lo(3)", a_3, row, b_lo)?;
            AssignedBits::<3>::assign_bits(region, || "b_hi(3)", a_3, row + 1, b_hi)?;
        }
        else if shift == 11 {
            let a: Value<[bool; 11]> = word_hi.map(|q| q[5..].try_into().unwrap());
            let a: Value<[bool; 16]> = a.map(|x| lebs2ip::<11>(&x)).map(|y| i2lebsp::<16>(y));
            let b_lo: Value<[bool; 2]> = word_hi.map(|q| q[0..2].try_into().unwrap());
            let b_hi: Value<[bool; 3]> = word_hi.map(|q| q[2..5].try_into().unwrap());
            self.assign_spread_word(region, &self.lookup, row, a, c)?;

            AssignedBits::<2>::assign_bits(region, || "b_lo(2)", a_3, row, b_lo)?;
            AssignedBits::<3>::assign_bits(region, || "b_hi(3)", a_3, row + 1, b_hi)?;
        }
        else if shift == 12 {
            let a: Value<[bool; 12]> = word_hi.map(|q| q[4..].try_into().unwrap());
            let a: Value<[bool; 16]> = a.map(|x| lebs2ip::<12>(&x)).map(|y| i2lebsp::<16>(y));
            let b_lo: Value<[bool; 2]> = word_hi.map(|q| q[0..2].try_into().unwrap());
            let b_hi: Value<[bool; 2]> = word_hi.map(|q| q[2..4].try_into().unwrap());
            self.assign_spread_word(region, &self.lookup, row, a, c)?;

            AssignedBits::<2>::assign_bits(region, || "b_lo(2)", a_3, row, b_lo)?;
            AssignedBits::<2>::assign_bits(region, || "b_hi(2)", a_3, row + 1, b_hi)?;
        }
        else if shift == 13 {
            let a: Value<[bool; 13]> = word_hi.map(|q| q[3..].try_into().unwrap());
            let a: Value<[bool; 16]> = a.map(|x| lebs2ip::<13>(&x)).map(|y| i2lebsp::<16>(y));
            let b: Value<[bool; 3]> = word_hi.map(|q| q[0..3].try_into().unwrap());
            self.assign_spread_word(region, &self.lookup, row, a, c)?;

            AssignedBits::<3>::assign_bits(region, || "b(3)", a_3, row, b)?;
        }
        else if shift == 14 {
            let a: Value<[bool; 14]> = word_hi.map(|q| q[2..].try_into().unwrap());
            let a: Value<[bool; 16]> = a.map(|x| lebs2ip::<14>(&x)).map(|y| i2lebsp::<16>(y));
            let b: Value<[bool; 2]> = word_hi.map(|q| q[0..2].try_into().unwrap());
            self.assign_spread_word(region, &self.lookup, row, a, c)?;

            AssignedBits::<2>::assign_bits(region, || "b(2)", a_3, row, b)?;
        }
        else {
            let a: Value<[bool; 15]> = word_hi.map(|q| q[1..].try_into().unwrap());
            let a: Value<[bool; 16]> = a.map(|x| lebs2ip::<15>(&x)).map(|y| i2lebsp::<16>(y));
            let b: Value<[bool; 1]> = word_hi.map(|q| q[0..1].try_into().unwrap());
            self.assign_spread_word(region, &self.lookup, row, a, c)?;

            AssignedBits::<1>::assign_bits(region, || "b(1)", a_3, row, b)?;
        };

        Ok((rol_word_lo, rol_word_hi))
    }

    // s_sum1 | a_0 |   a_1  |       a_2     | a_3  | a_4  | a_5   |
    //   1    |     | sum_lo | spread_sum_lo | a_lo | f_lo | x_lo  | 
    //        |     | sum_hi | spread_sum_hi | a_hi | f_hi | x_hi  | 
    //        |     |        |               | k_lo | k_hi | carry |
    //
    pub(super) fn assign_sum_afxk(
        &self,
        region: &mut Region<'_, pallas::Base>,
        row: usize,
        a: RoundWordDense,
        f: RoundWordDense,
        x: RoundWordDense,
        k: u32,
    ) -> Result<RoundWordDense, Error> {
        let a_3 = self.advice[0];
        let a_4 = self.advice[1];
        let a_5 = self.advice[2];


        // Assign and copy a_lo, a_hi
        a.0.copy_advice(|| "a_lo", region, a_3, row)?;
        a.1.copy_advice(|| "a_hi", region, a_3, row + 1)?;
        
        // Assign and copy f_lo, f_hi
        f.0.copy_advice(|| "f_lo", region, a_4, row)?;
        f.1.copy_advice(|| "f_hi", region, a_4, row + 1)?;

        // Assign and copy x_lo, x_hi
        x.0.copy_advice(|| "x_lo", region, a_5, row)?;
        x.1.copy_advice(|| "x_hi", region, a_5, row + 1)?;
        
        // Assign k
        let k: [bool; 32] = i2lebsp(k.into());
        let k_lo: [bool; 16] = k[..16].try_into().unwrap();
        let k_hi: [bool; 16] = k[16..].try_into().unwrap();
        AssignedBits::<16>::assign_bits(region, || "k_lo", a_3, row + 2, Value::known(k_lo))?;
        AssignedBits::<16>::assign_bits(region, || "k_hi", a_4, row + 2, Value::known(k_hi))?;
        
        let (sum, carry) = sum_with_carry(vec![
            (a.0.value_u16(), a.1.value_u16()),
            (f.0.value_u16(), f.1.value_u16()),
            (x.0.value_u16(), x.1.value_u16()),
            (
                Value::known(lebs2ip(&k_lo) as u16),
                Value::known(lebs2ip(&k_hi) as u16),
            ),
        ]);

        region.assign_advice(
            || "sum_afxk_carry",
            a_5,
            row + 2,
            || carry.map(|value| pallas::Base::from(value as u64)),
        )?;

        let sum: Value<[bool; 32]> = sum.map(|w| i2lebsp(w.into()));
        let sum_lo: Value<[bool; 16]> = sum.map(|w| w[..16].try_into().unwrap());
        let sum_hi: Value<[bool; 16]> = sum.map(|w| w[16..].try_into().unwrap());

        let (dense, _spread) = self.assign_spread_word(region, &self.lookup, row, sum_lo, sum_hi)?;

        Ok(dense.into())
    }

    // s_sum1 | a_0 |   a_1  |       a_2     | a_3    | a_4  | a_5   |
    //   1    |     | sum_lo | spread_sum_lo | rol_lo | e_lo | carry | 
    //        |     | sum_hi | spread_sum_hi | rol_hi | e_hi |       |
    //
    pub(super) fn assign_sum_re(
        &self,
        region: &mut Region<'_, pallas::Base>,
        row: usize,
        rol: RoundWordDense,
        e: RoundWordDense,
    ) -> Result<RoundWordDense, Error> {
        let a_3 = self.advice[0];
        let a_4 = self.advice[1];
        let a_5 = self.advice[2];


        // Assign and copy a_lo, a_hi
        rol.0.copy_advice(|| "rol_lo", region, a_3, row)?;
        rol.1.copy_advice(|| "rol_hi", region, a_3, row + 1)?;
        
        // Assign and copy f_lo, f_hi
        e.0.copy_advice(|| "e_lo", region, a_4, row)?;
        e.1.copy_advice(|| "e_hi", region, a_4, row + 1)?;

        let (sum, carry) = sum_with_carry(vec![
            (rol.0.value_u16(), rol.1.value_u16()),
            (e.0.value_u16(), e.1.value_u16()),
        ]);

        region.assign_advice(
            || "sum_re_carry",
            a_5,
            row,
            || carry.map(|value| pallas::Base::from(value as u64)),
        )?;

        let sum: Value<[bool; 32]> = sum.map(|w| i2lebsp(w.into()));
        let sum_lo: Value<[bool; 16]> = sum.map(|w| w[..16].try_into().unwrap());
        let sum_hi: Value<[bool; 16]> = sum.map(|w| w[16..].try_into().unwrap());

        let (dense, _spread) = self.assign_spread_word(region, &self.lookup, row, sum_lo, sum_hi)?;

        Ok(dense.into())
    }

    //          | a_0 |   a_1    |       a_2       |
    // row      |     | R_0_even | spread_R_0_even | 
    // row + 1  |     | R_0_odd  | spread_R_0_odd  | 
    // row + 2  |     | R_1_even | spread_R_1_even | 
    // row + 3  |     | R_1_odd  | spread_R_1_odd  | 
    // 
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn assign_spread_outputs(
        &self,
        region: &mut Region<'_, pallas::Base>,
        lookup: &SpreadInputs,
        row: usize,
        r_0_even: Value<[bool; 16]>,
        r_0_odd: Value<[bool; 16]>,
        r_1_even: Value<[bool; 16]>,
        r_1_odd: Value<[bool; 16]>,
    ) -> Result<
        (
            (AssignedBits<16>, AssignedBits<16>),
            (AssignedBits<16>, AssignedBits<16>),
        ),
        Error,
    > {
        // Lookup R_0^{even}, R_0^{odd}, R_1^{even}, R_1^{odd}
        let r_0_even = SpreadVar::with_lookup(
            region,
            lookup,
            row,
            r_0_even.map(SpreadWord::<16, 32>::new),
        )?;
        let r_0_odd = SpreadVar::with_lookup(
            region,
            lookup,
            row + 1,
            r_0_odd.map(SpreadWord::<16, 32>::new),
        )?;
        let r_1_even = SpreadVar::with_lookup(
            region,
            lookup,
            row + 2,
            r_1_even.map(SpreadWord::<16, 32>::new),
        )?;
        let r_1_odd = SpreadVar::with_lookup(
            region,
            lookup,
            row + 3,
            r_1_odd.map(SpreadWord::<16, 32>::new),
        )?;

        Ok((
            (r_0_even.dense, r_1_even.dense),
            (r_0_odd.dense, r_1_odd.dense),
        ))
    }

    //          | a_0 | a_1    |     a_2     |
    // row      |     | R_0    | spread_R_0  | 
    // row + 1  |     | R_1    | spread_R_1  | 
    // 
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::type_complexity)]
    fn assign_spread_word(
        &self,
        region: &mut Region<'_, pallas::Base>,
        lookup: &SpreadInputs,
        row: usize,
        r_lo: Value<[bool; 16]>,
        r_hi: Value<[bool; 16]>,
    ) -> Result<
        (
            (AssignedBits<16>, AssignedBits<16>),
            (AssignedBits<32>, AssignedBits<32>),
        ),
            Error,
    > 
    {
        // Lookup R_lo, R_hi
        let r_lo_var = SpreadVar::with_lookup(
            region,
            lookup,
            row,
            r_lo.map(SpreadWord::<16, 32>::new),
        )?;
        let r_hi_var = SpreadVar::with_lookup(
            region,
            lookup,
            row + 1,
            r_hi.map(SpreadWord::<16, 32>::new),
        )?;

        Ok((
            (r_lo_var.dense, r_hi_var.dense),
            (r_lo_var.spread, r_hi_var.spread),
        ))
    }

    pub(super) fn assign_decompose_0(
        &self,
        region: &mut Region<'_, pallas::Base>,
        row: usize,
        word_lo: AssignedBits<16>,
        word_hi: AssignedBits<16>,
        word: Value<u32>,
    ) -> Result<(), Error> {
        let a_3 = self.advice[0];
        let a_4 = self.advice[1];
        let a_5 = self.advice[2];

        self.s_decompose_0.enable(region, row)?;

        AssignedBits::<32>::assign(
            region,
            || "word(u32)",
            a_5,
            row,
            word,
        )?;

        word_lo.copy_advice(|| "word_lo", region, a_3, row)?;
        word_hi.copy_advice(|| "word_hi", region, a_4, row)?;

        Ok(())
    }

}