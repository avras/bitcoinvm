use crate::ripemd160::table16::{AssignedBits, util::{i2lebsp, even_bits, odd_bits}, spread_table::{SpreadInputs, SpreadVar, SpreadWord}};

use super::{CompressionConfig, RoundWordSpread};

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

}