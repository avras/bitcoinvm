use self::compression_gates::CompressionGate;

use super::{
    AssignedBits, BlockWord, SpreadInputs, SpreadVar, Table16Assignment, ROUNDS, DIGEST_SIZE, NUM_ADVICE_COLS,
};
use super::util::{i2lebsp, lebs2ip};
use super::gates::Gate;
use halo2::halo2curves::FieldExt;
use halo2::plonk::{Expression, Constraints};
use halo2::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use halo2::halo2curves::pasta::{pallas, Fp};
use std::convert::TryInto;
use std::ops::Range;

mod compression_gates;
mod compression_util;
// mod subregion_digest;
// mod subregion_initial;
// mod subregion_main;

// use compression_gates::CompressionGate;

#[derive(Clone, Debug)]
pub struct RoundWordDense(AssignedBits<16>, AssignedBits<16>);

impl From<(AssignedBits<16>, AssignedBits<16>)> for RoundWordDense {
    fn from(halves: (AssignedBits<16>, AssignedBits<16>)) -> Self {
        Self(halves.0, halves.1)
    }
}

impl RoundWordDense {
    pub fn value(&self) -> Value<u32> {
        self.0
            .value_u16()
            .zip(self.1.value_u16())
            .map(|(lo, hi)| lo as u32 + (1 << 16) * hi as u32)
    }
}

#[derive(Clone, Debug)]
pub struct RoundWordSpread(AssignedBits<32>, AssignedBits<32>);

impl From<(AssignedBits<32>, AssignedBits<32>)> for RoundWordSpread {
    fn from(halves: (AssignedBits<32>, AssignedBits<32>)) -> Self {
        Self(halves.0, halves.1)
    }
}

impl RoundWordSpread {
    pub fn value(&self) -> Value<u64> {
        self.0
            .value_u32()
            .zip(self.1.value_u32())
            .map(|(lo, hi)| lo as u64 + (1 << 32) * hi as u64)
    }
}

#[derive(Clone, Debug)]
pub(super) struct CompressionConfig {
    lookup: SpreadInputs,
    advice: [Column<Advice>; NUM_ADVICE_COLS],

    s_decompose_0: Selector,
    s_f1: Selector,
    s_f2f4: Selector,
    s_ch: Selector,
    s_ch_neg: Selector,
    s_or_not_xor: Selector,
    s_rotate_left: [Selector; 11], // Rotate left with shifts from 5 to 15 (inclusive)
    s_sum_afxk: Selector,
    s_sum_re: Selector,
}

impl Table16Assignment for CompressionConfig {}

impl CompressionConfig {
    pub(super) fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        lookup: SpreadInputs,
        advice: [Column<Advice>; NUM_ADVICE_COLS],
        s_decompose_0: Selector, 
    ) -> Self {
        let s_f1 = meta.selector();
        let s_f2f4 = meta.selector();
        let s_ch = meta.selector();
        let s_ch_neg = meta.selector();
        let s_or_not_xor = meta.selector();
        let s_rotate_left = [
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
            meta.selector(),
        ];
        let s_sum_afxk = meta.selector();
        let s_sum_re = meta.selector();

        // Rename these here for ease of matching the gates to the specification.
        let a_0 = lookup.tag;
        let a_1 = lookup.dense;
        let a_2 = lookup.spread;
        let a_3 = advice[0];
        let a_4 = advice[1];
        let a_5 = advice[2];

        // s_decompose_0 for all words
        meta.create_gate("s_decompose_0", |meta| {
            let s_decompose_0 = meta.query_selector(s_decompose_0);
            let lo = meta.query_advice(a_3, Rotation::cur());
            let hi = meta.query_advice(a_4, Rotation::cur());
            let word = meta.query_advice(a_5, Rotation::cur());

            Gate::s_decompose_0(s_decompose_0, lo, hi, word)
        });

        // s_f1 on b, c, d words
        meta.create_gate("s_f1", |meta| {
            let s_f1 = meta.query_selector(s_f1);
            let spread_r0_even = meta.query_advice(a_2, Rotation(0));
            let spread_r0_odd  = meta.query_advice(a_2, Rotation(1));
            let spread_r1_even = meta.query_advice(a_2, Rotation(2));
            let spread_r1_odd  = meta.query_advice(a_2, Rotation(3));
            let spread_b_lo = meta.query_advice(a_3, Rotation::cur());
            let spread_b_hi = meta.query_advice(a_3, Rotation::next());
            let spread_c_lo = meta.query_advice(a_4, Rotation::cur());
            let spread_c_hi = meta.query_advice(a_4, Rotation::next());
            let spread_d_lo = meta.query_advice(a_5, Rotation::cur());
            let spread_d_hi = meta.query_advice(a_5, Rotation::next());
            
            CompressionGate::f1_gate(
                s_f1,
                spread_r0_even,
                spread_r0_odd,
                spread_r1_even,
                spread_r1_odd,
                spread_b_lo,
                spread_b_hi,
                spread_c_lo,
                spread_c_hi,
                spread_d_lo,
                spread_d_hi
            )
        });

        // s_f2 on b, c, d words
        // The f4 gate is the same as the f2 gate with arguments (D, B, C) instead of (B, C, D)
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
        meta.create_gate("s_f2f4", |meta| {
            let s_f2f4 = meta.query_selector(s_f2f4);
            let spread_p0_even = meta.query_advice(a_2, Rotation(0));
            let spread_p0_odd  = meta.query_advice(a_2, Rotation(1));
            let p0_odd  = meta.query_advice(a_1, Rotation(1));
            let spread_p1_even = meta.query_advice(a_2, Rotation(2));
            let spread_p1_odd  = meta.query_advice(a_2, Rotation(3));
            let p1_odd  = meta.query_advice(a_1, Rotation(3));
            let spread_q0_even = meta.query_advice(a_2, Rotation(4));
            let spread_q0_odd  = meta.query_advice(a_2, Rotation(5));
            let q0_odd  = meta.query_advice(a_1, Rotation(5));
            let spread_q1_even = meta.query_advice(a_2, Rotation(6));
            let spread_q1_odd  = meta.query_advice(a_2, Rotation(7));
            let q1_odd  = meta.query_advice(a_1, Rotation(7));
            let spread_b_lo = meta.query_advice(a_3, Rotation::cur());
            let spread_b_hi = meta.query_advice(a_3, Rotation::next());
            let spread_c_lo = meta.query_advice(a_4, Rotation::cur());
            let spread_c_hi = meta.query_advice(a_4, Rotation::next());
            let spread_d_lo = meta.query_advice(a_4, Rotation(4));
            let spread_d_hi = meta.query_advice(a_4, Rotation(5));
            let spread_b_neg_lo = meta.query_advice(a_5, Rotation(4));
            let spread_b_neg_hi = meta.query_advice(a_5, Rotation(5));
            let sum_lo = meta.query_advice(a_3, Rotation(6));
            let sum_hi = meta.query_advice(a_3, Rotation(7));
            let carry = meta.query_advice(a_4, Rotation(6));
            
            
            CompressionGate::f2_gate(
                s_f2f4,
                spread_p0_even,
                spread_p0_odd,
                spread_p1_even,
                spread_p1_odd,
                p0_odd,
                p1_odd,
                spread_q0_even,
                spread_q0_odd,
                spread_q1_even,
                spread_q1_odd,
                q0_odd,
                q1_odd,
                spread_b_lo,
                spread_b_hi,
                spread_c_lo,
                spread_c_hi,
                spread_d_lo,
                spread_d_hi,
                spread_b_neg_lo,
                spread_b_neg_hi,
                sum_lo,
                sum_hi,
                carry,
            )
        });
        
        // s_ch on b, c words
        meta.create_gate("s_ch", |meta| {
            let s_ch = meta.query_selector(s_ch);
            let spread_p0_even = meta.query_advice(a_2, Rotation(0));
            let spread_p0_odd  = meta.query_advice(a_2, Rotation(1));
            let spread_p1_even = meta.query_advice(a_2, Rotation(2));
            let spread_p1_odd  = meta.query_advice(a_2, Rotation(3));
            let spread_b_lo = meta.query_advice(a_3, Rotation::cur());
            let spread_b_hi = meta.query_advice(a_3, Rotation::next());
            let spread_c_lo = meta.query_advice(a_4, Rotation::cur());
            let spread_c_hi = meta.query_advice(a_4, Rotation::next());
            
            CompressionGate::ch_gate(
                s_ch,
                spread_p0_even,
                spread_p0_odd,
                spread_p1_even,
                spread_p1_odd,
                spread_b_lo,
                spread_b_hi,
                spread_c_lo,
                spread_c_hi,
            )
        });


        // s_ch_neg on b, d words
        meta.create_gate("s_ch_neg", |meta| {
            let s_ch_neg = meta.query_selector(s_ch_neg);
            let spread_q0_even = meta.query_advice(a_2, Rotation(0));
            let spread_q0_odd  = meta.query_advice(a_2, Rotation(1));
            let spread_q1_even = meta.query_advice(a_2, Rotation(2));
            let spread_q1_odd  = meta.query_advice(a_2, Rotation(3));
            let spread_b_lo = meta.query_advice(a_3, Rotation::cur());
            let spread_b_hi = meta.query_advice(a_3, Rotation::next());
            let spread_d_lo = meta.query_advice(a_4, Rotation::cur());
            let spread_d_hi = meta.query_advice(a_4, Rotation::next());
            let spread_b_neg_lo = meta.query_advice(a_5, Rotation::cur());
            let spread_b_neg_hi = meta.query_advice(a_5, Rotation::next());
            
            CompressionGate::ch_neg_gate(
                s_ch_neg,
                spread_q0_even,
                spread_q0_odd,
                spread_q1_even,
                spread_q1_odd,
                spread_b_lo,
                spread_b_hi,
                spread_b_neg_lo,
                spread_b_neg_hi,
                spread_d_lo,
                spread_d_hi,
            )
        });

        // s_or_not_xor on b, c, d words
        // (b | !c) ^ d
        meta.create_gate("s_or_not_xor", |meta| {
            let s_or_not_xor = meta.query_selector(s_or_not_xor);
            let spread_sum0_even = meta.query_advice(a_2, Rotation(0));
            let spread_sum0_odd  = meta.query_advice(a_2, Rotation(1));
            let spread_sum1_even = meta.query_advice(a_2, Rotation(2));
            let spread_sum1_odd  = meta.query_advice(a_2, Rotation(3));
            let spread_or_lo = meta.query_advice(a_2, Rotation(4));
            let spread_or_hi = meta.query_advice(a_2, Rotation(5));
            let spread_r0_even = meta.query_advice(a_2, Rotation(6));
            let spread_r0_odd  = meta.query_advice(a_2, Rotation(7));
            let spread_r1_even = meta.query_advice(a_2, Rotation(8));
            let spread_r1_odd  = meta.query_advice(a_2, Rotation(9));
            let spread_c_neg_lo = meta.query_advice(a_3, Rotation::cur());
            let spread_c_neg_hi = meta.query_advice(a_3, Rotation::next());
            let spread_b_lo = meta.query_advice(a_4, Rotation::cur());
            let spread_b_hi = meta.query_advice(a_4, Rotation::next());
            let spread_c_lo = meta.query_advice(a_5, Rotation::cur());
            let spread_c_hi = meta.query_advice(a_5, Rotation::next());
            let spread_d_lo = meta.query_advice(a_3, Rotation(4));
            let spread_d_hi = meta.query_advice(a_3, Rotation(5));
            
            CompressionGate::or_not_xor_gate(
                s_or_not_xor,
                spread_r0_even,
                spread_r0_odd,
                spread_r1_even,
                spread_r1_odd,
                spread_or_lo,
                spread_or_hi,
                spread_sum0_even,
                spread_sum0_odd,
                spread_sum1_even,
                spread_sum1_odd,
                spread_b_lo,
                spread_b_hi,
                spread_c_lo,
                spread_c_hi,
                spread_c_neg_lo,
                spread_c_neg_hi,
                spread_d_lo,
                spread_d_hi,
            )
        });

        meta.create_gate("rotate_left_5", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[0]);
            let tag_b = meta.query_advice(a_0, Rotation::cur());
            let b = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let a_lo = meta.query_advice(a_3, Rotation::cur());
            let a_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());
            
            CompressionGate::rotate_left_5_gate(
                s_rotate_left,
                a_lo,
                a_hi,
                b,
                tag_b,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });
        
        meta.create_gate("rotate_left_6", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[1]);
            let tag_b = meta.query_advice(a_0, Rotation::cur());
            let b = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let a_lo = meta.query_advice(a_3, Rotation::cur());
            let a_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());
            
            CompressionGate::rotate_left_6_gate(
                s_rotate_left,
                a_lo,
                a_hi,
                b,
                tag_b,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });
        
        meta.create_gate("rotate_left_7", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[2]);
            let tag_b = meta.query_advice(a_0, Rotation::cur());
            let b = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let a_lo = meta.query_advice(a_3, Rotation::cur());
            let a_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());
            
            CompressionGate::rotate_left_7_gate(
                s_rotate_left,
                a_lo,
                a_hi,
                b,
                tag_b,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });
        
        meta.create_gate("rotate_left_8", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[3]);
            let tag_b = meta.query_advice(a_0, Rotation::cur());
            let b = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let a_lo = meta.query_advice(a_3, Rotation::cur());
            let a_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());
            
            CompressionGate::rotate_left_8_gate(
                s_rotate_left,
                a_lo,
                a_hi,
                b,
                tag_b,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });
        
        meta.create_gate("s_rotate_left_9", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[4]);
            let tag_a = meta.query_advice(a_0, Rotation::cur());
            let a = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let b_lo = meta.query_advice(a_3, Rotation::cur());
            let b_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());
            
            CompressionGate::rotate_left_9_gate(
                s_rotate_left,
                a,
                tag_a,
                b_lo,
                b_hi,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        meta.create_gate("s_rotate_left_10", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[5]);
            let tag_a = meta.query_advice(a_0, Rotation::cur());
            let a = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let b_lo = meta.query_advice(a_3, Rotation::cur());
            let b_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());
            
            CompressionGate::rotate_left_10_gate(
                s_rotate_left,
                a,
                tag_a,
                b_lo,
                b_hi,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        meta.create_gate("s_rotate_left_11", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[6]);
            let tag_a = meta.query_advice(a_0, Rotation::cur());
            let a = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let b_lo = meta.query_advice(a_3, Rotation::cur());
            let b_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());
            
            CompressionGate::rotate_left_11_gate(
                s_rotate_left,
                a,
                tag_a,
                b_lo,
                b_hi,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        meta.create_gate("s_rotate_left_12", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[7]);
            let tag_a = meta.query_advice(a_0, Rotation::cur());
            let a = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let b_lo = meta.query_advice(a_3, Rotation::cur());
            let b_hi = meta.query_advice(a_3, Rotation::next());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());
            
            CompressionGate::rotate_left_12_gate(
                s_rotate_left,
                a,
                tag_a,
                b_lo,
                b_hi,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        meta.create_gate("s_rotate_left_13", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[8]);
            let tag_a = meta.query_advice(a_0, Rotation::cur());
            let a = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let b = meta.query_advice(a_3, Rotation::cur());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());
            
            CompressionGate::rotate_left_13_gate(
                s_rotate_left,
                a,
                tag_a,
                b,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        meta.create_gate("s_rotate_left_14", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[9]);
            let tag_a = meta.query_advice(a_0, Rotation::cur());
            let a = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let b = meta.query_advice(a_3, Rotation::cur());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());
            
            CompressionGate::rotate_left_14_gate(
                s_rotate_left,
                a,
                tag_a,
                b,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        meta.create_gate("s_rotate_left_15", |meta| {
            let s_rotate_left = meta.query_selector(s_rotate_left[10]);
            let tag_a = meta.query_advice(a_0, Rotation::cur());
            let a = meta.query_advice(a_1, Rotation::cur());
            let c = meta.query_advice(a_1, Rotation::next());
            let b = meta.query_advice(a_3, Rotation::cur());
            let word_lo = meta.query_advice(a_4, Rotation::cur());
            let word_hi = meta.query_advice(a_4, Rotation::next());
            let rol_word_lo = meta.query_advice(a_5, Rotation::cur());
            let rol_word_hi = meta.query_advice(a_5, Rotation::next());
            
            CompressionGate::rotate_left_15_gate(
                s_rotate_left,
                a,
                tag_a,
                b,
                c,
                word_lo,
                word_hi,
                rol_word_lo,
                rol_word_hi,
            )
        });

        meta.create_gate("s_sum_afxk", |meta| {
            let s_sum_afxk = meta.query_selector(s_sum_afxk);
            let sum_lo = meta.query_advice(a_1, Rotation::cur());
            let sum_hi = meta.query_advice(a_1, Rotation::next());
            let a_lo = meta.query_advice(a_3, Rotation::cur());
            let a_hi = meta.query_advice(a_3, Rotation::next());
            let f_lo = meta.query_advice(a_4, Rotation::cur());
            let f_hi = meta.query_advice(a_4, Rotation::next());
            let x_lo = meta.query_advice(a_5, Rotation::cur());
            let x_hi = meta.query_advice(a_5, Rotation::next());

            let k_lo = meta.query_advice(a_3, Rotation(2));
            let k_hi = meta.query_advice(a_4, Rotation(2));
            let carry = meta.query_advice(a_5, Rotation(2));
            
            CompressionGate::sum_afxk_gate(
                s_sum_afxk,
                sum_lo,
                sum_hi,
                carry,
                a_lo,
                a_hi,
                f_lo,
                f_hi,
                x_lo,
                x_hi,
                k_lo,
                k_hi,
            )
        });

        meta.create_gate("s_sum_re", |meta| {
            let s_sum_re = meta.query_selector(s_sum_re);
            let sum_lo = meta.query_advice(a_1, Rotation::cur());
            let sum_hi = meta.query_advice(a_1, Rotation::next());
            let rol_lo = meta.query_advice(a_3, Rotation::cur());
            let rol_hi = meta.query_advice(a_3, Rotation::next());
            let e_lo = meta.query_advice(a_4, Rotation::cur());
            let e_hi = meta.query_advice(a_4, Rotation::next());
            let carry = meta.query_advice(a_5, Rotation::cur());
            
            CompressionGate::sum_re_gate(
                s_sum_re,
                sum_lo,
                sum_hi,
                carry,
                rol_lo,
                rol_hi,
                e_lo,
                e_hi,
            )
        });


        CompressionConfig {
            lookup,
            advice,
            s_decompose_0,
            s_f1,
            s_f2f4,
            s_ch,
            s_ch_neg,
            s_or_not_xor,
            s_rotate_left,
            s_sum_afxk,
            s_sum_re,
        }
    }
    
}