use self::compression_gates::CompressionGate;

use super::{
    AssignedBits, BlockWord, SpreadInputs, SpreadVar, Table16Assignment, ROUNDS, DIGEST_SIZE, NUM_ADVICE_COLS,
};
use super::util::{i2lebsp, lebs2ip};
use super::gates::Gate;
use halo2::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use halo2::halo2curves::pasta::pallas;
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
    s_ch: Selector,
    s_ch_neg: Selector,
    s_or_not_xor: Selector,
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
        let s_ch = meta.selector();
        let s_ch_neg = meta.selector();
        let s_or_not_xor = meta.selector();

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

        CompressionConfig {
            lookup,
            advice,
            s_decompose_0,
            s_f1,
            s_ch,
            s_ch_neg,
            s_or_not_xor
        }
    }
    
}