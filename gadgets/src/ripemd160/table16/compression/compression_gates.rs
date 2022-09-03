use super::super::{util::*, Gate};
use halo2::{
    arithmetic::FieldExt,
    plonk::{Constraint, Constraints, Expression},
};
use std::marker::PhantomData;

pub struct CompressionGate<F: FieldExt>(PhantomData<F>);

impl<F: FieldExt> CompressionGate<F> {
    fn ones() -> Expression<F> {
        Expression::Constant(F::one())
    }

    // Gate for B ^ C ^ D; XOR of three 32 bit words
    // Output is in spread_r0_even, spread_r1_even
    #[allow(clippy::too_many_arguments)]
    fn f1_gate(
        s_f1: Expression<F>,
        spread_r0_even: Expression<F>,
        spread_r0_odd: Expression<F>,
        spread_r1_even: Expression<F>,
        spread_r1_odd: Expression<F>,
        spread_b_lo: Expression<F>,
        spread_b_hi: Expression<F>,
        spread_c_lo: Expression<F>,
        spread_c_hi: Expression<F>,
        spread_d_lo: Expression<F>,
        spread_d_hi: Expression<F>,
    ) -> Option<(&'static str, Expression<F>)> {
        let xor_even = spread_r0_even + spread_r1_even * F::from(1 << 32);
        let xor_odd = spread_r0_odd + spread_r1_odd * F::from(1 << 32);
        let xor = xor_even + xor_odd * F::from(2);

        let b = spread_b_lo + spread_b_hi * F::from(1 << 32);
        let c = spread_c_lo + spread_c_hi * F::from(1 << 32);
        let d = spread_d_lo + spread_d_hi * F::from(1 << 32);
        let sum = b + c + d;

        Some(("maj", s_f1 * (sum - xor)))
    }

    // First part of choice gate on (X, Y, Z), X & Y
    // Used in both f2 and f4
    // f2(B, C, D) = (B & C) | (!B & D)
    // f4(B, C, D) = (B & D) | (C & !D)
    // Note: We don't implement separate gates for f2 and f4 as their
    // output can be rolled into the calculation of T in each round
    // Output is in spread_p0_odd, spread_p1_odd
    #[allow(clippy::too_many_arguments)]
    pub fn ch_gate(
        s_ch: Expression<F>,
        spread_p0_even: Expression<F>,
        spread_p0_odd: Expression<F>,
        spread_p1_even: Expression<F>,
        spread_p1_odd: Expression<F>,
        spread_x_lo: Expression<F>,
        spread_x_hi: Expression<F>,
        spread_y_lo: Expression<F>,
        spread_y_hi: Expression<F>,
    ) -> Option<(&'static str, Expression<F>)> {
        let lhs_lo = spread_x_lo + spread_y_lo;
        let lhs_hi = spread_x_hi + spread_y_hi;
        let lhs = lhs_lo + lhs_hi * F::from(1 << 32);

        let rhs_even = spread_p0_even + spread_p1_even * F::from(1 << 32);
        let rhs_odd = spread_p0_odd + spread_p1_odd * F::from(1 << 32);
        let rhs = rhs_even + rhs_odd * F::from(2);

        let check = lhs + rhs * -F::one();

        Some(("s_ch", s_ch * check))
    }

    // Second part of Choice gate on (X, Y, Z), !X & Z
    // Used in both f2 and f4
    // f2(B, C, D) = (B & C) | (!B & D)
    // f4(B, C, D) = (B & D) | (C & !D)
    // Note: We don't implement separate gates for f2 and f4 as their
    // output can be rolled into the calculation of T in each round
    // Output is in spread_q0_odd, spread_q1_odd
    #[allow(clippy::too_many_arguments)]
    pub fn ch_neg_gate(
        s_ch_neg: Expression<F>,
        spread_q0_even: Expression<F>,
        spread_q0_odd: Expression<F>,
        spread_q1_even: Expression<F>,
        spread_q1_odd: Expression<F>,
        spread_x_lo: Expression<F>,
        spread_x_hi: Expression<F>,
        spread_x_neg_lo: Expression<F>,
        spread_x_neg_hi: Expression<F>,
        spread_z_lo: Expression<F>,
        spread_z_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        let neg_check = {
            let evens = Self::ones() * F::from(MASK_EVEN_32 as u64);
            // evens - spread_x_lo = spread_x_neg_lo
            let lo_check = spread_x_neg_lo.clone() + spread_x_lo + (evens.clone() * (-F::one()));
            // evens - spread_x_hi = spread_x_neg_hi
            let hi_check = spread_x_neg_hi.clone() + spread_x_hi + (evens * (-F::one()));

            std::iter::empty()
                .chain(Some(("lo_check", lo_check)))
                .chain(Some(("hi_check", hi_check)))
        };

        let lhs_lo = spread_x_neg_lo + spread_z_lo;
        let lhs_hi = spread_x_neg_hi + spread_z_hi;
        let lhs = lhs_lo + lhs_hi * F::from(1 << 32);

        let rhs_even = spread_q0_even + spread_q1_even * F::from(1 << 32);
        let rhs_odd = spread_q0_odd + spread_q1_odd * F::from(1 << 32);
        let rhs = rhs_even + rhs_odd * F::from(2);

        Constraints::with_selector(s_ch_neg, neg_check.chain(Some(("s_ch_neg", lhs - rhs))))
    }

    // Gate for (X | !Y ) ^ Z
    // Used in both f3 and f5
    // f3(X, Y, Z) = (X | !Y ) ^ Z
    // f5(X, Y, Z) = X ^ (Y | !Z)
    // Output is in spread_r0_even, spread_r1_even
    #[allow(clippy::too_many_arguments)]
    pub fn or_not_xor_gate(
        s_or_not_xor: Expression<F>,
        spread_r0_even: Expression<F>,
        spread_r0_odd: Expression<F>,
        spread_r1_even: Expression<F>,
        spread_r1_odd: Expression<F>,
        spread_or_lo: Expression<F>,
        spread_or_hi: Expression<F>,
        spread_sum0_even: Expression<F>,
        spread_sum0_odd: Expression<F>,
        spread_sum1_even: Expression<F>,
        spread_sum1_odd: Expression<F>,
        spread_x_lo: Expression<F>,
        spread_x_hi: Expression<F>,
        spread_y_lo: Expression<F>,
        spread_y_hi: Expression<F>,
        spread_y_neg_lo: Expression<F>,
        spread_y_neg_hi: Expression<F>,
        spread_z_lo: Expression<F>,
        spread_z_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        let checks = {
            let evens = Self::ones() * F::from(MASK_EVEN_32 as u64);
            // evens - spread_y_lo = spread_y_neg_lo
            let lo_check = spread_y_neg_lo.clone() + spread_y_lo + (evens.clone() * (-F::one()));
            // evens - spread_y_hi = spread_y_neg_hi
            let hi_check = spread_y_neg_hi.clone() + spread_y_hi + (evens * (-F::one()));

            std::iter::empty()
                .chain(Some(("y_lo_check", lo_check)))
                .chain(Some(("y_hi_check", hi_check)))
        };

        // X + !Y
        let sum_lhs_lo = spread_x_lo + spread_y_neg_lo;
        let sum_lhs_hi = spread_x_hi + spread_y_neg_hi;
        let sum_lhs = sum_lhs_lo + sum_lhs_hi * F::from(1 << 32);

        let sum_rhs_even = spread_sum0_even.clone() + spread_sum1_even.clone() * F::from(1 << 32);
        let sum_rhs_odd = spread_sum0_odd.clone() + spread_sum1_odd.clone() * F::from(1 << 32);
        let sum_rhs = sum_rhs_even + sum_rhs_odd * F::from(2);

        // X | !Y
        // OR gate output is obtained as the sum of the spread versions of even and odd parts of X + !Y
        let or_lhs_lo = spread_sum0_even + spread_sum0_odd;
        let or_lhs_hi = spread_sum1_even + spread_sum1_odd;
        let or_lhs = or_lhs_lo + or_lhs_hi * F::from(1 << 32);

        let or_rhs = spread_or_lo.clone() + spread_or_hi.clone() * F::from(1 << 32);

        let xor_even = spread_r0_even + spread_r1_even * F::from(1 << 32);
        let xor_odd = spread_r0_odd + spread_r1_odd * F::from(1 << 32);
        let xor = xor_even + xor_odd * F::from(2);

        let or = spread_or_lo + spread_or_hi * F::from(1 << 32);
        let z = spread_z_lo + spread_z_hi * F::from(1 << 32);
        let sum = or + z;

        Constraints::with_selector(
            s_or_not_xor,
            checks
                .chain(
                    Some(("sum_x_not_y", sum_lhs - sum_rhs))
                )
                .chain(
                    Some(("or_x_not_y", or_lhs - or_rhs))
                )
                .chain(
                    Some(("or_x_not_y_xor_z", sum - xor))
                )
        )
    }

    // Gate for rotate_left(W, 5)
    // word = (a,b,c) = (5, 11, 16) chunks with a = (a_lo, a_hi) = (2, 3) chunks
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_left_5_gate(
        s_rotate_left_5: Expression<F>,
        a_lo: Expression<F>,
        a_hi: Expression<F>,
        b: Expression<F>,
        tag_b: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_5_word_lo: Expression<F>,
        rol_5_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits 
        // by the lookup table
        let range_check_tag_b = Gate::range_check(tag_b, 0, 3); // tag <= 3 => b < 2^11
        let range_check_a_lo = Gate::two_bit_range(a_lo.clone());
        let range_check_a_hi = Gate::three_bit_range(a_hi.clone());

        let word_check = a_lo.clone()
        + a_hi.clone() * F::from(1 << 2)
        + b.clone() * F::from(1 << 5)
        + c.clone() * F::from(1 << 16)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_5_word_check = b
        + c * F::from(1 << 11)
        + a_lo * F::from(1 << 27)
        + a_hi * F::from(1 << 29)
        + rol_5_word_lo * (-F::one())
        + rol_5_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_5,
            std::iter::empty()
                .chain(Some(("range_check_tag_b", range_check_tag_b)))
                .chain(range_check_a_lo)
                .chain(range_check_a_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_5_word_check", rol_5_word_check)))
        )
    }

    // Gate for rotate_left(W, 6)
    // word = (a,b,c) = (6, 10, 16) chunks with a = (a_lo, a_hi) = (3, 3) chunks
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_left_6_gate(
        s_rotate_left_6: Expression<F>,
        a_lo: Expression<F>,
        a_hi: Expression<F>,
        b: Expression<F>,
        tag_b: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_6_word_lo: Expression<F>,
        rol_6_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits 
        // by the lookup table
        let range_check_tag_b = Gate::range_check(tag_b, 0, 2); // tag <= 2 => b < 2^10
        let range_check_a_lo = Gate::three_bit_range(a_lo.clone());
        let range_check_a_hi = Gate::three_bit_range(a_hi.clone());

        let word_check = a_lo.clone()
        + a_hi.clone() * F::from(1 << 3)
        + b.clone() * F::from(1 << 6)
        + c.clone() * F::from(1 << 16)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_6_word_check = b
        + c * F::from(1 << 10)
        + a_lo * F::from(1 << 26)
        + a_hi * F::from(1 << 29)
        + rol_6_word_lo * (-F::one())
        + rol_6_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_6,
            std::iter::empty()
                .chain(Some(("range_check_tag_b", range_check_tag_b)))
                .chain(range_check_a_lo)
                .chain(range_check_a_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_6_word_check", rol_6_word_check)))
        )
    }

    // Gate for rotate_left(W, 7)
    // word = (a,b,c) = (7, 9, 16) chunks with a = (a_lo, a_hi) = (3, 4) chunks
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_left_7_gate(
        s_rotate_left_7: Expression<F>,
        a_lo: Expression<F>,
        a_hi: Expression<F>,
        b: Expression<F>,
        tag_b: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_7_word_lo: Expression<F>,
        rol_7_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits 
        // by the lookup table
        let range_check_tag_b = Gate::range_check(tag_b, 0, 1); // tag <= 1 => b < 2^9
        let range_check_a_lo = Gate::three_bit_range(a_lo.clone());
        let range_check_a_hi = Gate::four_bit_range(a_hi.clone());

        let word_check = a_lo.clone()
        + a_hi.clone() * F::from(1 << 3)
        + b.clone() * F::from(1 << 7)
        + c.clone() * F::from(1 << 16)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_7_word_check = b
        + c * F::from(1 << 9)
        + a_lo * F::from(1 << 25)
        + a_hi * F::from(1 << 28)
        + rol_7_word_lo * (-F::one())
        + rol_7_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_7,
            std::iter::empty()
                .chain(Some(("range_check_tag_b", range_check_tag_b)))
                .chain(range_check_a_lo)
                .chain(range_check_a_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_7_word_check", rol_7_word_check)))
        )
    }

    // Gate for rotate_left(W, 8)
    // word = (a,b,c) = (8, 8, 16) chunks with a = (a_lo, a_hi) = (4, 4) chunks
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_left_8_gate(
        s_rotate_left_8: Expression<F>,
        a_lo: Expression<F>,
        a_hi: Expression<F>,
        b: Expression<F>,
        tag_b: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_8_word_lo: Expression<F>,
        rol_8_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits 
        // by the lookup table
        let range_check_tag_b = Gate::range_check(tag_b, 0, 0); // tag = 0 => b < 2^8
        let range_check_a_lo = Gate::four_bit_range(a_lo.clone());
        let range_check_a_hi = Gate::four_bit_range(a_hi.clone());

        let word_check = a_lo.clone()
        + a_hi.clone() * F::from(1 << 4)
        + b.clone() * F::from(1 << 8)
        + c.clone() * F::from(1 << 16)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_8_word_check = b
        + c * F::from(1 << 8)
        + a_lo * F::from(1 << 24)
        + a_hi * F::from(1 << 28)
        + rol_8_word_lo * (-F::one())
        + rol_8_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_8,
            std::iter::empty()
                .chain(Some(("range_check_tag_b", range_check_tag_b)))
                .chain(range_check_a_lo)
                .chain(range_check_a_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_8_word_check", rol_8_word_check)))
        )
    }

    // Gate for rotate_left(W, 9)
    // word = (a,b,c) = (9, 7, 16) chunks with b = (b_lo, b_hi) = (3, 4) chunks
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_left_9_gate(
        s_rotate_left_9: Expression<F>,
        a: Expression<F>,
        tag_a: Expression<F>,
        b_lo: Expression<F>,
        b_hi: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_9_word_lo: Expression<F>,
        rol_9_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits 
        // by the lookup table
        let range_check_tag_a = Gate::range_check(tag_a, 0, 1); // tag <= 1 => a < 2^9
        let range_check_b_lo = Gate::three_bit_range(b_lo.clone());
        let range_check_b_hi = Gate::four_bit_range(b_hi.clone());

        let word_check = a.clone()
        + b_lo.clone() * F::from(1 << 9)
        + b_hi.clone() * F::from(1 << 12)
        + c.clone() * F::from(1 << 16)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_9_word_check = b_lo
        + b_hi * F::from(1 << 3)
        + c * F::from(1 << 7)
        + a * F::from(1 << 23)
        + rol_9_word_lo * (-F::one())
        + rol_9_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_9,
            std::iter::empty()
                .chain(Some(("range_check_tag_a", range_check_tag_a)))
                .chain(range_check_b_lo)
                .chain(range_check_b_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_9_word_check", rol_9_word_check)))
        )
    }

    // Gate for rotate_left(W, 10)
    // word = (a,b,c) = (10, 6, 16) chunks with b = (b_lo, b_hi) = (3, 3) chunks
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_left_10_gate(
        s_rotate_left_10: Expression<F>,
        a: Expression<F>,
        tag_a: Expression<F>,
        b_lo: Expression<F>,
        b_hi: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_10_word_lo: Expression<F>,
        rol_10_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits 
        // by the lookup table
        let range_check_tag_a = Gate::range_check(tag_a, 0, 2); // tag <= 2 => a < 2^10
        let range_check_b_lo = Gate::three_bit_range(b_lo.clone());
        let range_check_b_hi = Gate::three_bit_range(b_hi.clone());

        let word_check = a.clone()
        + b_lo.clone() * F::from(1 << 10)
        + b_hi.clone() * F::from(1 << 13)
        + c.clone() * F::from(1 << 16)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_10_word_check = b_lo
        + b_hi * F::from(1 << 3)
        + c * F::from(1 << 6)
        + a * F::from(1 << 22)
        + rol_10_word_lo * (-F::one())
        + rol_10_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_10,
            std::iter::empty()
                .chain(Some(("range_check_tag_a", range_check_tag_a)))
                .chain(range_check_b_lo)
                .chain(range_check_b_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_10_word_check", rol_10_word_check)))
        )
    }

    // Gate for rotate_left(W, 11)
    // word = (a,b,c) = (11, 5, 16) chunks with b = (b_lo, b_hi) = (2, 3) chunks
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_left_11_gate(
        s_rotate_left_11: Expression<F>,
        a: Expression<F>,
        tag_a: Expression<F>,
        b_lo: Expression<F>,
        b_hi: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_11_word_lo: Expression<F>,
        rol_11_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits 
        // by the lookup table
        let range_check_tag_a = Gate::range_check(tag_a, 0, 3); // tag <= 3 => a < 2^11
        let range_check_b_lo = Gate::two_bit_range(b_lo.clone());
        let range_check_b_hi = Gate::three_bit_range(b_hi.clone());

        let word_check = a.clone()
        + b_lo.clone() * F::from(1 << 11)
        + b_hi.clone() * F::from(1 << 13)
        + c.clone() * F::from(1 << 16)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_11_word_check = b_lo
        + b_hi * F::from(1 << 2)
        + c * F::from(1 << 5)
        + a * F::from(1 << 21)
        + rol_11_word_lo * (-F::one())
        + rol_11_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_11,
            std::iter::empty()
                .chain(Some(("range_check_tag_a", range_check_tag_a)))
                .chain(range_check_b_lo)
                .chain(range_check_b_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_11_word_check", rol_11_word_check)))
        )
    }

    // Gate for rotate_left(W, 12)
    // word = (a,b,c) = (12, 4, 16) chunks with b = (b_lo, b_hi) = (2, 2) chunks
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_left_12_gate(
        s_rotate_left_12: Expression<F>,
        a: Expression<F>,
        tag_a: Expression<F>,
        b_lo: Expression<F>,
        b_hi: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_12_word_lo: Expression<F>,
        rol_12_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits 
        // by the lookup table
        let range_check_tag_a = Gate::range_check(tag_a, 0, 4); // tag <= 4 => a < 2^12
        let range_check_b_lo = Gate::two_bit_range(b_lo.clone());
        let range_check_b_hi = Gate::two_bit_range(b_hi.clone());

        let word_check = a.clone()
        + b_lo.clone() * F::from(1 << 12)
        + b_hi.clone() * F::from(1 << 14)
        + c.clone() * F::from(1 << 16)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_12_word_check = b_lo
        + b_hi * F::from(1 << 2)
        + c * F::from(1 << 4)
        + a * F::from(1 << 20)
        + rol_12_word_lo * (-F::one())
        + rol_12_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_12,
            std::iter::empty()
                .chain(Some(("range_check_tag_a", range_check_tag_a)))
                .chain(range_check_b_lo)
                .chain(range_check_b_hi)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_12_word_check", rol_12_word_check)))
        )
    }

    // Gate for rotate_left(W, 13)
    // word = (a,b,c) = (13, 3, 16) chunks
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_left_13_gate(
        s_rotate_left_13: Expression<F>,
        a: Expression<F>,
        tag_a: Expression<F>,
        b: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_13_word_lo: Expression<F>,
        rol_13_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits 
        // by the lookup table
        let range_check_tag_a = Gate::range_check(tag_a, 0, 5); // tag <= 5 => a < 2^13
        let range_check_b= Gate::three_bit_range(b.clone());

        let word_check = a.clone()
        + b.clone() * F::from(1 << 13)
        + c.clone() * F::from(1 << 16)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_13_word_check = b
        + c * F::from(1 << 3)
        + a * F::from(1 << 19)
        + rol_13_word_lo * (-F::one())
        + rol_13_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_13,
            std::iter::empty()
                .chain(Some(("range_check_tag_a", range_check_tag_a)))
                .chain(range_check_b)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_13_word_check", rol_13_word_check)))
        )
    }

    // Gate for rotate_left(W, 14)
    // word = (a,b,c) = (14, 2, 16) chunks
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_left_14_gate(
        s_rotate_left_14: Expression<F>,
        a: Expression<F>,
        tag_a: Expression<F>,
        b: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_14_word_lo: Expression<F>,
        rol_14_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits 
        // by the lookup table
        let range_check_tag_a = Gate::range_check(tag_a, 0, 6); // tag <= 6 => a < 2^14
        let range_check_b= Gate::two_bit_range(b.clone());

        let word_check = a.clone()
        + b.clone() * F::from(1 << 14)
        + c.clone() * F::from(1 << 16)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_14_word_check = b
        + c * F::from(1 << 2)
        + a * F::from(1 << 18)
        + rol_14_word_lo * (-F::one())
        + rol_14_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_14,
            std::iter::empty()
                .chain(Some(("range_check_tag_a", range_check_tag_a)))
                .chain(range_check_b)
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_14_word_check", rol_14_word_check)))
        )
    }

    // Gate for rotate_left(W, 14)
    // word = (a,b,c) = (15, 1, 16) chunks
    #[allow(clippy::too_many_arguments)]
    pub fn rotate_left_15_gate(
        s_rotate_left_15: Expression<F>,
        a: Expression<F>,
        tag_a: Expression<F>,
        b: Expression<F>,
        c: Expression<F>,
        word_lo: Expression<F>,
        word_hi: Expression<F>,
        rol_15_word_lo: Expression<F>,
        rol_15_word_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        // Note: There is no need to check the tag of c as it will be constrained to be 16 bits 
        // by the lookup table
        let range_check_tag_a = Gate::range_check(tag_a, 0, 7); // tag <= 7 => a < 2^15
        let range_check_b= Gate::range_check(b.clone(), 0, 1);

        let word_check = a.clone()
        + b.clone() * F::from(1 << 14)
        + c.clone() * F::from(1 << 16)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_15_word_check = b
        + c * F::from(1 << 2)
        + a * F::from(1 << 18)
        + rol_15_word_lo * (-F::one())
        + rol_15_word_hi * F::from(1 << 16) * (-F::one());

        Constraints::with_selector(
            s_rotate_left_15,
            std::iter::empty()
                .chain(Some(("range_check_tag_a", range_check_tag_a)))
                .chain(Some(("range_check_b", range_check_b)))
                .chain(Some(("word_check", word_check)))
                .chain(Some(("rol_15_word_check", rol_15_word_check)))
        )
    }
}