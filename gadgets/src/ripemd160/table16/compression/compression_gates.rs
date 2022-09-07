use super::super::{util::*, Gate};
use halo2::{
    arithmetic::FieldExt,
    circuit::Layouter,
    plonk::{Constraint, Constraints, Expression, Error},
};
use std::marker::PhantomData;

pub struct CompressionGate<F: FieldExt>(PhantomData<F>);

impl<F: FieldExt> CompressionGate<F> {
    fn ones() -> Expression<F> {
        Expression::Constant(F::one())
    }

    // Gate for B ^ C ^ D; XOR of three 32 bit words
    // Output is in r0_even, r1_even
    #[allow(clippy::too_many_arguments)]
    pub fn f1_gate(
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
    // Output is in p0_odd, p1_odd
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
    // Output is in q0_odd, q1_odd
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
    // Output is in r0_even, r1_even
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
    // word = (a,b,c) = (5, 11, 16) chunks with a = (a_hi, a_lo) = (3, 2) chunks
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

        let word_check = c.clone()
        + b.clone() * F::from(1 << 16)
        + a_lo.clone() * F::from(1 << 27)
        + a_hi.clone() * F::from(1 << 29)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_5_word_check = a_lo
        + a_hi * F::from(1 << 2)
        + c * F::from(1 << 5)
        + b * F::from(1 << 21)
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
    // word = (a,b,c) = (6, 10, 16) chunks with a = (a_hi, a_lo) = (3, 3) chunks
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

        let word_check = c.clone()
        + b.clone() * F::from(1 << 16)
        + a_lo.clone() * F::from(1 << 26)
        + a_hi.clone() * F::from(1 << 29)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_6_word_check = a_lo
        + a_hi * F::from(1 << 3)
        + c * F::from(1 << 6)
        + b * F::from(1 << 22)
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
    // word = (a,b,c) = (7, 9, 16) chunks with a = (a_hi, a_lo) = (4, 3) chunks
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

        let word_check = c.clone()
        + b.clone() * F::from(1 << 16)
        + a_lo.clone() * F::from(1 << 25)
        + a_hi.clone() * F::from(1 << 28)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_7_word_check = a_lo
        + a_hi * F::from(1 << 3)
        + c * F::from(1 << 7)
        + b * F::from(1 << 23)
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
    // word = (a,b,c) = (8, 8, 16) chunks with a = (a_hi, a_lo) = (4, 4) chunks
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

        let word_check = c.clone()
        + b.clone() * F::from(1 << 16)
        + a_lo.clone() * F::from(1 << 24)
        + a_hi.clone() * F::from(1 << 28)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_8_word_check = a_lo
        + a_hi * F::from(1 << 4)
        + c * F::from(1 << 8)
        + b * F::from(1 << 24)
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
    // word = (a,b,c) = (9, 7, 16) chunks with b = (b_hi, b_lo) = (4, 3) chunks
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

        let word_check = c.clone()
        + b_lo.clone() * F::from(1 << 16)
        + b_hi.clone() * F::from(1 << 19)
        + a.clone() * F::from(1 << 23)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_9_word_check = a
        + c * F::from(1 << 9)
        + b_lo * F::from(1 << 25)
        + b_hi * F::from(1 << 28)
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
    // word = (a,b,c) = (10, 6, 16) chunks with b = (b_hi, b_lo) = (3, 3) chunks
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

        let word_check = c.clone()
        + b_lo.clone() * F::from(1 << 16)
        + b_hi.clone() * F::from(1 << 19)
        + a.clone() * F::from(1 << 22)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_10_word_check = a
        + c * F::from(1 << 10)
        + b_lo * F::from(1 << 26)
        + b_hi * F::from(1 << 29)
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
    // word = (a,b,c) = (11, 5, 16) chunks with b = (b_hi, b_lo) = (3, 2) chunks
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

        let word_check = c.clone()
        + b_lo.clone() * F::from(1 << 16)
        + b_hi.clone() * F::from(1 << 18)
        + a.clone() * F::from(1 << 21)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_11_word_check = a
        + c * F::from(1 << 11)
        + b_lo * F::from(1 << 27)
        + b_hi * F::from(1 << 29)
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
    // word = (a,b,c) = (12, 4, 16) chunks with b = (b_hi, b_lo) = (2, 2) chunks
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

        let word_check = c.clone()
        + b_lo.clone() * F::from(1 << 16)
        + b_hi.clone() * F::from(1 << 18)
        + a.clone() * F::from(1 << 20)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_12_word_check = a
        + c * F::from(1 << 12)
        + b_lo * F::from(1 << 28)
        + b_hi * F::from(1 << 30)
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

        let word_check = c.clone()
        + b.clone() * F::from(1 << 16)
        + a.clone() * F::from(1 << 19)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_13_word_check = a
        + c * F::from(1 << 13)
        + b * F::from(1 << 29)
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

        let word_check = c.clone()
        + b.clone() * F::from(1 << 16)
        + a.clone() * F::from(1 << 18)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_14_word_check = a
        + c * F::from(1 << 14)
        + b * F::from(1 << 30)
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

        let word_check = c.clone()
        + b.clone() * F::from(1 << 16)
        + a.clone() * F::from(1 << 17)
        + word_lo * (-F::one())
        + word_hi * F::from(1 << 16) * (-F::one());

        let rol_15_word_check = a
        + c * F::from(1 << 15)
        + b * F::from(1 << 31)
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

#[cfg(test)]
mod tests {
    use halo2::plonk::{Circuit, ConstraintSystem, Error};
    use halo2::halo2curves::{pasta::Fp};
    use halo2::circuit::{SimpleFloorPlanner, Layouter, Region, Value};
    use halo2::dev::MockProver;
    use rand::Rng;

    use crate::ripemd160::ref_impl::helper_functions::rol;
    use crate::ripemd160::table16::{Table16Assignment, AssignedBits};
    use crate::ripemd160::table16::spread_table::{SpreadTableConfig, SpreadTableChip};
    use crate::ripemd160::table16::compression::{CompressionConfig, RoundWordDense};

    #[derive(Debug, Clone)]
    struct CompressionGateTesterConfig {
        lookup: SpreadTableConfig,
        compression: CompressionConfig,
    }

    struct CompressionGateTester {
        pub b: u32,
        pub c: u32,
        pub d: u32,
        pub xor: u32,
        pub b_and_c: u32,
        pub neg_b_and_d: u32,
        pub b_or_neg_c_xor_d: u32,
        pub rol_5_b: u32,
        pub rol_6_b: u32,
        pub rol_7_b: u32,
        pub rol_8_b: u32,
        pub rol_9_b: u32,
        pub rol_10_b: u32,
        pub rol_11_b: u32,
        pub rol_12_b: u32,
        pub rol_13_b: u32,
        pub rol_14_b: u32,
        pub rol_15_b: u32,
    }

    impl Circuit<Fp> for CompressionGateTester {
        type Config = CompressionGateTesterConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            CompressionGateTester {
                b: 0,
                c: 0,
                d: 0,
                xor: 0,
                b_and_c: 0,
                neg_b_and_d: 0,
                b_or_neg_c_xor_d: 0,
                rol_5_b: 0,
                rol_6_b: 0,
                rol_7_b: 0,
                rol_8_b: 0,
                rol_9_b: 0,
                rol_10_b: 0,
                rol_11_b: 0,
                rol_12_b: 0,
                rol_13_b: 0,
                rol_14_b: 0,
                rol_15_b: 0,
            }
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            let input_tag = meta.advice_column();
            let input_dense = meta.advice_column();
            let input_spread = meta.advice_column();
            let advice= [
                meta.advice_column(),
                meta.advice_column(),
                meta.advice_column()
            ];
            let s_decompose_0 = meta.selector();

            let lookup = SpreadTableChip::configure(meta, input_tag, input_dense, input_spread);
            let lookup_inputs = lookup.input.clone();

            let _a_0 = lookup_inputs.tag;
            let a_1 = lookup_inputs.dense;
            let a_2 = lookup_inputs.spread;
            let a_3 = advice[0];
            let a_4 = advice[1];
            let a_5 = advice[2];

            // Add all advice columns to permutation
            for column in [a_1, a_2, a_3, a_4, a_5 ].iter() {
                meta.enable_equality(*column);
            }
            
            let compression = CompressionConfig::configure(meta, lookup_inputs, advice, s_decompose_0);

            Self::Config {
                lookup,
                compression,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>
        ) -> Result<(), Error> {
            SpreadTableChip::load(config.lookup.clone(), &mut layouter)?;
            
            layouter.assign_region(
                || "compression_gate testing",
                |mut region: Region<Fp>| {
                    let a_3 = config.compression.advice[0];
                    let a_4 = config.compression.advice[1];
                    let a_5 = config.compression.advice[2];

                    let mut row = 0_usize;

                    let (_, (spread_b_var_lo, spread_b_var_hi)) =
                    config.compression.assign_word_and_halves(
                         "b".to_string(),
                         &mut region,
                         &config.lookup.input,
                         a_3,
                         a_4,
                         a_5,
                         Value::known(self.b),
                         row,
                    )?;
                    row += 2;

                    // row = 2
                    let (_, (spread_c_var_lo, spread_c_var_hi)) =
                    config.compression.assign_word_and_halves(
                         "c".to_string(),
                         &mut region,
                         &config.lookup.input,
                         a_3,
                         a_4,
                         a_5,
                         Value::known(self.c),
                         row,
                    )?;
                    row += 2;

                    // row = 4
                    let (_, (spread_d_var_lo, spread_d_var_hi)) =
                    config.compression.assign_word_and_halves(
                         "d".to_string(),
                         &mut region,
                         &config.lookup.input,
                         a_3,
                         a_4,
                         a_5,
                         Value::known(self.d),
                         row,
                    )?;
                    row += 2;

                    let spread_halves_b = (spread_b_var_lo.clone().spread, spread_b_var_hi.clone().spread);
                    let spread_halves_c = (spread_c_var_lo.spread, spread_c_var_hi.spread);
                    let spread_halves_d = (spread_d_var_lo.spread, spread_d_var_hi.spread);

                    // row = 6
                    // Testing f1_gate
                    let (xor_out_lo, xor_out_hi) =
                    config.compression.assign_f1(
                        &mut region,
                        row,
                        spread_halves_b.clone().into(), 
                        spread_halves_c.clone().into(),
                        spread_halves_d.clone().into()
                    )?;
                    row += 4; // f1 requires four rows

                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    // row = 10
                    AssignedBits::<32>::assign(
                        &mut region,
                        || "xor_out",
                        a_5,
                        row,
                        Value::known(self.xor),
                    )?;

                    xor_out_lo.copy_advice(|| "xor_out_lo", &mut region, a_3, row)?;
                    xor_out_hi.copy_advice(|| "xor_out_hi", &mut region, a_4, row)?;

                    // Testing ch_gate
                    row += 1;
                    // row = 11
                    let (b_and_c_lo, b_and_c_hi) =
                    config.compression.assign_ch(
                        &mut region,
                        row,
                        spread_halves_b.clone().into(), 
                        spread_halves_c.clone().into(),
                    )?;
                    row += 4; // ch requires four rows

                    // row = 15
                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    AssignedBits::<32>::assign(
                        &mut region,
                        || "b_and_c",
                        a_5,
                        row,
                        Value::known(self.b_and_c),
                    )?;

                    b_and_c_lo.copy_advice(|| "b_and_c_lo", &mut region, a_3, row)?;
                    b_and_c_hi.copy_advice(|| "b_and_c_hi", &mut region, a_4, row)?;
                    row += 1;


                    // row = 16
                    // Testing ch_neg_gate
                    let (neg_b_and_c_lo, neg_b_and_c_hi) =
                    config.compression.assign_ch_neg(
                        &mut region,
                        row,
                        spread_halves_b.clone().into(), 
                        spread_halves_d.clone().into(),
                    )?;
                    row += 4; // ch requires four rows


                    // row = 20
                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    AssignedBits::<32>::assign(
                        &mut region,
                        || "neg_b_and_d",
                        a_5,
                        row,
                        Value::known(self.neg_b_and_d),
                    )?;

                    neg_b_and_c_lo.copy_advice(|| "b_and_c_lo", &mut region, a_3, row)?;
                    neg_b_and_c_hi.copy_advice(|| "b_and_c_hi", &mut region, a_4, row)?;
                    row += 1;

                    // row = 21
                    // Testing or_not_xor gate
                    let (b_or_neg_c_xor_d_lo, b_or_neg_c_xor_d_hi) =
                    config.compression.assign_or_not_xor(
                        &mut region,
                        row,
                        spread_halves_b.into(), 
                        spread_halves_c.into(), 
                        spread_halves_d.into(),
                    )?;
                    row += 10; // or_not_xor requires ten rows


                    // row = 31
                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    AssignedBits::<32>::assign(
                        &mut region,
                        || "b_or_neg_c_xor_d",
                        a_5,
                        row,
                        Value::known(self.b_or_neg_c_xor_d),
                    )?;

                    b_or_neg_c_xor_d_lo.copy_advice(|| "b_or_neg_c_xor_d_lo", &mut region, a_3, row)?;
                    b_or_neg_c_xor_d_hi.copy_advice(|| "b_or_neg_c_xor_d_hi", &mut region, a_4, row)?;
                    row += 1;

                    // row = 32
                    // Testing rotate_left_5 gate
                    let b_round_word_dense =
                        RoundWordDense(spread_b_var_lo.clone().dense, spread_b_var_hi.clone().dense);
                    let (rol_5_b_lo, rol_5_b_hi) =
                    config.compression.assign_rotate_left(
                        &mut region,
                        row,
                        b_round_word_dense,
                        5
                    )?;
                    row += 2; // rotate_left_5 requires two rows

                    // row = 34
                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    AssignedBits::<32>::assign(
                        &mut region,
                        || "rol_5_b",
                        a_5,
                        row,
                        Value::known(self.rol_5_b),
                    )?;

                    rol_5_b_lo.copy_advice(|| "rol_5_b_lo", &mut region, a_3, row)?;
                    rol_5_b_hi.copy_advice(|| "rol_5_b_lo", &mut region, a_4, row)?;
                    row += 1;

                    // row = 35
                    // Testing rotate_left_6 gate
                    let b_round_word_dense =
                        RoundWordDense(spread_b_var_lo.clone().dense, spread_b_var_hi.clone().dense);
                    let (rol_6_b_lo, rol_6_b_hi) =
                    config.compression.assign_rotate_left(
                        &mut region,
                        row,
                        b_round_word_dense,
                        6
                    )?;
                    row += 2; // rotate_left_6 requires two rows

                    // row = 37
                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    AssignedBits::<32>::assign(
                        &mut region,
                        || "rol_6_b",
                        a_5,
                        row,
                        Value::known(self.rol_6_b),
                    )?;

                    rol_6_b_lo.copy_advice(|| "rol_6_b_lo", &mut region, a_3, row)?;
                    rol_6_b_hi.copy_advice(|| "rol_6_b_lo", &mut region, a_4, row)?;
                    row += 1;

                    // row = 38
                    // Testing rotate_left_7 gate
                    let b_round_word_dense =
                        RoundWordDense(spread_b_var_lo.clone().dense, spread_b_var_hi.clone().dense);
                    let (rol_7_b_lo, rol_7_b_hi) =
                    config.compression.assign_rotate_left(
                        &mut region,
                        row,
                        b_round_word_dense,
                        7
                    )?;
                    row += 2; // rotate_left_7 requires two rows

                    // row = 40
                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    AssignedBits::<32>::assign(
                        &mut region,
                        || "rol_7_b",
                        a_5,
                        row,
                        Value::known(self.rol_7_b),
                    )?;

                    rol_7_b_lo.copy_advice(|| "rol_7_b_lo", &mut region, a_3, row)?;
                    rol_7_b_hi.copy_advice(|| "rol_7_b_lo", &mut region, a_4, row)?;
                    row += 1;

                    // row = 39
                    // Testing rotate_left_8 gate
                    let b_round_word_dense =
                        RoundWordDense(spread_b_var_lo.clone().dense, spread_b_var_hi.clone().dense);
                    let (rol_8_b_lo, rol_8_b_hi) =
                    config.compression.assign_rotate_left(
                        &mut region,
                        row,
                        b_round_word_dense,
                        8
                    )?;
                    row += 2; // rotate_left_8 requires two rows

                    // row = 41
                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    AssignedBits::<32>::assign(
                        &mut region,
                        || "rol_8_b",
                        a_5,
                        row,
                        Value::known(self.rol_8_b),
                    )?;

                    rol_8_b_lo.copy_advice(|| "rol_8_b_lo", &mut region, a_3, row)?;
                    rol_8_b_hi.copy_advice(|| "rol_8_b_lo", &mut region, a_4, row)?;
                    row += 1;

                    // row = 42
                    // Testing rotate_left_9 gate
                    let b_round_word_dense =
                        RoundWordDense(spread_b_var_lo.clone().dense, spread_b_var_hi.clone().dense);
                    let (rol_9_b_lo, rol_9_b_hi) =
                    config.compression.assign_rotate_left(
                        &mut region,
                        row,
                        b_round_word_dense,
                        9
                    )?;
                    row += 2; // rotate_left_9 requires two rows

                    // row = 44
                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    AssignedBits::<32>::assign(
                        &mut region,
                        || "rol_9_b",
                        a_5,
                        row,
                        Value::known(self.rol_9_b),
                    )?;

                    rol_9_b_lo.copy_advice(|| "rol_9_b_lo", &mut region, a_3, row)?;
                    rol_9_b_hi.copy_advice(|| "rol_9_b_lo", &mut region, a_4, row)?;
                    row += 1;

                    // row = 45
                    // Testing rotate_left_10 gate
                    let b_round_word_dense =
                        RoundWordDense(spread_b_var_lo.clone().dense, spread_b_var_hi.clone().dense);
                    let (rol_10_b_lo, rol_10_b_hi) =
                    config.compression.assign_rotate_left(
                        &mut region,
                        row,
                        b_round_word_dense,
                        10
                    )?;
                    row += 2; // rotate_left_10 requires two rows

                    // row = 47
                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    AssignedBits::<32>::assign(
                        &mut region,
                        || "rol_10_b",
                        a_5,
                        row,
                        Value::known(self.rol_10_b),
                    )?;

                    rol_10_b_lo.copy_advice(|| "rol_10_b_lo", &mut region, a_3, row)?;
                    rol_10_b_hi.copy_advice(|| "rol_10_b_lo", &mut region, a_4, row)?;
                    row += 1;

                    // row = 48
                    // Testing rotate_left_11 gate
                    let b_round_word_dense =
                        RoundWordDense(spread_b_var_lo.clone().dense, spread_b_var_hi.clone().dense);
                    let (rol_11_b_lo, rol_11_b_hi) =
                    config.compression.assign_rotate_left(
                        &mut region,
                        row,
                        b_round_word_dense,
                        11
                    )?;
                    row += 2; // rotate_left_11 requires two rows

                    // row = 50
                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    AssignedBits::<32>::assign(
                        &mut region,
                        || "rol_11_b",
                        a_5,
                        row,
                        Value::known(self.rol_11_b),
                    )?;

                    rol_11_b_lo.copy_advice(|| "rol_11_b_lo", &mut region, a_3, row)?;
                    rol_11_b_hi.copy_advice(|| "rol_11_b_lo", &mut region, a_4, row)?;
                    row += 1;

                    // row = 51
                    // Testing rotate_left_12 gate
                    let b_round_word_dense =
                        RoundWordDense(spread_b_var_lo.clone().dense, spread_b_var_hi.clone().dense);
                    let (rol_12_b_lo, rol_12_b_hi) =
                    config.compression.assign_rotate_left(
                        &mut region,
                        row,
                        b_round_word_dense,
                        12
                    )?;
                    row += 2; // rotate_left_12 requires two rows

                    // row = 53
                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    AssignedBits::<32>::assign(
                        &mut region,
                        || "rol_12_b",
                        a_5,
                        row,
                        Value::known(self.rol_12_b),
                    )?;

                    rol_12_b_lo.copy_advice(|| "rol_12_b_lo", &mut region, a_3, row)?;
                    rol_12_b_hi.copy_advice(|| "rol_12_b_lo", &mut region, a_4, row)?;
                    row += 1;

                    // row = 54
                    // Testing rotate_left_13 gate
                    let b_round_word_dense =
                        RoundWordDense(spread_b_var_lo.clone().dense, spread_b_var_hi.clone().dense);
                    let (rol_13_b_lo, rol_13_b_hi) =
                    config.compression.assign_rotate_left(
                        &mut region,
                        row,
                        b_round_word_dense,
                        13
                    )?;
                    row += 2; // rotate_left_13 requires two rows

                    // row = 56
                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    AssignedBits::<32>::assign(
                        &mut region,
                        || "rol_13_b",
                        a_5,
                        row,
                        Value::known(self.rol_13_b),
                    )?;

                    rol_13_b_lo.copy_advice(|| "rol_13_b_lo", &mut region, a_3, row)?;
                    rol_13_b_hi.copy_advice(|| "rol_13_b_lo", &mut region, a_4, row)?;
                    row += 1;

                    // row = 57
                    // Testing rotate_left_14 gate
                    let b_round_word_dense =
                        RoundWordDense(spread_b_var_lo.clone().dense, spread_b_var_hi.clone().dense);
                    let (rol_14_b_lo, rol_14_b_hi) =
                    config.compression.assign_rotate_left(
                        &mut region,
                        row,
                        b_round_word_dense,
                        14
                    )?;
                    row += 2; // rotate_left_14 requires two rows

                    // row = 59
                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    AssignedBits::<32>::assign(
                        &mut region,
                        || "rol_14_b",
                        a_5,
                        row,
                        Value::known(self.rol_14_b),
                    )?;

                    rol_14_b_lo.copy_advice(|| "rol_14_b_lo", &mut region, a_3, row)?;
                    rol_14_b_hi.copy_advice(|| "rol_14_b_lo", &mut region, a_4, row)?;
                    row += 1;

                    // row = 60
                    // Testing rotate_left_15 gate
                    let b_round_word_dense =
                        RoundWordDense(spread_b_var_lo.clone().dense, spread_b_var_hi.clone().dense);
                    let (rol_15_b_lo, rol_15_b_hi) =
                    config.compression.assign_rotate_left(
                        &mut region,
                        row,
                        b_round_word_dense,
                        15
                    )?;
                    row += 2; // rotate_left_15 requires two rows

                    // row = 62
                    config.compression.s_decompose_0.enable(&mut region, row)?;

                    AssignedBits::<32>::assign(
                        &mut region,
                        || "rol_15_b",
                        a_5,
                        row,
                        Value::known(self.rol_15_b),
                    )?;

                    rol_15_b_lo.copy_advice(|| "rol_15_b_lo", &mut region, a_3, row)?;
                    rol_15_b_hi.copy_advice(|| "rol_15_b_lo", &mut region, a_4, row)?;
                    Ok(())
                }
            )?;
            Ok(())    
        }
    }

    #[test]
    fn test_gates() {
        let mut rng = rand::thread_rng();
        let b: u32 = rng.gen();
        let c: u32 = rng.gen();
        let d: u32 = rng.gen();
        let xor: u32 = b ^ c ^ d;
        let b_and_c: u32 = b & c;
        let neg_b_and_d: u32 = !b & d;
        let b_or_neg_c_xor_d: u32 = (b | !c) ^ d;
        let rol_5_b: u32 = rol(b, 5);
        let rol_6_b: u32 = rol(b, 6);
        let rol_7_b: u32 = rol(b, 7);
        let rol_8_b: u32 = rol(b, 8);
        let rol_9_b: u32 = rol(b, 9);
        let rol_10_b: u32 = rol(b, 10);
        let rol_11_b: u32 = rol(b, 11);
        let rol_12_b: u32 = rol(b, 12);
        let rol_13_b: u32 = rol(b, 13);
        let rol_14_b: u32 = rol(b, 14);
        let rol_15_b: u32 = rol(b, 15);

        let circuit = CompressionGateTester {
            b,
            c,
            d,
            xor,
            b_and_c,
            neg_b_and_d,
            b_or_neg_c_xor_d,
            rol_5_b,
            rol_6_b,
            rol_7_b,
            rol_8_b,
            rol_9_b,
            rol_10_b,
            rol_11_b,
            rol_12_b,
            rol_13_b,
            rol_14_b,
            rol_15_b,
        };

        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

}