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

    // Gate for f2(B, C, D) = (B & C) | (!B & D)
    // Used also for f4
    // f4(B, C, D) = (B & D) | (C & !D)
    // Output is in sum_lo, sum_hi
    #[allow(clippy::too_many_arguments)]
    pub fn f2_gate(
        s_f2f4: Expression<F>,
        spread_p0_even: Expression<F>,
        spread_p0_odd: Expression<F>,
        spread_p1_even: Expression<F>,
        spread_p1_odd: Expression<F>,
        p0_odd: Expression<F>,
        p1_odd: Expression<F>,
        spread_q0_even: Expression<F>,
        spread_q0_odd: Expression<F>,
        spread_q1_even: Expression<F>,
        spread_q1_odd: Expression<F>,
        q0_odd: Expression<F>,
        q1_odd: Expression<F>,
        spread_b_lo: Expression<F>,
        spread_b_hi: Expression<F>,
        spread_c_lo: Expression<F>,
        spread_c_hi: Expression<F>,
        spread_d_lo: Expression<F>,
        spread_d_hi: Expression<F>,
        spread_b_neg_lo: Expression<F>,
        spread_b_neg_hi: Expression<F>,
        sum_lo: Expression<F>,
        sum_hi: Expression<F>,
        carry: Expression<F>,
    )  -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        let p_lhs_lo = spread_b_lo.clone() + spread_c_lo;
        let p_lhs_hi = spread_b_hi.clone() + spread_c_hi;
        let p_lhs = p_lhs_lo + p_lhs_hi * F::from(1 << 32);

        let p_rhs_even = spread_p0_even + spread_p1_even * F::from(1 << 32);
        let p_rhs_odd = spread_p0_odd.clone() + spread_p1_odd.clone() * F::from(1 << 32);
        let p_rhs = p_rhs_even + p_rhs_odd * F::from(2);

        let p_check = p_lhs + p_rhs * -F::one();

        let neg_check = {
            let evens = Self::ones() * F::from(MASK_EVEN_32 as u64);
            // evens - spread_x_lo = spread_x_neg_lo
            let lo_check = spread_b_neg_lo.clone() + spread_b_lo + (evens.clone() * (-F::one()));
            // evens - spread_x_hi = spread_x_neg_hi
            let hi_check = spread_b_neg_hi.clone() + spread_b_hi + (evens * (-F::one()));

            std::iter::empty()
                .chain(Some(("lo_check", lo_check)))
                .chain(Some(("hi_check", hi_check)))
        };

        let q_lhs_lo = spread_b_neg_lo + spread_d_lo;
        let q_lhs_hi = spread_b_neg_hi + spread_d_hi;
        let q_lhs = q_lhs_lo + q_lhs_hi * F::from(1 << 32);

        let q_rhs_even = spread_q0_even + spread_q1_even * F::from(1 << 32);
        let q_rhs_odd = spread_q0_odd.clone() + spread_q1_odd.clone() * F::from(1 << 32);
        let q_rhs = q_rhs_even + q_rhs_odd * F::from(2);

        let q_check = q_lhs + q_rhs * -F::one();

        let range_check_carry = Gate::range_check(carry.clone(), 0, 0);

        let lo = p0_odd + q0_odd;
        let hi = p1_odd + q1_odd;
        let sum = lo + hi * F::from(1 << 16);
        let mod_sum = sum_lo + sum_hi * F::from(1 << 16);

        let sum_check = sum - (carry * F::from(1 << 32)) - mod_sum;

        Constraints::with_selector(
            s_f2f4,
            std::iter::empty()
                .chain(neg_check)
                .chain(Some(("p_check", p_check)))
                .chain(Some(("q_check", q_check)))
                .chain(Some(("sum_f2f4", sum_check)))
                .chain(Some(("range_check_carry", range_check_carry)))
        )
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

    // Gate for  A + f(j, B, C, D) + X[r[j]] + K[j]  where r is the rotate amount array
    #[allow(clippy::too_many_arguments)]
    pub fn sum_afxk_gate(
        s_sum_afxk: Expression<F>,
        sum_lo: Expression<F>,
        sum_hi: Expression<F>,
        carry: Expression<F>,
        a_lo: Expression<F>,
        a_hi: Expression<F>,
        f_lo: Expression<F>,
        f_hi: Expression<F>,
        x_lo: Expression<F>,
        x_hi: Expression<F>,
        k_lo: Expression<F>,
        k_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        let range_check_carry = Gate::range_check(carry.clone(), 0, 2);

        let lo = a_lo + f_lo + x_lo + k_lo;
        let hi = a_hi + f_hi + x_hi + k_hi;
        let sum = lo + hi * F::from(1 << 16);
        let mod_sum = sum_lo + sum_hi * F::from(1 << 16);

        let sum_check = sum - (carry * F::from(1 << 32)) - mod_sum;

        Constraints::with_selector(
            s_sum_afxk,
            std::iter::empty()
                .chain(Some(("range_check_carry", range_check_carry)))
                .chain(Some(("sum_afxk", sum_check)))
        )
    }

    // Gate for T = rol + E  where rol is
    // the rotated version of A + f(j, B,C,D) + X[r[j]] + K[j]
    #[allow(clippy::too_many_arguments)]
    pub fn sum_re_gate(
        s_sum_re: Expression<F>,
        sum_lo: Expression<F>,
        sum_hi: Expression<F>,
        carry: Expression<F>,
        rol_lo: Expression<F>,
        rol_hi: Expression<F>,
        e_lo: Expression<F>,
        e_hi: Expression<F>,
    ) -> Constraints<
        F,
        (&'static str, Expression<F>),
        impl Iterator<Item = (&'static str, Expression<F>)>,
    > {
        let range_check_carry = Gate::range_check(carry.clone(), 0, 1);

        let lo = rol_lo + e_lo;
        let hi = rol_hi + e_hi;
        let sum = lo + hi * F::from(1 << 16);
        let mod_sum = sum_lo + sum_hi * F::from(1 << 16);

        let sum_check = sum - (carry * F::from(1 << 32)) - mod_sum;

        Constraints::with_selector(
            s_sum_re,
            std::iter::empty()
                .chain(Some(("range_check_carry", range_check_carry)))
                .chain(Some(("sum_re", sum_check)))
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

    use crate::ripemd160::ref_impl::helper_functions::{rol, f2, f4};
    use crate::ripemd160::table16::Table16Assignment;
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
        pub k: u32,
        pub xor: u32,
        pub f2_bcd: u32,
        pub f4_bcd: u32,
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
        pub sum_bcdk: u32,
        pub sum_bc: u32,
    }

    impl Circuit<Fp> for CompressionGateTester {
        type Config = CompressionGateTesterConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            CompressionGateTester {
                b: 0,
                c: 0,
                d: 0,
                k: 0,
                xor: 0,
                f2_bcd: 0,
                f4_bcd: 0,
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
                sum_bcdk: 0,
                sum_bc: 0,
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
                         || "b",
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
                         || "c",
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
                         || "d",
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
                    let spread_halves_c = (spread_c_var_lo.clone().spread, spread_c_var_hi.clone().spread);
                    let spread_halves_d = (spread_d_var_lo.clone().spread, spread_d_var_hi.clone().spread);

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


                    // row = 10
                    config.compression.assign_decompose_0(&mut region, row, xor_out_lo, xor_out_hi, Value::known(self.xor))?;
                    row += 1;

                    // row = 11
                    // Testing f2_gate
                    let (f2_bcd_lo, f2_bcd_hi) =
                    config.compression.assign_f2(
                        &mut region,
                        row,
                        spread_halves_b.clone().into(), 
                        spread_halves_c.clone().into(),
                        spread_halves_d.clone().into(),
                    )?;
                    row += 8; // f2 requires eight rows


                    // row = 19
                    config.compression.assign_decompose_0(&mut region, row, f2_bcd_lo, f2_bcd_hi, Value::known(self.f2_bcd))?;
                    row += 1;

                    // row = 20
                    // Testing f4_gate
                    let (f4_bcd_lo, f4_bcd_hi) =
                    config.compression.assign_f4(
                        &mut region,
                        row,
                        spread_halves_b.clone().into(), 
                        spread_halves_c.clone().into(),
                        spread_halves_d.clone().into(),
                    )?;
                    row += 8; // f4 requires eight rows


                    // row = 28
                    config.compression.assign_decompose_0(&mut region, row, f4_bcd_lo, f4_bcd_hi, Value::known(self.f4_bcd))?;
                    row += 1;

                    // row = 29
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


                    // row = 39
                    config.compression.assign_decompose_0(
                        &mut region,
                        row,
                        b_or_neg_c_xor_d_lo,
                        b_or_neg_c_xor_d_hi,
                        Value::known(self.b_or_neg_c_xor_d)
                    )?;
                    row += 1;

                    // row = 40
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

                    // row = 42
                    config.compression.assign_decompose_0(&mut region, row, rol_5_b_lo, rol_5_b_hi, Value::known(self.rol_5_b))?;
                    row += 1;

                    // row = 43
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

                    // row = 45
                    config.compression.assign_decompose_0(&mut region, row, rol_6_b_lo, rol_6_b_hi, Value::known(self.rol_6_b))?;
                    row += 1;

                    // row = 46
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

                    // row = 48
                    config.compression.assign_decompose_0(&mut region, row, rol_7_b_lo, rol_7_b_hi, Value::known(self.rol_7_b))?;
                    row += 1;

                    // row = 49
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

                    // row = 51
                    config.compression.assign_decompose_0(&mut region, row, rol_8_b_lo, rol_8_b_hi, Value::known(self.rol_8_b))?;
                    row += 1;

                    // row = 52
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

                    // row = 54
                    config.compression.assign_decompose_0(&mut region, row, rol_9_b_lo, rol_9_b_hi, Value::known(self.rol_9_b))?;
                    row += 1;

                    // row = 55
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

                    // row = 57
                    config.compression.assign_decompose_0(&mut region, row, rol_10_b_lo, rol_10_b_hi, Value::known(self.rol_10_b))?;
                    row += 1;

                    // row = 58
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

                    // row = 60
                    config.compression.assign_decompose_0(&mut region, row, rol_11_b_lo, rol_11_b_hi, Value::known(self.rol_11_b))?;
                    row += 1;

                    // row = 61
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

                    // row = 63
                    config.compression.assign_decompose_0(&mut region, row, rol_12_b_lo, rol_12_b_hi, Value::known(self.rol_12_b))?;
                    row += 1;

                    // row = 64
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

                    // row = 66
                    config.compression.assign_decompose_0(&mut region, row, rol_13_b_lo, rol_13_b_hi, Value::known(self.rol_13_b))?;
                    row += 1;

                    // row = 67
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

                    // row = 69
                    config.compression.assign_decompose_0(&mut region, row, rol_14_b_lo, rol_14_b_hi, Value::known(self.rol_14_b))?;
                    row += 1;

                    // row = 70
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

                    // row = 72
                    config.compression.assign_decompose_0(&mut region, row, rol_15_b_lo, rol_15_b_hi, Value::known(self.rol_15_b))?;
                    row += 1;
                    
                    // row = 73
                    // Testing sum1_gate
                    let b_round_word_dense = RoundWordDense(spread_b_var_lo.clone().dense, spread_b_var_hi.clone().dense);
                    let c_round_word_dense = RoundWordDense(spread_c_var_lo.clone().dense, spread_c_var_hi.clone().dense);
                    let d_round_word_dense = RoundWordDense(spread_d_var_lo.clone().dense, spread_d_var_hi.clone().dense);
                    let sum_dense =
                    config.compression.assign_sum_afxk(
                        &mut region,
                        row,
                        b_round_word_dense,
                        c_round_word_dense,
                        d_round_word_dense,
                        self.k,
                    )?;
                    row += 3; // sum_afxk_gate requires three rows

                    // row = 76
                    config.compression.assign_decompose_0(&mut region, row, sum_dense.0, sum_dense.1, Value::known(self.sum_bcdk))?;
                    row += 1;
                    
                    // row = 77
                    // Testing sum1_gate
                    let b_round_word_dense = RoundWordDense(spread_b_var_lo.clone().dense, spread_b_var_hi.clone().dense);
                    let c_round_word_dense = RoundWordDense(spread_c_var_lo.clone().dense, spread_c_var_hi.clone().dense);
                    let sum_dense =
                    config.compression.assign_sum_re(
                        &mut region,
                        row,
                        b_round_word_dense,
                        c_round_word_dense,
                    )?;
                    row += 2; // sum_re_gate requires two rows

                    // row = 79
                    config.compression.assign_decompose_0(&mut region, row, sum_dense.0, sum_dense.1, Value::known(self.sum_bc))?;

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
        let k: u32 = rng.gen();
        let xor: u32 = b ^ c ^ d;
        let f2_bcd: u32 = f2(b, c, d);
        let f4_bcd: u32 = f4(b, c, d);
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
        let sum_bcdk = b.overflowing_add(c).0
            .overflowing_add(d).0
            .overflowing_add(k).0;
        let sum_bc = b.overflowing_add(c).0;

        let circuit = CompressionGateTester {
            b,
            c,
            d,
            k,
            xor,
            f2_bcd,
            f4_bcd,
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
            sum_bcdk,
            sum_bc,
        };

        let prover = MockProver::run(17, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

}