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
    fn s_f1(
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
    pub fn s_ch(
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
    pub fn s_ch_neg(
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
    pub fn s_or_not_xor(
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
    

}