/*
Modified version of code from https://github.com/privacy-scaling-explorations/halo2/blob/8c945507ceca5f4ed6e52da3672ea0308bcac812/halo2_gadgets/src/sha256/table16/gates.rs
*/

use halo2::{arithmetic::FieldExt, plonk::Expression};

pub struct Gate<F: FieldExt>(pub Expression<F>);

impl<F: FieldExt> Gate<F> {
    fn ones() -> Expression<F> {
        Expression::Constant(F::one())
    }

    // Helper gates
    fn lagrange_interpolate(
        var: Expression<F>,
        points: Vec<u16>,
        evals: Vec<u32>,
    ) -> (F, Expression<F>) {
        assert_eq!(points.len(), evals.len());
        let deg = points.len();

        fn factorial(n: u64) -> u64 {
            if n < 2 {
                1
            } else {
                n * factorial(n - 1)
            }
        }

        // Scale the whole expression by factor to avoid divisions
        let factor = factorial((deg - 1) as u64);

        let numerator = |var: Expression<F>, eval: u32, idx: u64| {
            let mut expr = Self::ones();
            for i in 0..deg {
                let i = i as u64;
                if i != idx {
                    expr = expr * (Self::ones() * (-F::one()) * F::from(i) + var.clone());
                }
            }
            expr * F::from(u64::from(eval))
        };
        let denominator = |idx: i32| {
            let mut denom: i32 = 1;
            for i in 0..deg {
                let i = i as i32;
                if i != idx {
                    denom *= idx - i
                }
            }
            if denom < 0 {
                -F::one() * F::from(factor / (-denom as u64))
            } else {
                F::from(factor / (denom as u64))
            }
        };

        let mut expr = Self::ones() * F::zero();
        for ((idx, _), eval) in points.iter().enumerate().zip(evals.iter()) {
            expr = expr + numerator(var.clone(), *eval, idx as u64) * denominator(idx as i32)
        }

        (F::from(factor), expr)
    }

    pub fn range_check(value: Expression<F>, lower_range: u64, upper_range: u64) -> Expression<F> {
        let mut expr = Self::ones();
        for i in lower_range..(upper_range + 1) {
            expr = expr * (Self::ones() * (-F::one()) * F::from(i) + value.clone())
        }
        expr
    }

    /// Range check on 2-bit word
    pub fn two_bit_range(
        value: Expression<F>,
    ) -> impl Iterator<Item = (&'static str, Expression<F>)> {
        std::iter::empty().chain(Some(
            ("two_bit_range_check", Self::range_check(value.clone(), 0, (1 << 2) - 1))
        ))
    }

    /// Range check on 3-bit word
    pub fn three_bit_range(
        value: Expression<F>,
    ) -> impl Iterator<Item = (&'static str, Expression<F>)> {
        std::iter::empty().chain(Some(
            ("three_bit_range_check", Self::range_check(value.clone(), 0, (1 << 3) - 1))
        ))
    }

    /// Range check on 4-bit word
    pub fn four_bit_range(
        value: Expression<F>,
    ) -> impl Iterator<Item = (&'static str, Expression<F>)> {
        std::iter::empty().chain(Some(
            ("four_bit_range_check", Self::range_check(value.clone(), 0, (1 << 4) - 1))
        ))
    }

    /// s_decompose_word for all words
    pub fn s_decompose_word(
        s_decompose_word: Expression<F>,
        lo: Expression<F>,
        hi: Expression<F>,
        word: Expression<F>,
    ) -> Option<(&'static str, Expression<F>)> {
        let check = lo + hi * F::from(1 << 16) - word;
        Some(("s_decompose_word", s_decompose_word * check))
    }
}
