use halo2::{arithmetic::FieldExt, plonk::Expression};
use std::marker::PhantomData;

pub struct ScheduleGate<F: FieldExt>(PhantomData<F>);

impl<F: FieldExt> ScheduleGate<F> {
    /// s_decompose_0 for all words
    pub fn s_decompose_0(
        s_decompose_0: Expression<F>,
        lo: Expression<F>,
        hi: Expression<F>,
        word: Expression<F>,
    ) -> Option<(&'static str, Expression<F>)> {
        let check = lo + hi * F::from(1 << 16) - word;
        Some(("s_decompose_0", s_decompose_0 * check))
    }
}
