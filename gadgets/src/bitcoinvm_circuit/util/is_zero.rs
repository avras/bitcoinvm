//! IsZero gadget works as follows:
//!
//! Given a `value` to be checked if it is zero:
//!  - witnesses `inv0(value)`, where `inv0(x)` is 0 when `x` = 0, and
//!  `1/x` otherwise

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Chip, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
    poly::Rotation,
};

use super::expr::Expr;

/// Trait that needs to be implemented for any gadget or circuit that wants to
/// implement `IsZero`.
pub trait IsZeroInstruction<F: FieldExt> {
    /// Given a `value` to be checked if it is zero:
    ///   - witnesses `inv0(value)`, where `inv0(x)` is 0 when `x` = 0, and
    ///     `1/x` otherwise
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Value<F>,
    ) -> Result<(), Error>;
}

/// Config struct representing the required fields for an `IsZero` config to
/// exist.
#[derive(Clone, Debug)]
pub struct IsZeroConfig<F> {
    /// Modular inverse of the value.
    pub value_inv: Column<Advice>,
    /// This can be used directly for custom gate at the offset if `is_zero` is
    /// called, it will be 1 if `value` is zero, and 0 otherwise.
    pub is_zero_expression: Expression<F>,
}

impl<F: FieldExt> IsZeroConfig<F> {
    /// Returns the is_zero expression
    pub fn expr(&self) -> Expression<F> {
        self.is_zero_expression.clone()
    }
}

/// Wrapper arround [`IsZeroConfig`] for which [`Chip`] is implemented.
pub struct IsZeroChip<F> {
    config: IsZeroConfig<F>,
}

#[rustfmt::skip]
impl<F: FieldExt> IsZeroChip<F> {
    /// Sets up the configuration of the chip by creating the required columns
    /// and defining the constraints that take part when using `is_zero` gate.
    ///
    /// Truth table of iz_zero gate:
    /// +----+-------+-----------+-----------------------+---------------------------------+-------------------------------------+
    /// | ok | value | value_inv | 1 - value ⋅ value_inv | value ⋅ (1 - value ⋅ value_inv) | value_inv ⋅ (1 - value ⋅ value_inv) |
    /// +----+-------+-----------+-----------------------+---------------------------------+-------------------------------------+
    /// | V  | 0     | 0         | 1                     | 0                               | 0                                   |
    /// |    | 0     | x         | 1                     | 0                               | x                                   |
    /// |    | x     | 0         | 1                     | x                               | 0                                   |
    /// | V  | x     | 1/x       | 0                     | 0                               | 0                                   |
    /// |    | x     | y         | 1 - xy                | x(1 - xy)                       | y(1 - xy)                           |
    /// +----+-------+-----------+-----------------------+---------------------------------+-------------------------------------+
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        value: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        value_inv: Column<Advice>,
    ) -> IsZeroConfig<F> {
        // dummy initialization
        let mut is_zero_expression = 0.expr();

        meta.create_gate("is_zero gate", |meta| {
            let q_enable = q_enable(meta);

            let value_inv = meta.query_advice(value_inv, Rotation::cur());
            let value = value(meta);

            is_zero_expression = 1.expr() - value.clone() * value_inv;

            // We wish to satisfy the below constrain for the following cases:
            //
            // 1. value == 0
            // 2. if value != 0, require is_zero_expression == 0 => value_inv == value.invert()
            [q_enable * value * is_zero_expression.clone()]
        });

        IsZeroConfig::<F> {
            value_inv,
            is_zero_expression,
        }
    }

    /// Given an `IsZeroConfig`, construct the chip.
    pub fn construct(config: IsZeroConfig<F>) -> Self {
        IsZeroChip { config }
    }
}

impl<F: FieldExt> IsZeroInstruction<F> for IsZeroChip<F> {
    fn assign(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        value: Value<F>,
    ) -> Result<(), Error> {
        let config = self.config();

        let value_invert = value.map(|value| value.invert().unwrap_or(F::zero()));
        region.assign_advice(
            || "witness inverse of value",
            config.value_inv,
            offset,
            || value_invert,
        )?;

        Ok(())
    }
}

impl<F: FieldExt> Chip<F> for IsZeroChip<F> {
    type Config = IsZeroConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}