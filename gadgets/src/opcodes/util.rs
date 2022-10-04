pub mod sign_types;

use ecc::GeneralEccChip;
use ecdsa::ecdsa::EcdsaChip;
use halo2_proofs::{arithmetic::FieldExt, plonk::{Expression, Error, Column, Advice}, halo2curves::secp256k1::{Secp256k1Affine, self}, circuit::{AssignedCell, Region}};
use integer::{AssignedInteger, IntegerChip};
use maingate::{AssignedValue, RegionCtx, MainGate, MainGateInstructions, RangeChip, RangeInstructions};

use super::{Field, constants::{NUMBER_OF_LIMBS, BIT_LEN_LIMB}};
use itertools::Itertools;

pub fn range_check<F: FieldExt> (value: Expression<F>, lower_range: u64, upper_range: u64) -> Expression<F> {
    let one = Expression::Constant(F::one());
    let mut expr = one.clone();
    for i in lower_range..(upper_range + 1) {
        expr = expr * (one.clone() * (-F::one()) * F::from(i) + value.clone())
    }
    expr
}

/// Return a copy of the serialized public key with swapped Endianness.
pub fn pk_bytes_swap_endianness<T: Clone>(pk: &[T]) -> [T; 64] {
    assert_eq!(pk.len(), 64);
    let mut pk_swap = <&[T; 64]>::try_from(pk)
        .map(|r| r.clone())
        .expect("pk.len() != 64");
    pk_swap[..32].reverse();
    pk_swap[32..].reverse();
    pk_swap
}


/// Returns the random linear combination of the inputs.
/// Encoding is done as follows: v_0 * R^0 + v_1 * R^1 + ...
pub(crate) mod rlc {
    use halo2_proofs::{arithmetic::FieldExt, plonk::Expression};

    pub(crate) fn expr<F: FieldExt>(
        expressions: &[Expression<F>],
        power_of_randomness: &[Expression<F>],
    ) -> Expression<F> {
        debug_assert!(expressions.len() <= power_of_randomness.len() + 1);

        let mut rlc = expressions[0].clone();
        for (expression, randomness) in expressions[1..].iter().zip(power_of_randomness.iter()) {
            rlc = rlc + (*expression).clone() * (*randomness).clone();
        }
        rlc
    }

    pub(crate) fn value<'a, F: FieldExt, I>(values: I, randomness: F) -> F
    where
        I: IntoIterator<Item = &'a u8>,
        <I as IntoIterator>::IntoIter: DoubleEndedIterator,
    {
        values.into_iter().rev().fold(F::zero(), |acc, value| {
            acc * randomness + F::from(*value as u64)
        })
    }
}


pub(crate) struct AssignedPublicKeyBytes<F: Field> {
    pub(crate) pk_x_le: [AssignedValue<F>; 32],
    pub(crate) pk_y_le: [AssignedValue<F>; 32],
}

#[derive(Debug)]
pub(crate) struct AssignedPublicKeyRLC<F: Field> {
    pub(crate) pk_rlc: AssignedCell<F, F>,
}

// Returns assigned constants [256^1, 256^2, .., 256^{n-1}]
pub(crate) fn assign_pows_256<F: Field>(
    ctx: &mut RegionCtx<'_, F>,
    main_gate: &MainGate<F>,
    n: usize,
) -> Result<Vec<AssignedValue<F>>, Error> {
    let mut pows = Vec::new();
    for i in 1..n {
        pows.push(main_gate.assign_constant(ctx, F::from(256).pow(&[i as u64, 0, 0, 0]))?);
    }
    Ok(pows)
}

// Return an array of bytes that corresponds to the little endian representation
// of the integer, adding the constraints to verify the correctness of the
// conversion (byte range check included).
pub(crate) fn integer_to_bytes_le<F: Field, FE: FieldExt>(
    ctx: &mut RegionCtx<'_, F>,
    range_chip: &RangeChip<F>,
    int: &AssignedInteger<FE, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
) -> Result<[AssignedValue<F>; 32], Error> {
    let (_, limb0_bytes) =
        range_chip.decompose(ctx, int.limbs()[0].as_ref().value().copied(), 8, 72)?;
    let (_, limb1_bytes) =
        range_chip.decompose(ctx, int.limbs()[1].as_ref().value().copied(), 8, 72)?;
    let (_, limb2_bytes) =
        range_chip.decompose(ctx, int.limbs()[2].as_ref().value().copied(), 8, 72)?;
    let (_, limb3_bytes) =
        range_chip.decompose(ctx, int.limbs()[3].as_ref().value().copied(), 8, 40)?;
    Ok(std::iter::empty()
        .chain(limb0_bytes)
        .chain(limb1_bytes)
        .chain(limb2_bytes)
        .chain(limb3_bytes)
        .collect_vec()
        .try_into()
        .unwrap())
}

/// Constraint equality (using copy constraints) between `src` integer bytes and
/// `dst` integer bytes. Then assign the `dst` values from `src`.
pub(crate) fn copy_integer_bytes_le<F: Field>(
    region: &mut Region<'_, F>,
    name: &str,
    src: &[AssignedValue<F>; 32],
    dst: &[Column<Advice>; 32],
    offset: usize,
) -> Result<(), Error> {
    for (i, byte) in src.iter().enumerate() {
        let assigned_cell = region.assign_advice(
            || format!("{} byte {}", name, i),
            dst[i],
            offset,
            || byte.value().copied(),
        )?;
        region.constrain_equal(assigned_cell.cell(), byte.cell())?;
    }
    Ok(())
}

/// Helper structure pass around references to all the chips required for an
/// ECDSA verification.
pub(crate) struct ChipsRef<'a, F: Field, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> {
    pub(crate) main_gate: &'a MainGate<F>,
    pub(crate) range_chip: &'a RangeChip<F>,
    pub(crate) ecc_chip: &'a GeneralEccChip<Secp256k1Affine, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    pub(crate) scalar_chip: &'a IntegerChip<secp256k1::Fq, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    pub(crate) ecdsa_chip: &'a EcdsaChip<Secp256k1Affine, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}