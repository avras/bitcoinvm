use std::marker::PhantomData;
use ecc::{EccConfig, GeneralEccChip};
use ecdsa::ecdsa::{AssignedEcdsaSig, AssignedPublicKey};
use halo2_proofs::poly::Rotation;
use halo2_proofs::halo2curves::secp256k1::{Secp256k1Affine, Fq};
use halo2_proofs::plonk::{Selector, Column, Advice, Expression, ConstraintSystem, Error};
use halo2_proofs::circuit::{Layouter, Value, Region};
use integer::{IntegerInstructions, Range};
use maingate::{MainGateConfig, RangeConfig, RangeChip, RangeInstructions, MainGate, RegionCtx};

use super::constants::{NUMBER_OF_LIMBS, BIT_LEN_LIMB, PREFIX_PK_COMPRESSED_EVEN_Y, PREFIX_PK_UNCOMPRESSED, PREFIX_PK_COMPRESSED_ODD_Y};
use super::parity_table::{ParityTableConfig, ParityTableChip};
use super::util::sign_types::SignData;
use super::util::{range_check, pk_bytes_swap_endianness, rlc, ChipsRef, integer_to_bytes_le, copy_integer_bytes_le, AssignedPublicKeyRLC, AssignedPublicKeyBytes};
use super::{Field, constants::PK_POW_RAND_SIZE};

/// Gadget to verify the OP_CHECKSIG opcode
#[derive(Clone, Default, Debug)]
pub struct OpCheckSigChip<F: Field, const MAX_OPCODE_COUNT: usize> {
    /// Aux generator for EccChip
    pub aux_generator: Secp256k1Affine,
    /// Window size for EccChip
    pub window_size: usize,
    /// Marker
    pub _marker: PhantomData<F>,
}

/// OpCheckSig configuration
#[derive(Debug, Clone)]
pub(crate) struct OpCheckSigConfig<F: Field> {
    q_enable: Selector,

    // Prefix byte public key serialization used to calculate pk_rlc
    pk_prefix: Column<Advice>,

    // RLC of the public key serialization as it appears in the scriptPubKey
    pk_rlc: Column<Advice>,

    // First 32 cells = x coordinate as LE bytes, next 32 cells = y coordinate as LE bytes
    pk: [[Column<Advice>; 32]; 2],

    // Table to check parity of y coordinate matches pk_prefix
    parity_table: ParityTableConfig,

    // Powers of a randomness to compute RLCs
    power_of_randomness: [Expression<F>; PK_POW_RAND_SIZE],

    // ECDSA
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl<F: Field> OpCheckSigConfig<F> {
    pub(crate) fn new(
        meta: &mut ConstraintSystem<F>,
        power_of_randomness: [Expression<F>; PK_POW_RAND_SIZE],
    ) -> Self {
        let q_enable: Selector = meta.complex_selector();

        let pk_prefix = meta.advice_column();
        meta.enable_equality(pk_prefix);

        let pk_rlc = meta.advice_column();
        meta.enable_equality(pk_rlc);

        let pk = [(); 2].map(|_| [(); 32].map(|_| meta.advice_column()));
        pk.iter()
           .for_each(|coord| coord.iter().for_each(|c| meta.enable_equality(*c)));
       
        meta.create_gate("Check that pk_prefix byte is in correct range", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let pk_prefix = meta.query_advice(pk_prefix, Rotation::cur());
            vec![q_enable * range_check(pk_prefix, PREFIX_PK_COMPRESSED_EVEN_Y, PREFIX_PK_UNCOMPRESSED)]
        });

        meta.create_gate("Check that pk_rlc is consistent with pk", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let pk_prefix = meta.query_advice(pk_prefix, Rotation::cur());
            let pk_rlc = meta.query_advice(pk_rlc, Rotation::cur());

            let pk_le: [Expression<F>; 64] = pk
                .map(|coord| coord.map(|c| meta.query_advice(c, Rotation::cur())))
                .iter()
                .flatten()
                .cloned()
                .collect::<Vec<Expression<F>>>()
                .try_into()
                .expect("vector to array of size 64");

            let pk_be = pk_bytes_swap_endianness(&pk_le);
            let mut prefixed_pk_be = pk_be.to_vec();
            prefixed_pk_be.insert(0, pk_prefix.clone());
            let prefixed_pk_be_slice = prefixed_pk_be.as_slice();
            let uncompressed_pk_rlc = rlc::expr(prefixed_pk_be_slice, &power_of_randomness);

            // The gate expression is non-zero only when prefix byte is 0x04
            let uncompressed_pk_gate =
                (pk_prefix.clone() - Expression::Constant(F::from(PREFIX_PK_COMPRESSED_EVEN_Y)))
                * (pk_prefix.clone() - Expression::Constant(F::from(PREFIX_PK_COMPRESSED_ODD_Y)));

            // Only the prefix byte and x coordinate are considered
            let compressed_pk_rlc = rlc::expr(&prefixed_pk_be_slice[..33], &power_of_randomness);
            // The gate expression is non-zero when prefix byte is 0x02 or 0x03
            let compressed_pk_gate = pk_prefix - Expression::Constant(F::from(PREFIX_PK_UNCOMPRESSED));

            
            vec![
                q_enable.clone() * uncompressed_pk_gate * (pk_rlc.clone() - uncompressed_pk_rlc),
                q_enable * compressed_pk_gate * (pk_rlc - compressed_pk_rlc),
            ]
        });

        // The LSB of the y coordinate is located at pk[1][0]
        let parity_table = ParityTableChip::configure(meta, pk_prefix, pk[1][0]);

        // ECDSA config
        let (rns_base, rns_scalar) =
            GeneralEccChip::<Secp256k1Affine, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
        let main_gate_config = MainGate::<F>::configure(meta);
        let mut overflow_bit_lengths: Vec<usize> = vec![];
        overflow_bit_lengths.extend(rns_base.overflow_lengths());
        overflow_bit_lengths.extend(rns_scalar.overflow_lengths());
        let range_config = RangeChip::<F>::configure(
            meta,
            &main_gate_config,
            vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS, 8],
            overflow_bit_lengths,
        );        

        Self {
            q_enable,
            pk_prefix,
            pk_rlc,
            pk,
            parity_table,
            power_of_randomness,
            main_gate_config,
            range_config,
        }
    }
    
    pub(crate) fn load_range(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let range_chip = RangeChip::<F>::new(self.range_config.clone());
        range_chip.load_table(layouter)
    }

    pub(crate) fn ecc_chip_config(&self) -> EccConfig {
        EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }

}

impl<F: Field, const MAX_OPCODE_COUNT: usize> OpCheckSigChip<F, MAX_OPCODE_COUNT> {
    fn assign_aux(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        ecc_chip: &mut GeneralEccChip<Secp256k1Affine, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        ecc_chip.assign_aux_generator(ctx, Value::known(self.aux_generator))?;
        ecc_chip.assign_aux(ctx, self.window_size, 1)?;
        Ok(())
    }

    fn assign_ecdsa(
        &self,
        ctx: &mut RegionCtx<F>,
        chips: &ChipsRef<F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        sign_data: &SignData,
    ) -> Result<AssignedPublicKeyBytes<F>, Error> {
        let SignData {
            signature,
            pk,
        } = sign_data;
        let (sig_r, sig_s) = signature;

        let ChipsRef {
            main_gate: _,
            range_chip,
            ecc_chip,
            scalar_chip,
            ecdsa_chip,
        } = chips;

        let integer_r = ecc_chip.new_unassigned_scalar(Value::known(*sig_r));
        let integer_s = ecc_chip.new_unassigned_scalar(Value::known(*sig_s));
        // Message hash is always the field element 1 since we only need to prove ownership, not spend
        let msg_hash = ecc_chip.new_unassigned_scalar(Value::known(Fq::one()));

        let r_assigned = scalar_chip.assign_integer(ctx, integer_r, Range::Remainder)?;
        let s_assigned = scalar_chip.assign_integer(ctx, integer_s, Range::Remainder)?;
        let sig = AssignedEcdsaSig {
            r: r_assigned,
            s: s_assigned,
        };

        let pk_in_circuit = ecc_chip.assign_point(ctx, Value::known(*pk))?;
        let pk_assigned = AssignedPublicKey {
            point: pk_in_circuit,
        };
        let msg_hash = scalar_chip.assign_integer(ctx, msg_hash, Range::Remainder)?;

        // Convert (pk_x, pk_y) integers to little endian bytes
        let pk_x = pk_assigned.point.x();
        let pk_x_le = integer_to_bytes_le(ctx, range_chip, pk_x)?;
        let pk_y = pk_assigned.point.y();
        let pk_y_le = integer_to_bytes_le(ctx, range_chip, pk_y)?;

        // Ref. spec SignVerifyChip 4. Verify the ECDSA signature
        ecdsa_chip.verify(ctx, &sig, &pk_assigned, &msg_hash)?;

        // TODO: Update once halo2wrong suports the following methods:
        // - `IntegerChip::assign_integer_from_bytes_le`
        // - `GeneralEccChip::assing_point_from_bytes_le`

        Ok(AssignedPublicKeyBytes {
            pk_x_le,
            pk_y_le,
        })
    }


    #[allow(clippy::too_many_arguments)]
    fn assign_opchecksig(
        &self,
        config: &OpCheckSigConfig<F>,
        region: &mut Region<'_, F>,
        offset: usize,
        randomness: F,
        sign_data: Option<&SignData>,
        assigned_pk_bytes: &AssignedPublicKeyBytes<F>,
    ) -> Result<AssignedPublicKeyRLC<F>, Error> {
        let (padding, sign_data) = match sign_data {
            Some(sign_data) => (false, sign_data.clone()),
            None => (true, SignData::default()),
        };
        let SignData {
            signature: _,
            pk,
        } = sign_data;

        // Copy constraints between pub_key and msg_hash
        // bytes of this chip and the ECDSA chip
        copy_integer_bytes_le(
            region,
            "pk_x",
            &assigned_pk_bytes.pk_x_le,
            &config.pk[0],
            offset,
        )?;
        copy_integer_bytes_le(
            region,
            "pk_y",
            &assigned_pk_bytes.pk_y_le,
            &config.pk[1],
            offset,
        )?;

        config.q_enable.enable(region, offset)?;


        Ok(
            AssignedPublicKeyRLC { pk_rlc: unimplemented!() } 
        )
    }

}