use std::marker::PhantomData;
use crate::Field;
use crate::bitcoinvm_circuit::execution::ExecutionChipAssignedCells;
use crate::bitcoinvm_circuit::util::expr::Expr;
use crate::bitcoinvm_circuit::util::is_zero::{IsZeroConfig, IsZeroChip, IsZeroInstruction};
use ecc::{EccConfig, GeneralEccChip};
use ecdsa::ecdsa::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};
use halo2_proofs::poly::Rotation;
use halo2_proofs::halo2curves::secp256k1::{Secp256k1Affine, Fq};
use halo2_proofs::plonk::{Selector, Column, Advice, Expression, ConstraintSystem, Error};
use halo2_proofs::circuit::{Layouter, Value, Region};
use integer::{IntegerInstructions, Range};
use maingate::{MainGateConfig, RangeConfig, RangeChip, RangeInstructions, MainGate, RegionCtx};

use crate::bitcoinvm_circuit::constants::*;
use super::parity_table::{ParityTableConfig, ParityTableChip};
use super::super::util::sign_util::SignData;
use super::checksig_util::{range_check, pk_bytes_swap_endianness, rlc, ChipsRef, integer_to_bytes_le, copy_integer_bytes_le, AssignedPublicKeyBytes, ct_option_ok_or};
use super::super::util::pk_parser::PublicKeyInScript;

const PK_POW_RAND_SIZE: usize = 64;

/// OpCheckSig configuration
#[derive(Debug, Clone)]
pub(crate) struct OpCheckSigConfig<F: Field> {
    q_enable: Selector,

    // Number of CHECKSIG opcodes found in scriptPubkey; one signature required per public key
    num_checksig_opcodes: Column<Advice>,
    num_checksig_opcodes_inv: Column<Advice>,
    num_checksig_opcodes_is_zero: IsZeroConfig<F>,

    // Accumulator value of public key RLCs
    pk_rlc_acc: Column<Advice>,

    // RLC of the public key serialization as it appears in the scriptPubKey
    pk_rlc: Column<Advice>,

    // Prefix byte public key serialization used to calculate pk_rlc
    pk_prefix: Column<Advice>,

    // First 32 cells = x coordinate as LE bytes, next 32 cells = y coordinate as LE bytes
    pk: [[Column<Advice>; 32]; 2],

    // Powers of a randomness to compute RLCs
    powers_of_randomness: [Column<Advice>; PK_POW_RAND_SIZE],

    // Table to check parity of y coordinate matches pk_prefix
    parity_table: ParityTableConfig,

    // ECDSA
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl<F: Field> OpCheckSigConfig<F> {
    pub(crate) fn load_range(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let range_chip = RangeChip::<F>::new(self.range_config.clone());
        range_chip.load_table(layouter)
    }

    pub(crate) fn ecc_chip_config(&self) -> EccConfig {
        EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }
}


/// Gadget to verify the OP_CHECKSIG opcode
#[derive(Clone, Debug)]
pub(crate) struct OpCheckSigChip<F: Field, const MAX_CHECKSIG_COUNT: usize> {
    /// Aux generator for EccChip
    pub aux_generator: Secp256k1Affine,
    /// Window size for EccChip
    pub window_size: usize,
    /// Marker
    pub _marker: PhantomData<F>,
}

impl<F: Field, const MAX_CHECKSIG_COUNT: usize> OpCheckSigChip<F, MAX_CHECKSIG_COUNT> {
    pub fn construct(
        aux_generator: Secp256k1Affine,
        window_size: usize,
    ) -> Self {
        Self {
            aux_generator,
            window_size,
            _marker: PhantomData,
        }
    }

    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
    ) -> OpCheckSigConfig<F> {
        let q_enable: Selector = meta.complex_selector();

        let num_checksig_opcodes = meta.advice_column();
        meta.enable_equality(num_checksig_opcodes);
        let num_checksig_opcodes_inv = meta.advice_column();
        meta.enable_equality(num_checksig_opcodes_inv);


        let num_checksig_opcodes_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_enable),
            |meta| meta.query_advice(num_checksig_opcodes, Rotation::cur()),
            num_checksig_opcodes_inv,
        );

        let pk_rlc_acc = meta.advice_column();
        meta.enable_equality(pk_rlc_acc);

        let pk_rlc = meta.advice_column();
        meta.enable_equality(pk_rlc);

        let pk_prefix = meta.advice_column();
        meta.enable_equality(pk_prefix);

        let pk = [(); 2].map(|_| [(); 32].map(|_| meta.advice_column()));
        pk.iter()
           .for_each(|coord| coord.iter().for_each(|c| meta.enable_equality(*c)));

        let powers_of_randomness = [(); PK_POW_RAND_SIZE].map(|_| meta.advice_column());
        powers_of_randomness.iter().for_each(|p| meta.enable_equality(*p));
       
        // The LSB of the y coordinate is located at pk[1][0]
        let parity_table = ParityTableChip::configure(meta, q_enable, pk_prefix, pk[1][0]);

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

        meta.create_gate("Check that the powers of randomness are consistent", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let cur_power_one = meta.query_advice(powers_of_randomness[0], Rotation::cur());
            let next_power_one = meta.query_advice(powers_of_randomness[0], Rotation::next());

            let mut constraints = vec![q_enable.clone() * (cur_power_one.clone() - next_power_one)];

            let cur_power_two = meta.query_advice(powers_of_randomness[1], Rotation::cur());
            constraints.push(q_enable.clone() * (cur_power_two - cur_power_one.clone() * cur_power_one.clone()));

            for i in 2..PK_POW_RAND_SIZE {
                let cur_power_i = meta.query_advice(powers_of_randomness[i], Rotation::cur());
                let cur_power_i_minus_one = meta.query_advice(powers_of_randomness[i-1], Rotation::cur());
                constraints.push(q_enable.clone() * (cur_power_i - cur_power_i_minus_one.clone() * cur_power_one.clone()));
            }
            
            constraints
        });

        meta.create_gate("Check that pk_rlc_acc is zero when num_checksig_opcodes is zero", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let cur_pk_rlc_acc = meta.query_advice(pk_rlc_acc, Rotation::cur());

            vec![
                q_enable
                * num_checksig_opcodes_is_zero.expr()
                * cur_pk_rlc_acc
            ]
        });

        meta.create_gate("Check that pk_rlc is consistent with pk_rlc_acc", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let pk_rlc = meta.query_advice(pk_rlc, Rotation::cur());
            let cur_pk_rlc_acc = meta.query_advice(pk_rlc_acc, Rotation::cur());
            let next_pk_rlc_acc = meta.query_advice(pk_rlc_acc, Rotation::next());
            let randomness = meta.query_advice(powers_of_randomness[0], Rotation::cur());

            vec![
                q_enable
                * (1u8.expr() - num_checksig_opcodes_is_zero.expr())
                * (pk_rlc + randomness * next_pk_rlc_acc - cur_pk_rlc_acc)
            ]
        });

        meta.create_gate("Check that pk_prefix byte is in correct range", |meta| {
            let q_enable = meta.query_selector(q_enable);
            let pk_prefix = meta.query_advice(pk_prefix, Rotation::cur());
            vec![
                q_enable
                * (1u8.expr() - num_checksig_opcodes_is_zero.expr())
                * range_check(pk_prefix, PREFIX_PK_COMPRESSED_EVEN_Y, PREFIX_PK_UNCOMPRESSED)]
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
            
            let powers_of_randomness: [Expression<F>; PK_POW_RAND_SIZE] = powers_of_randomness
                .map(|p| meta.query_advice(p, Rotation::cur()))
                .iter()
                .cloned()
                .collect::<Vec<Expression<F>>>()
                .try_into()
                .expect("vector to array of size 64");

            let pk_be = pk_bytes_swap_endianness(&pk_le);
            let mut prefixed_pk_be = pk_be.to_vec();
            prefixed_pk_be.insert(0, pk_prefix.clone());
            prefixed_pk_be.reverse();
            let prefixed_pk_be_slice = prefixed_pk_be.as_slice();
            let uncompressed_pk_rlc = rlc::expr(prefixed_pk_be_slice, &powers_of_randomness);

            // The gate expression is non-zero only when prefix byte is 0x04
            let uncompressed_pk_gate =
                (pk_prefix.clone() - Expression::Constant(F::from(PREFIX_PK_COMPRESSED_EVEN_Y)))
                * (pk_prefix.clone() - Expression::Constant(F::from(PREFIX_PK_COMPRESSED_ODD_Y)));

            // Only the prefix byte and x coordinate are considered
            let compressed_pk_rlc = rlc::expr(&prefixed_pk_be_slice[32..], &powers_of_randomness);
            // The gate expression is non-zero when prefix byte is 0x02 or 0x03
            let compressed_pk_gate = pk_prefix - Expression::Constant(F::from(PREFIX_PK_UNCOMPRESSED));

            
            vec![
                q_enable.clone() * uncompressed_pk_gate * (pk_rlc.clone() - uncompressed_pk_rlc),
                q_enable * compressed_pk_gate * (pk_rlc - compressed_pk_rlc),
            ]
        });

        OpCheckSigConfig {
            q_enable,
            num_checksig_opcodes,
            num_checksig_opcodes_inv,
            num_checksig_opcodes_is_zero,
            pk_rlc_acc,
            pk_rlc,
            pk_prefix,
            pk,
            powers_of_randomness,
            parity_table,
            main_gate_config,
            range_config,
        }
    }
    
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
        // Message hash is always a fixed field element since we only need to prove ownership, not spend
        let msg_hash = ecc_chip.new_unassigned_scalar(Value::known(Fq::from(ECDSA_MESSAGE_HASH as u64)));

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


    pub(crate) fn assign(
        &self,
        config: &OpCheckSigConfig<F>,
        layouter: &mut impl Layouter<F>,
        execution_cells: &ExecutionChipAssignedCells<F>,
        randomness: F,
        signatures: &[SignData],
        collected_pks: &[PublicKeyInScript],
    ) -> Result<(), Error> {
        if signatures.len() > MAX_CHECKSIG_COUNT || signatures.len() != collected_pks.len() {
            return Err(Error::Synthesis);
        }

        for i in 0..signatures.len() {
            // The two vectors should have the same public keys
            if signatures[i].pk != collected_pks[i].pk {
                return Err(Error::Synthesis);
            }
        }

        // Load the range table
        config.load_range(layouter)?;

        let main_gate = MainGate::new(config.main_gate_config.clone());
        let range_chip = RangeChip::new(config.range_config.clone());
        let mut ecc_chip = GeneralEccChip::<Secp256k1Affine, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(
            config.ecc_chip_config(),
        );
        let cloned_ecc_chip = ecc_chip.clone();
        let scalar_chip = cloned_ecc_chip.scalar_field_chip();

        layouter.assign_region(
            || "ecc chip aux",
            |region| self.assign_aux(&mut RegionCtx::new(region, 0), &mut ecc_chip),
        )?;

        let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());

        let mut assigned_pks = Vec::new();

        let chips = ChipsRef {
            main_gate: &main_gate,
            range_chip: &range_chip,
            ecc_chip: &ecc_chip,
            scalar_chip,
            ecdsa_chip: &ecdsa_chip,
        };

        layouter.assign_region(
            || "ecdsa chip verification",
            |region| {
                assigned_pks.clear();
                let offset = &mut 0;
                let mut ctx = RegionCtx::new(region, *offset);
                for i in 0..MAX_CHECKSIG_COUNT {
                    let signature = if i < signatures.len() {
                        signatures[i].clone()
                    } else {
                        // padding (enabled when number of OP_CHECKSIG opcodes is less than max number)
                        SignData::default()
                    };
                    let assigned_pk = self.assign_ecdsa(&mut ctx, &chips, &signature)?;
                    assigned_pks.push(assigned_pk);
                }
                Ok(())
            },
        )?;


        ParityTableChip::load(config.parity_table.clone(), layouter)?;
        
        let mut pk_rlc_acc: F = F::zero();
        for i in 0..collected_pks.len() {
            for b in collected_pks[i].clone().bytes {
                pk_rlc_acc = F::from(b as u64) + randomness * pk_rlc_acc;
            }
        }

        layouter.assign_region(
            || "OP_CHECKSIG public key collection verification",
            |mut region: Region<F>| {
                let num_checksig_opcodes_is_zero_chip
                    = IsZeroChip::construct(config.num_checksig_opcodes_is_zero.clone());

                // an extra row is assigned as queries are made to next rows
                for offset in 0..MAX_CHECKSIG_COUNT+1 {

                    if offset < MAX_CHECKSIG_COUNT {
                        // Enable selector in MAX_CHECKSIG_COUNT rows
                        config.q_enable.enable(&mut region, offset)?;

                        let mut power = randomness;
                        for i in 0..PK_POW_RAND_SIZE {
                            let rcell = region.assign_advice(
                                || "Assign (i+1)th power of randomness",
                                config.powers_of_randomness[i],
                                offset,
                                || Value::known(power),
                            )?;
                            // The value in the first row and first power_of_randomness array is constrained
                            // to be equal to the randomness value used in the ExecutionChip
                            if offset == 0 && i == 0 {
                                region.constrain_equal(rcell.cell(), execution_cells.randomness.cell())?;
                            }
                            power = power * randomness;
                        }
                    }
                    else {
                        // The randomness value is queried in the extra row
                        region.assign_advice(
                            || "Assign first power of randomness in extra row",
                            config.powers_of_randomness[0],
                            offset,
                            || Value::known(randomness),
                        )?;

                        // The pk_rlc_acc value is queried in the extra row
                        region.assign_advice(
                            || "Assign pk_rlc_acc in extra row",
                            config.pk_rlc_acc,
                            offset,
                            || Value::known(F::zero()),
                        )?;
                    }
                    
                    if offset < collected_pks.len() {
                        let num_checksig_opcodes_remaining = F::from((collected_pks.len() - offset) as u64);
                        let num_cs_cell = region.assign_advice(
                            || "Number of OP_CHECKSIG operations",
                            config.num_checksig_opcodes,
                            offset,
                            || Value::known(num_checksig_opcodes_remaining),
                        )?;

                        // The value in the first row of the num_checksig_opcodes column is constrained
                        // to be equal to the num_checksig_opcodes value calculated in the ExecutionChip
                        if offset == 0 {
                            region.constrain_equal(num_cs_cell.cell(), execution_cells.num_checksig_opcodes.cell())?;
                        }

                        num_checksig_opcodes_is_zero_chip.assign(
                            &mut region,
                            offset,
                            Value::known(num_checksig_opcodes_remaining),
                        )?;
                       
                        // Assign public key bytes
                        copy_integer_bytes_le(
                            &mut region,
                            "pk_x",
                            &assigned_pks[offset].pk_x_le,
                            &config.pk[0],
                            offset,
                        )?;
                        copy_integer_bytes_le(
                            &mut region,
                            "pk_y",
                            &assigned_pks[offset].pk_y_le,
                            &config.pk[1],
                            offset,
                        )?;

                        region.assign_advice(
                            || "Public key prefix byte",
                            config.pk_prefix,
                            offset,
                            || Value::known(F::from(collected_pks[offset].bytes[0] as u64)),
                        )?;

                        let mut pk_rlc = F::zero();
                        for b in collected_pks[offset].clone().bytes {
                            pk_rlc = F::from(b as u64) + randomness * pk_rlc;
                        }

                        region.assign_advice(
                            || "Public key RLC accumulator",
                            config.pk_rlc,
                            offset,
                            || Value::known(pk_rlc),
                        )?;
                        
                        let acc_cell = region.assign_advice(
                            || "Public key RLC accumulator",
                            config.pk_rlc_acc,
                            offset,
                            || Value::known(pk_rlc_acc),
                        )?;

                        // The value in the first row of the pk_rlc_acc column is constrained
                        // to be equal to the pk_rlc_acc value calculated in the ExecutionChip
                        if offset == 0 {
                            region.constrain_equal(acc_cell.cell(), execution_cells.pk_rlc_acc.cell())?;
                        }
                        
                        let randomness_inv = ct_option_ok_or(randomness.invert(), Error::Synthesis).unwrap();
                        // Update the value of pk_rlc_acc
                        pk_rlc_acc = randomness_inv * (pk_rlc_acc - pk_rlc);
                    }
                    else {
                        region.assign_advice(
                            || "Number of OP_CHECKSIG operations",
                            config.num_checksig_opcodes,
                            offset,
                            || Value::known(F::zero()),
                        )?;

                        num_checksig_opcodes_is_zero_chip.assign(
                            &mut region,
                            offset,
                            Value::known(F::zero()),
                        )?;

                        region.assign_advice(
                            || "Public key RLC accumulator",
                            config.pk_rlc_acc,
                            offset,
                            || Value::known(pk_rlc_acc),
                        )?;
                        
                    }
                }
                Ok(())
            },
        )?;
        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use halo2_proofs::arithmetic::Field as HaloField;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::CurveAffine;
    use halo2_proofs::halo2curves::bn256::Fr as BnScalar;
    use halo2_proofs::circuit::{SimpleFloorPlanner, Layouter};
    use halo2_proofs::halo2curves::{secp256k1::{Secp256k1Affine, Fq, Fp}};
    use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
    use rand::{Rng, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use secp256k1::{self, Secp256k1, SecretKey, PublicKey};
    use secp256k1::constants::PUBLIC_KEY_SIZE;

    use crate::bitcoinvm_circuit::constants::*;
    use crate::bitcoinvm_circuit::crypto_opcodes::checksig::checksig_util::{ct_option_ok_or, pk_bytes_swap_endianness};
    use crate::bitcoinvm_circuit::crypto_opcodes::util::pk_parser::{PublicKeyInScript, collect_public_keys, StackElement};
    use crate::bitcoinvm_circuit::crypto_opcodes::util::sign_util::{SignData, sign};
    use crate::bitcoinvm_circuit::execution::{ExecutionChip, ExecutionConfig};
    use super::{OpCheckSigChip, OpCheckSigConfig};
    use crate::Field;

    #[derive(Clone, Debug)]
    struct TestOpChecksigCircuitConfig<F: Field, const MAX_CHECKSIG_COUNT: usize> {
        execution_config: ExecutionConfig<F>,
        op_checksig_config: OpCheckSigConfig<F>,
    }

    struct TestOpChecksigCircuit<F: Field, const MAX_CHECKSIG_COUNT: usize> {
        pub op_checksig_chip: OpCheckSigChip<F, MAX_CHECKSIG_COUNT>,
        pub script_pubkey: Vec<u8>,
        pub randomness: F,
        pub initial_stack: [F; MAX_STACK_DEPTH],
        pub signatures: Vec<SignData>,
        pub collected_pks: Vec<PublicKeyInScript>,
    }

    impl<F: Field, const MAX_CHECKSIG_COUNT: usize> Circuit<F> for TestOpChecksigCircuit<F, MAX_CHECKSIG_COUNT> {
        type Config = TestOpChecksigCircuitConfig<F, MAX_CHECKSIG_COUNT>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                op_checksig_chip: OpCheckSigChip::<F, MAX_CHECKSIG_COUNT> {
                    aux_generator: Secp256k1Affine::default(),
                    window_size: 0,
                    _marker: std::marker::PhantomData::default()
                },
                script_pubkey: vec![],
                randomness: F::one(),
                initial_stack: [F::zero(); MAX_STACK_DEPTH],
                signatures: vec![],
                collected_pks: vec![],
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            TestOpChecksigCircuitConfig {
                execution_config: ExecutionChip::<F>::configure(meta),
                op_checksig_config: OpCheckSigChip::<F, MAX_CHECKSIG_COUNT>::configure(meta),
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>
        ) -> Result<(), Error> {
            let exec_chip = ExecutionChip::construct();

            let execution_chip_cells  = exec_chip.assign_script_pubkey_unroll(
                config.execution_config.clone(),
                &mut layouter,
                self.script_pubkey.clone(),
                self.randomness,
                self.initial_stack,
            )?;
            
            exec_chip.expose_public(
                config.execution_config.clone(),
                layouter.namespace(|| "script_length"),
                execution_chip_cells.clone().script_length,
                 0
            )?;
            exec_chip.expose_public(
                config.execution_config.clone(),
                layouter.namespace(|| "script_rlc_acc"),
                execution_chip_cells.clone().script_rlc_acc_init,
                1
            )?;
            exec_chip.expose_public(
                config.execution_config.clone(),
                layouter.namespace(|| "randomness"),
                execution_chip_cells.clone().randomness,
                2
            )?;

            let checksig_chip: OpCheckSigChip<F, MAX_CHECKSIG_COUNT> = self.op_checksig_chip.clone();
            checksig_chip.assign(
                &config.op_checksig_config,
                &mut layouter,
                &execution_chip_cells,
                self.randomness,
                &self.signatures,
                &self.collected_pks,
            )?;
            Ok(())
        }
    }


    #[test]
    fn test_opchecksig() {
        let k = 19;

        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let public_key_bytes: [u8; PUBLIC_KEY_SIZE] = public_key.serialize();
        
        let mut script_pubkey: Vec<u8> = vec![];
        script_pubkey.push(PUBLIC_KEY_SIZE as u8); // "Push 33 bytes" opcode
        script_pubkey.extend(public_key_bytes.iter());
        script_pubkey.push(OP_CHECKSIG as u8);

        let mut rng = XorShiftRng::seed_from_u64(1);
        let mut initial_stack_vec = vec![BnScalar::one()]; // This value will force a signature verification later
        initial_stack_vec.extend_from_slice(&[BnScalar::zero(); MAX_STACK_DEPTH-1]);
        let initial_stack: [BnScalar; MAX_STACK_DEPTH] = initial_stack_vec.as_slice().try_into().unwrap();
        
        // TODO: Derive initial stack and pk_parser_initial_stack from the same value
        let pk_parser_initial_stack = vec![StackElement::ValidSignature];
        let collected_pks = collect_public_keys(script_pubkey.clone(), pk_parser_initial_stack).expect("PK collection failed");

        let aux_generator = Secp256k1Affine::random(&mut rng);
        let sig_randomness = Fq::random(&mut rng);
        let mut sk_bytes = secret_key.secret_bytes();
        sk_bytes.reverse();
        let sk = ct_option_ok_or(
            Fq::from_bytes(&sk_bytes), libsecp256k1::Error::InvalidSecretKey
        ).unwrap();
        let sig = sign(sig_randomness, sk, Fq::from(ECDSA_MESSAGE_HASH as u64));

        let pk_be = public_key.serialize_uncompressed();
        let pk_le = pk_bytes_swap_endianness(&pk_be[1..]);
        let x = ct_option_ok_or(
            Fp::from_bytes(pk_le[..32].try_into().unwrap()),
            libsecp256k1::Error::InvalidPublicKey,
        ).expect("x coordinate corrupted");
        let y = ct_option_ok_or(
            Fp::from_bytes(pk_le[32..].try_into().unwrap()),
            libsecp256k1::Error::InvalidPublicKey,
        ).expect("y coordinate corrupted");
        let pk = ct_option_ok_or(
            Secp256k1Affine::from_xy(x, y),
            libsecp256k1::Error::InvalidPublicKey,
        ).expect("Public key corrupted");
        
        let sign_data: SignData = SignData { signature: sig, pk };
        

        let r: u64 = rng.gen();
        let randomness: BnScalar = BnScalar::from(r);

        let circuit = TestOpChecksigCircuit::<BnScalar, MAX_CHECKSIG_COUNT> {
            op_checksig_chip: OpCheckSigChip::<BnScalar, MAX_CHECKSIG_COUNT> {
                aux_generator,
                window_size: 2,
                _marker: std::marker::PhantomData,
            },
            script_pubkey: script_pubkey.clone(),
            randomness,
            initial_stack,
            signatures: vec![sign_data],
            collected_pks,
        };

        script_pubkey.reverse();
        let script_rlc_init = script_pubkey.clone().into_iter().fold(BnScalar::zero(), |acc, v| {
            acc * randomness + BnScalar::from(v as u64)
        });

        let public_input = vec![
            BnScalar::from(script_pubkey.len() as u64),
            script_rlc_init,
            randomness,
        ];

        let prover = MockProver::run(k, &circuit, vec![public_input.clone(), vec![]]).unwrap();
        prover.assert_satisfied();
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn plot_opchecksig() {
        use plotters::prelude::*;
        let k = 19;
        const CHECKSIG_COUNT: usize = 3;
        let num_collected_pks = 2;

        let aux_generator = Secp256k1Affine::default();
        let sig_default = SignData::default();

        let coll_pk = PublicKeyInScript {
            pk: sig_default.pk,
            bytes: vec![1u8; 33], // placeholder value for plotting circuit layout
        };

        let circuit = TestOpChecksigCircuit::<BnScalar, CHECKSIG_COUNT> {
            op_checksig_chip: OpCheckSigChip::<BnScalar, CHECKSIG_COUNT> {
                aux_generator,
                window_size: 2,
                _marker: std::marker::PhantomData,
            },
            script_pubkey: vec![1u8; 35], // placeholder value for plotting circuit layout
            randomness: BnScalar::one(),
            initial_stack: [BnScalar::one(); MAX_STACK_DEPTH],
            signatures: vec![SignData::default(); num_collected_pks],
            collected_pks: vec![coll_pk; num_collected_pks],
        };

        let root = BitMapBackend::new("opchecksig-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("OpCheckSig Layout", ("sans-serif", 60)).unwrap();


        halo2_proofs::dev::CircuitLayout::default()
            .render(k, &circuit, &root)
            .unwrap();
    }
}