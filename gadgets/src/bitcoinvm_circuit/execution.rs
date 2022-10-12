use halo2_proofs::circuit::{Layouter, Region, Value, AssignedCell};
use halo2_proofs::plonk::{Column, Advice, Selector, ConstraintSystem, Expression, Error, Instance};
use halo2_proofs::poly::Rotation;
use super::constants::*;
use super::util::expr::Expr;
use super::util::is_zero::{IsZeroConfig, IsZeroChip};
use super::opcode_table::{OpcodeTableConfig, OpcodeTableChip};

use crate::Field;
use crate::bitcoinvm_circuit::util::is_zero::IsZeroInstruction;
use crate::bitcoinvm_circuit::util::opcode::{opcode_enabled, op0_indicator, pushdata1_indicator, pushdata2_indicator, pushdata4_indicator, op1_to_op16_indicator, push1_to_push75_indicator};


#[derive(Clone, Debug)]
pub(crate) struct ExecutionConfig<F: Field> {
    // Instance column with scriptPubkey length and rlc values in first and second rows
    instance: Column<Instance>,
    // Randomness used for RLC
    randomness: Column<Advice>,
    // Selector for first row
    q_first: Selector,
    // Selector that is active after first row
    q_execution: Selector,
    // Current opcode being processed
    opcode: Column<Advice>,
    opcode_table: OpcodeTableConfig,
    is_opcode_enabled: Column<Advice>, // Opcodes enabled in BitcoinVM is a subset of opcodes enabled in Bitcoin
    is_opcode_op0: Column<Advice>,
    is_opcode_op1_to_op16: Column<Advice>,
    is_opcode_push1_to_push75: Column<Advice>,
    is_opcode_pushdata1: Column<Advice>,
    is_opcode_pushdata2: Column<Advice>,
    is_opcode_pushdata4: Column<Advice>,

    script_rlc_acc: Column<Advice>,
    // Columns to track the parsing of script
    num_script_bytes_remaining: Column<Advice>,
    num_script_bytes_remaining_inv: Column<Advice>,
    num_script_bytes_remaining_is_zero: IsZeroConfig<F>,

    // Stack state
    stack: [Column<Advice>; MAX_STACK_DEPTH],

    num_data_bytes_remaining: Column<Advice>,
    num_data_bytes_remaining_inv: Column<Advice>,
    num_data_bytes_remaining_is_zero: IsZeroConfig<F>,

    num_data_length_bytes_remaining: Column<Advice>,
    num_data_length_bytes_remaining_inv: Column<Advice>,
    num_data_length_bytes_remaining_is_zero: IsZeroConfig<F>,
    num_data_length_bytes_remaining_minus_one_inv: Column<Advice>,
    num_data_length_bytes_remaining_is_one: IsZeroConfig<F>,
    num_data_length_acc_constant: Column<Advice>,

}


#[derive(Debug, Clone)]
struct ExecutionChip<F: Field> {
    config: ExecutionConfig<F>,
}

impl<F: Field> ExecutionChip<F> {
    pub fn construct(config: ExecutionConfig<F>) -> Self {
        Self {
            config,
        }
    }

    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
    ) -> ExecutionConfig<F> {
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        let randomness = meta.advice_column();
        meta.enable_equality(randomness);
        let q_first = meta.complex_selector();
        let q_execution = meta.complex_selector();
        let opcode = meta.advice_column();
        meta.enable_equality(opcode);
        let is_opcode_enabled = meta.advice_column();
        meta.enable_equality(is_opcode_enabled);
        let is_opcode_op0 = meta.advice_column();
        meta.enable_equality(is_opcode_op0);
        let is_opcode_op1_to_op16 = meta.advice_column();
        meta.enable_equality(is_opcode_op1_to_op16);
        let is_opcode_push1_to_push75 = meta.advice_column();
        meta.enable_equality(is_opcode_push1_to_push75);
        let is_opcode_pushdata1 = meta.advice_column();
        meta.enable_equality(is_opcode_pushdata1);
        let is_opcode_pushdata2 = meta.advice_column();
        meta.enable_equality(is_opcode_pushdata2);
        let is_opcode_pushdata4 = meta.advice_column();
        meta.enable_equality(is_opcode_pushdata4);
        let script_rlc_acc = meta.advice_column();
        meta.enable_equality(script_rlc_acc);
        let stack = [(); MAX_STACK_DEPTH].map(|_| meta.advice_column());
        stack.iter().for_each(|c| meta.enable_equality(*c));

        let num_script_bytes_remaining = meta.advice_column();
        meta.enable_equality(num_script_bytes_remaining);
        let num_script_bytes_remaining_inv = meta.advice_column();
        meta.enable_equality(num_script_bytes_remaining_inv);

        let num_script_bytes_remaining_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_execution),
            |meta| meta.query_advice(num_script_bytes_remaining, Rotation::cur()),
            num_script_bytes_remaining_inv,
        );

        let num_data_bytes_remaining = meta.advice_column();
        meta.enable_equality(num_data_bytes_remaining);
        let num_data_bytes_remaining_inv = meta.advice_column();
        meta.enable_equality(num_data_bytes_remaining_inv);

        let num_data_bytes_remaining_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_execution),
            |meta| meta.query_advice(num_data_bytes_remaining, Rotation::cur()),
            num_data_bytes_remaining_inv,
        );

        let num_data_length_bytes_remaining = meta.advice_column();
        meta.enable_equality(num_data_length_bytes_remaining);
        let num_data_length_bytes_remaining_inv = meta.advice_column();
        meta.enable_equality(num_data_length_bytes_remaining_inv);

        let num_data_length_bytes_remaining_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_execution),
            |meta| meta.query_advice(num_data_length_bytes_remaining, Rotation::cur()),
            num_data_length_bytes_remaining_inv,
        );

        let num_data_length_bytes_remaining_minus_one_inv = meta.advice_column();
        meta.enable_equality(num_data_length_bytes_remaining_minus_one_inv);

        let num_data_length_bytes_remaining_is_one = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_execution),
            |meta| meta.query_advice(num_data_length_bytes_remaining, Rotation::cur()) - 1u8.expr(),
            num_data_length_bytes_remaining_minus_one_inv,
        );
        let num_data_length_acc_constant = meta.advice_column();
        meta.enable_equality(num_data_length_acc_constant);

        let opcode_table = OpcodeTableChip::configure(
            meta,
            q_execution,
            opcode,
            is_opcode_enabled,
            is_opcode_op0,
            is_opcode_op1_to_op16,
            is_opcode_push1_to_push75,
            is_opcode_pushdata1,
            is_opcode_pushdata2,
            is_opcode_pushdata4,

        );

        meta.create_gate("First row constraints", |meta| {
            let q_first = meta.query_selector(q_first);

            let mut constraints = vec![];
            let cur_num_data_bytes_remaining = meta.query_advice(num_data_bytes_remaining, Rotation::cur());
            // num_data_bytes_remaining is initially zero
            constraints.push(q_first.clone() * cur_num_data_bytes_remaining);
            let next_num_data_bytes_remaining = meta.query_advice(num_data_bytes_remaining, Rotation::next());
            // Next num_data_bytes_remaining is also zero
            constraints.push(q_first.clone() * next_num_data_bytes_remaining);

            let cur_num_data_length_bytes_remaining = meta.query_advice(num_data_length_bytes_remaining, Rotation::cur());
            // num_data_length_bytes_remaining is initially zero
            constraints.push(q_first.clone() * cur_num_data_length_bytes_remaining);
            let next_num_data_length_bytes_remaining = meta.query_advice(num_data_length_bytes_remaining, Rotation::next());
            // Next num_data_length_bytes_remaining is also zero
            constraints.push(q_first.clone() * next_num_data_length_bytes_remaining);
            for s in stack {
                let stack_column = meta.query_advice(s, Rotation::cur());
                // All stack contents in first row are zero
                constraints.push(q_first.clone() * stack_column);
            }
            constraints
        });

        meta.create_gate("Randomness values are the same in all rows", |meta| {
            let q_execution = meta.query_selector(q_execution);
            let cur_randomness = meta.query_advice(randomness, Rotation::cur());
            let prev_randomness = meta.query_advice(randomness, Rotation::prev());
            vec![q_execution * (cur_randomness - prev_randomness)]
        });

        meta.create_gate("Pop byte out of script_rlc_acc", |meta| {
            let q_execution = meta.query_selector(q_execution);
            let randomness = meta.query_advice(randomness, Rotation::cur());
            let opcode = meta.query_advice(opcode, Rotation::cur());
            let current_script_rlc_acc = meta.query_advice(script_rlc_acc, Rotation::cur());
            let prev_script_rlc_acc = meta.query_advice(script_rlc_acc, Rotation::prev());

            let mut constraints = vec![
                q_execution.clone()
                * (1u8.expr() - num_script_bytes_remaining_is_zero.expr()) // Some script bytes remain
                * (opcode + randomness.clone() * current_script_rlc_acc.clone() - prev_script_rlc_acc.clone())
            ];
            let current_num_script_bytes_remaining = meta.query_advice(num_script_bytes_remaining, Rotation::cur());
            let next_num_script_bytes_remaining = meta.query_advice(num_script_bytes_remaining, Rotation::next());
            // Check that num_script_bytes_remaining is decremented in next row if it is non-zero in current row
            constraints.push(
                q_execution.clone()
                * (1u8.expr() - num_script_bytes_remaining_is_zero.expr())
                * (next_num_script_bytes_remaining + 1u8.expr() - current_num_script_bytes_remaining)
            );

            // If there are no script bytes remaining, then script_rlc_acc remains unchanged
            constraints.push(
                q_execution.clone()
                * num_script_bytes_remaining_is_zero.expr()
                * (current_script_rlc_acc.clone() - prev_script_rlc_acc)
            );
            // If there are no script bytes remaining, then script_rlc_acc must also be zero
            constraints.push(
                q_execution.clone()
                * num_script_bytes_remaining_is_zero.expr()
                * current_script_rlc_acc
            );
            constraints
        });

        meta.create_gate("Stack state unchanged once script is read", |meta| {
            let q_execution = meta.query_selector(q_execution);
            let is_script_read_complete = q_execution * num_script_bytes_remaining_is_zero.expr();
            let current_script_rlc_acc = meta.query_advice(script_rlc_acc, Rotation::cur());
            // script_rlc_acc must be zero
            let mut constraints = vec![
                is_script_read_complete.clone() * num_script_bytes_remaining_is_zero.expr() * current_script_rlc_acc
            ];

            // Check that the stack items remain the same
            for i in 0..MAX_STACK_DEPTH {
                let current_stack_item = meta.query_advice(stack[i], Rotation::cur());
                let prev_stack_item  = meta.query_advice(stack[i], Rotation::prev());
                constraints.push(is_script_read_complete.clone() * (current_stack_item - prev_stack_item));
            }

            let opcode = meta.query_advice(opcode, Rotation::cur());
            // Padding opcodes are all OP_NOP
            constraints.push(is_script_read_complete * (opcode - (OP_NOP as u64).expr()));
            constraints
        });

        meta.create_gate("Only supported opcodes allowed", |meta| {
            let q_execution = meta.query_selector(q_execution);
            let is_opcode_enabled = meta.query_advice(is_opcode_enabled, Rotation::cur());
            let is_current_byte_an_opcode = q_execution
                * (1u8.expr() - num_script_bytes_remaining_is_zero.expr())
                * num_data_bytes_remaining_is_zero.expr()
                * num_data_length_bytes_remaining_is_zero.expr();

            vec![is_current_byte_an_opcode * (1u8.expr() - is_opcode_enabled)]
        });

        meta.create_gate("OP_1 to OP_16", |meta| {
            let q_execution = meta.query_selector(q_execution);
            let is_opcode_op1_to_op16 = meta.query_advice(is_opcode_op1_to_op16, Rotation::cur());
            let is_relevant_opcode = q_execution 
                * (1u8.expr() - num_script_bytes_remaining_is_zero.expr())
                * is_opcode_op1_to_op16
                * num_data_bytes_remaining_is_zero.expr()
                * num_data_length_bytes_remaining_is_zero.expr();

            let opcode = meta.query_advice(opcode, Rotation::cur());
            // OP_1 has code 81, OP_2 has code 82, and so on
            let value_to_push = opcode - 80_u8.expr(); 
            let stack_top = meta.query_advice(stack[0], Rotation::cur());
            let mut constraints = vec![is_relevant_opcode.clone() * (stack_top - value_to_push)];
            
            // Check that the stack items to are shifted to the right
            for i in 1..MAX_STACK_DEPTH {
                let current_stack_item = meta.query_advice(stack[i], Rotation::cur());
                let prev_stack_item  = meta.query_advice(stack[i-1], Rotation::prev());
                constraints.push(is_relevant_opcode.clone() * (current_stack_item - prev_stack_item));
            }
            constraints
        });

        meta.create_gate("OP_0", |meta| {
            let q_execution = meta.query_selector(q_execution);
            let is_opcode_op0 = meta.query_advice(is_opcode_op0, Rotation::cur());
            let is_relevant_opcode = q_execution 
                * (1u8.expr() - num_script_bytes_remaining_is_zero.expr())
                * is_opcode_op0
                * num_data_bytes_remaining_is_zero.expr()
                * num_data_length_bytes_remaining_is_zero.expr();

            // Data byte pushes leave a RLC of the the bytes at stack_top. But the RLC is unlikely to be equal to 256.
            // OP_0 pushes an empty array of bytes onto the stack in Bitcoin. We represent the empty array by 256.
            let value_to_push = 256u64.expr();
            let stack_top = meta.query_advice(stack[0], Rotation::cur());
            let mut constraints = vec![is_relevant_opcode.clone() * (stack_top - value_to_push)];
            
            // Check that the stack items to are shifted to the right
            for i in 1..MAX_STACK_DEPTH {
                let current_stack_item = meta.query_advice(stack[i], Rotation::cur());
                let prev_stack_item  = meta.query_advice(stack[i-1], Rotation::prev());
                constraints.push(is_relevant_opcode.clone() * (current_stack_item - prev_stack_item));
            }
            constraints
        });

        meta.create_gate("PUSH1 to PUSH75", |meta| {
            let q_execution = meta.query_selector(q_execution);
            let is_opcode_push1_to_push75 = meta.query_advice(is_opcode_push1_to_push75, Rotation::cur());
            let is_relevant_opcode = q_execution 
                * (1u8.expr() - num_script_bytes_remaining_is_zero.expr())
                * is_opcode_push1_to_push75
                * num_data_bytes_remaining_is_zero.expr()
                * num_data_length_bytes_remaining_is_zero.expr();

            let opcode = meta.query_advice(opcode, Rotation::cur());
            let next_num_data_bytes_remaining = meta.query_advice(num_data_bytes_remaining, Rotation::next());
            // Number of bytes to push onto the stack equals the opcode value for opcodes 1 to 75
            let mut constraints = vec![is_relevant_opcode.clone() * (next_num_data_bytes_remaining - opcode)];

            let stack_top = meta.query_advice(stack[0], Rotation::cur());
            // Check that stack_top is zero
            constraints.push(is_relevant_opcode.clone() * stack_top);

            // Check that the stack items to are shifted to the right
            for i in 1..MAX_STACK_DEPTH {
                let current_stack_item = meta.query_advice(stack[i], Rotation::cur());
                let prev_stack_item  = meta.query_advice(stack[i-1], Rotation::prev());
                constraints.push(is_relevant_opcode.clone() * (current_stack_item - prev_stack_item));
            }
            constraints
        });

        macro_rules! create_pushdata_gate {
            ($annotation:expr, $is_opcode_pushdata_col:ident, $data_len:expr) => {
                meta.create_gate($annotation, |meta| {
                    let q_execution = meta.query_selector(q_execution);
                    let data_len = $data_len;
                    let is_opcode_pushdata = meta.query_advice($is_opcode_pushdata_col, Rotation::cur());
                    let is_relevant_opcode = q_execution 
                        * (1u8.expr() - num_script_bytes_remaining_is_zero.expr())
                        * is_opcode_pushdata
                        * num_data_bytes_remaining_is_zero.expr()
                        * num_data_length_bytes_remaining_is_zero.expr();
                    
                    let next_num_data_length_bytes_remaining: Expression<F> = meta.query_advice(num_data_length_bytes_remaining, Rotation::next());
                    // Place length of data in the next row of num_data_length_bytes_remaining
                    let mut constraints: Vec<Expression<F>> = vec![is_relevant_opcode.clone() * (data_len.expr() - next_num_data_length_bytes_remaining)];

                    let next_num_data_length_acc_constant: Expression<F> = meta.query_advice(num_data_length_acc_constant, Rotation::next());
                    // Set the next row of num_data_length_acc_constant to 1 = 256^0. It will be raised to higher powers in subsequent rows 
                    constraints.push(is_relevant_opcode.clone() * (1u8.expr() - next_num_data_length_acc_constant));

                    let current_num_data_bytes_remaining = meta.query_advice(num_data_bytes_remaining, Rotation::cur());
                    // Check that num_data_bytes_remaining is zero
                    constraints.push(is_relevant_opcode.clone() * current_num_data_bytes_remaining);

                    // Check that the stack items remain the same
                    for i in 0..MAX_STACK_DEPTH {
                        let current_stack_item = meta.query_advice(stack[i], Rotation::cur());
                        let prev_stack_item  = meta.query_advice(stack[i], Rotation::prev());
                        constraints.push(is_relevant_opcode.clone() * (current_stack_item - prev_stack_item));
                    }
                    constraints
                });

            };
        }

        create_pushdata_gate!("PUSHDATA1", is_opcode_pushdata1, 1u8);
        create_pushdata_gate!("PUSHDATA2", is_opcode_pushdata2, 2u8);
        create_pushdata_gate!("PUSHDATA4", is_opcode_pushdata4, 4u8);

        meta.create_gate("Accumulate data byte in stack top", |meta| {
            let q_execution = meta.query_selector(q_execution);
            let randomness = meta.query_advice(randomness, Rotation::cur());
            let data_push_in_progress = q_execution
                * (1u8.expr() - num_script_bytes_remaining_is_zero.expr())
                * (1u8.expr() - num_data_bytes_remaining_is_zero.expr())
                * num_data_length_bytes_remaining_is_zero.expr();
            let data_byte = meta.query_advice(opcode, Rotation::cur());
            let stack_top = meta.query_advice(stack[0], Rotation::cur());
            let prev_stack_top = meta.query_advice(stack[0], Rotation::prev());
            // Check that the data byte has been accumulated into stack_top
            let mut constraints = vec![data_push_in_progress.clone() * (data_byte + randomness.clone() * prev_stack_top - stack_top)];
            
            // Check that the non-top stack items remain the same
            for i in 1..MAX_STACK_DEPTH {
                let current_stack_item = meta.query_advice(stack[i], Rotation::cur());
                let prev_stack_item  = meta.query_advice(stack[i], Rotation::prev());
                constraints.push(data_push_in_progress.clone() * (current_stack_item - prev_stack_item));
            }

            let current_num_bytes_remaining = meta.query_advice(num_data_bytes_remaining, Rotation::cur());
            let next_num_bytes_remaining = meta.query_advice(num_data_bytes_remaining, Rotation::next());
            // Check that num_data_bytes_remaining is decremented
            constraints.push(data_push_in_progress * (next_num_bytes_remaining + 1u8.expr() - current_num_bytes_remaining));
            constraints
        });

        meta.create_gate("Accumulate data length into num_data_bytes_remaining", |meta| {
            let q_execution = meta.query_selector(q_execution);
            let data_length_push_in_progress = q_execution
                * (1u8.expr() - num_script_bytes_remaining_is_zero.expr())
                * (1u8.expr() - num_data_length_bytes_remaining_is_zero.expr());
            let data_length_byte = meta.query_advice(opcode, Rotation::cur());
            let current_data_length = meta.query_advice(num_data_bytes_remaining, Rotation::cur());
            let prev_data_length = meta.query_advice(num_data_bytes_remaining, Rotation::prev());
            let next_data_length = meta.query_advice(num_data_bytes_remaining, Rotation::next());
            let current_data_length_acc_constant = meta.query_advice(num_data_length_acc_constant, Rotation::cur());

            // Check that the data byte has been accumulated into num_data_bytes_remaining
            // The data length bytes appear in little-endian order. Hence we need constants which are increasing powers of 256
            let mut constraints = vec![
                data_length_push_in_progress.clone()
                * (data_length_byte * current_data_length_acc_constant + prev_data_length - current_data_length.clone())
            ];
            
            // Check that the stack items remain the same
            for i in 0..MAX_STACK_DEPTH {
                let current_stack_item = meta.query_advice(stack[i], Rotation::cur());
                let prev_stack_item  = meta.query_advice(stack[i], Rotation::prev());
                constraints.push(data_length_push_in_progress.clone() * (current_stack_item - prev_stack_item));
            }

            let current_num_data_length_bytes_remaining = meta.query_advice(num_data_length_bytes_remaining, Rotation::cur());
            let next_num_data_length_bytes_remaining = meta.query_advice(num_data_length_bytes_remaining, Rotation::next());
            // Check that num_data_length_bytes_remaining is decremented
            constraints.push(data_length_push_in_progress.clone() * (next_num_data_length_bytes_remaining + 1u8.expr() - current_num_data_length_bytes_remaining));

            let current_num_data_length_acc_constant = meta.query_advice(num_data_length_acc_constant, Rotation::cur());
            let prev_num_data_length_acc_constant = meta.query_advice(num_data_length_acc_constant, Rotation::prev());
            // Check that num_data_length_acc_constant is multiplied by 256
            constraints.push(
                data_length_push_in_progress.clone()
                * (1u8.expr() - current_num_data_length_acc_constant.clone())  // Constraint applies when the acc_constant is not 1
                * (prev_num_data_length_acc_constant * 256u64.expr() - current_num_data_length_acc_constant)
            );

            // If the current byte is the last data length byte, ensure that the current value of num_data_bytes_remaining is
            // non-zero and equal to next value.
            // The reason for checking the non-zero condition is to prevent OP_PUSHDATA opcodes with zero length
            constraints.push(
                data_length_push_in_progress
                * num_data_length_bytes_remaining_is_one.expr()
                * (1u8.expr() - num_data_bytes_remaining_is_zero.expr())
                * (current_data_length - next_data_length)
            );
            constraints
        });

        ExecutionConfig {
            instance,
            randomness,
            q_first,
            q_execution,
            opcode,
            opcode_table,
            is_opcode_enabled,
            is_opcode_op0,
            is_opcode_op1_to_op16,
            is_opcode_push1_to_push75,
            is_opcode_pushdata1,
            is_opcode_pushdata2,
            is_opcode_pushdata4,
            script_rlc_acc,
            num_script_bytes_remaining,
            num_script_bytes_remaining_inv,
            num_script_bytes_remaining_is_zero,
            stack,
            num_data_bytes_remaining,
            num_data_bytes_remaining_inv,
            num_data_bytes_remaining_is_zero,
            num_data_length_bytes_remaining,
            num_data_length_bytes_remaining_inv,
            num_data_length_bytes_remaining_is_zero,
            num_data_length_bytes_remaining_minus_one_inv,
            num_data_length_bytes_remaining_is_one,
            num_data_length_acc_constant,
        }
    }

    pub(crate) fn assign_script_pubkey_unroll(
        &self,
        layouter: &mut impl Layouter<F>,
        script_pubkey: Vec<u8>,
        randomness: F,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        assert!(script_pubkey.len() <= MAX_SCRIPT_PUBKEY_SIZE);

        OpcodeTableChip::load(self.config.opcode_table.clone(), layouter)?;

        layouter.assign_region(
            || "ScriptPubkey unrolling",
            |mut region: Region<F>| {

                self.config.q_first.enable(&mut region, 0)?;

                let script_length_cell = region.assign_advice(
                    || "Byte length of scriptPubkey",
                    self.config.num_script_bytes_remaining,
                    0,
                    || Value::known(F::from(script_pubkey.len() as u64)),
                )?;

                let randomness_cell = region.assign_advice(
                    || "Randomness for RLC operations",
                    self.config.randomness,
                    0,
                    || Value::known(randomness),
                )?;

                for i in 0..MAX_STACK_DEPTH {
                    region.assign_advice(
                        || "Initialize stack to zero elements",
                        self.config.stack[i],
                        0,
                        || Value::known(F::zero()),
                    )?;
                }

                region.assign_advice(
                    || "Initialize num_data_bytes_remaining to zero",
                    self.config.num_data_bytes_remaining,
                    0,
                    || Value::known(F::zero()),
                )?;

                region.assign_advice(
                    || "Initialize num_data_length_bytes_remaining to zero",
                    self.config.num_data_length_bytes_remaining,
                    0,
                    || Value::known(F::zero()),
                )?;

                region.assign_advice(
                    || "Initialize num_data_length_acc_constant to zero",
                    self.config.num_data_length_acc_constant,
                    0,
                    || Value::known(F::zero()),
                )?;

                let mut script_rlc_acc_vec = vec![];
                let mut acc_value = F::zero();
                script_rlc_acc_vec.push(acc_value);

                for i in (0..script_pubkey.len()).rev() {
                    acc_value = acc_value * randomness + F::from(script_pubkey[i] as u64);
                    script_rlc_acc_vec.push(acc_value);
                }

                // Reverse the script_rlc_acc running sum vector
                script_rlc_acc_vec.reverse();

                let script_rlc_acc_init_cell = region.assign_advice(
                    || "Initialize script_rlc_acc",
                    self.config.script_rlc_acc,
                    0,
                    || Value::known(script_rlc_acc_vec[0]),
                )?;

                let num_script_bytes_remaining_is_zero_chip
                    = IsZeroChip::construct(self.config.num_script_bytes_remaining_is_zero.clone());
                let num_data_bytes_remaining_is_zero_chip
                    = IsZeroChip::construct(self.config.num_data_bytes_remaining_is_zero.clone());
                let num_data_length_bytes_remaining_is_zero_chip
                    = IsZeroChip::construct(self.config.num_data_length_bytes_remaining_is_zero.clone());
                let num_data_length_bytes_remaining_is_one_chip
                    = IsZeroChip::construct(self.config.num_data_length_bytes_remaining_is_one.clone());

                let mut script_state = ScriptPubkeyParseState::new(randomness);
                
                for byte_index in 0..MAX_SCRIPT_PUBKEY_SIZE+1 { // an extra row is assigned as queries are made to next rows
                    
                    let offset = byte_index + 1;
                    
                    if byte_index != MAX_SCRIPT_PUBKEY_SIZE {
                        self.config.q_execution.enable(&mut region, offset)?;
                    }

                    region.assign_advice(
                        || "Randomness for RLC operations",
                        self.config.randomness,
                        offset,
                        || Value::known(randomness),
                    )?;

                    if byte_index < script_pubkey.len() {
                        region.assign_advice(
                            || "Load scriptPubkey bytes",
                            self.config.opcode,
                            offset,
                            || Value::known(F::from(script_pubkey[byte_index] as u64)),
                        )?;

                        region.assign_advice(
                            || "Load script_rlc_acc intermediate values",
                            self.config.script_rlc_acc,
                            offset,
                            || Value::known(script_rlc_acc_vec[offset]),
                        )?;

                        let num_script_bytes_remaining = F::from((script_pubkey.len() - byte_index) as u64);

                        region.assign_advice(
                            || "Load num_script_bytes_remaining values",
                            self.config.num_script_bytes_remaining,
                            offset,
                            || Value::known(num_script_bytes_remaining),
                        )?;

                        num_script_bytes_remaining_is_zero_chip.assign(
                            &mut region,
                            offset,
                            Value::known(num_script_bytes_remaining),
                        )?;

                        script_state.update(script_pubkey[byte_index]);

                        region.assign_advice(
                            || "Load num_data_bytes_remaining values",
                            self.config.num_data_bytes_remaining,
                            offset,
                            || Value::known(F::from(script_state.num_data_bytes_remaining)),
                        )?;

                        num_data_bytes_remaining_is_zero_chip.assign(
                            &mut region,
                            offset,
                            Value::known(F::from(script_state.num_data_bytes_remaining)),
                        )?;

                        region.assign_advice(
                            || "Load num_data_length_bytes_remaining values",
                            self.config.num_data_length_bytes_remaining,
                            offset,
                            || Value::known(F::from(script_state.num_data_length_bytes_remaining)),
                        )?;

                        num_data_length_bytes_remaining_is_zero_chip.assign(
                            &mut region,
                            offset,
                            Value::known(F::from(script_state.num_data_length_bytes_remaining)),
                        )?;

                        let data_length_bytes_minus_one_val = if script_state.num_data_length_bytes_remaining > 0 {
                            F::from(script_state.num_data_length_bytes_remaining.wrapping_sub(1))
                        } else {
                            -F::one()
                        };
                        num_data_length_bytes_remaining_is_one_chip.assign(
                            &mut region,
                            offset,
                            Value::known(data_length_bytes_minus_one_val),
                        )?;

                        region.assign_advice(
                            || "Load num_data_length_acc_constant values",
                            self.config.num_data_length_acc_constant,
                            offset,
                            || Value::known(F::from(script_state.num_data_length_acc_constant)),
                        )?;

                        region.assign_advice(
                            || "Load is_opcode_enabled column",
                            self.config.is_opcode_enabled,
                            offset,
                            || Value::known(F::from(opcode_enabled(script_pubkey[byte_index]))),
                        )?;

                        region.assign_advice(
                            || "Load is_opcode_op0 column",
                            self.config.is_opcode_op0,
                            offset,
                            || Value::known(F::from(op0_indicator(script_pubkey[byte_index]))),
                        )?;

                        region.assign_advice(
                            || "Load is_opcode_op1_to_op16 column",
                            self.config.is_opcode_op1_to_op16,
                            offset,
                            || Value::known(F::from(op1_to_op16_indicator(script_pubkey[byte_index]))),
                        )?;

                        region.assign_advice(
                            || "Load is_opcode_push1_to_push75 column",
                            self.config.is_opcode_push1_to_push75,
                            offset,
                            || Value::known(F::from(push1_to_push75_indicator(script_pubkey[byte_index]))),
                        )?;

                        region.assign_advice(
                            || "Load is_opcode_pushdata1 column",
                            self.config.is_opcode_pushdata1,
                            offset,
                            || Value::known(F::from(pushdata1_indicator(script_pubkey[byte_index]))),
                        )?;

                        region.assign_advice(
                            || "Load is_opcode_pushdata2 column",
                            self.config.is_opcode_pushdata2,
                            offset,
                            || Value::known(F::from(pushdata2_indicator(script_pubkey[byte_index]))),
                        )?;

                        region.assign_advice(
                            || "Load is_opcode_pushdata4 column",
                            self.config.is_opcode_pushdata4,
                            offset,
                            || Value::known(F::from(pushdata4_indicator(script_pubkey[byte_index]))),
                        )?;

                    }
                    else {

                        if byte_index != MAX_SCRIPT_PUBKEY_SIZE {
                            region.assign_advice(
                                || "Load scriptPubkey padding bytes",
                                self.config.opcode,
                                offset,
                                || Value::known(F::from(OP_NOP as u64)),
                            )?;

                            region.assign_advice(
                                || "Load is_opcode_enabled column",
                                self.config.is_opcode_enabled,
                                offset,
                                || Value::known(F::one()),
                            )?;
                        }
                        else {
                            region.assign_advice(
                                || "Load scriptPubkey padding bytes",
                                self.config.opcode,
                                offset,
                                || Value::known(F::zero()),
                            )?;

                            region.assign_advice(
                                || "Load is_opcode_enabled column",
                                self.config.is_opcode_enabled,
                                offset,
                                || Value::known(F::zero()),
                            )?;
                        }

                        region.assign_advice(
                            || "Load script_rlc_acc padding",
                            self.config.script_rlc_acc,
                            offset,
                            || Value::known(F::zero()),
                        )?;

                        region.assign_advice(
                            || "Load num_script_bytes_remaining values",
                            self.config.num_script_bytes_remaining,
                            offset,
                            || Value::known(F::zero()),
                        )?;

                        num_script_bytes_remaining_is_zero_chip.assign(
                            &mut region,
                            offset,
                            Value::known(F::zero()),
                        )?;

                        region.assign_advice(
                            || "Load num_data_bytes_remaining values",
                            self.config.num_data_bytes_remaining,
                            offset,
                            || Value::known(F::zero()),
                        )?;

                        num_data_bytes_remaining_is_zero_chip.assign(
                            &mut region,
                            offset,
                            Value::known(F::zero()),
                        )?;

                        region.assign_advice(
                            || "Load num_data_length_bytes_remaining values",
                            self.config.num_data_length_bytes_remaining,
                            offset,
                            || Value::known(F::zero()),
                        )?;

                        num_data_length_bytes_remaining_is_zero_chip.assign(
                            &mut region,
                            offset,
                            Value::known(F::zero()),
                        )?;

                        num_data_length_bytes_remaining_is_one_chip.assign(
                            &mut region,
                            offset,
                            Value::known(-F::one()),
                        )?;

                        region.assign_advice(
                            || "Load num_data_length_acc_constant values",
                            self.config.num_data_length_acc_constant,
                            offset,
                            || Value::known(F::from(script_state.num_data_length_acc_constant)),
                        )?;

                        region.assign_advice(
                            || "Load is_opcode_op0 column",
                            self.config.is_opcode_op0,
                            offset,
                            || Value::known(F::zero()),
                        )?;

                        region.assign_advice(
                            || "Load is_opcode_op1_to_op16 column",
                            self.config.is_opcode_op1_to_op16,
                            offset,
                            || Value::known(F::zero()),
                        )?;

                        region.assign_advice(
                            || "Load is_opcode_push1_to_push75 column",
                            self.config.is_opcode_push1_to_push75,
                            offset,
                            || Value::known(F::zero()),
                        )?;

                        region.assign_advice(
                            || "Load is_opcode_pushdata1 column",
                            self.config.is_opcode_pushdata1,
                            offset,
                            || Value::known(F::zero()),
                        )?;

                        region.assign_advice(
                            || "Load is_opcode_pushdata2 column",
                            self.config.is_opcode_pushdata2,
                            offset,
                            || Value::known(F::zero()),
                        )?;

                        region.assign_advice(
                            || "Load is_opcode_pushdata4 column",
                            self.config.is_opcode_pushdata4,
                            offset,
                            || Value::known(F::zero()),
                        )?;

                    }

                    for i in 0..MAX_STACK_DEPTH {
                        region.assign_advice(
                            || "Load stack values",
                            self.config.stack[i],
                            offset,
                            || Value::known(script_state.stack[i]),
                        )?;
                    }


                    
                }
                Ok((script_length_cell, script_rlc_acc_init_cell, randomness_cell))
            }
        )
    }
    
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}

struct ScriptPubkeyParseState<F: Field> {
    randomness: F,
    stack: [F; MAX_STACK_DEPTH],
    num_data_bytes_remaining: u64,
    next_num_data_bytes_remaining: u64,
    num_data_length_bytes_remaining: u64,
    next_num_data_length_bytes_remaining: u64,
    num_data_length_acc_constant: u64,
}

impl<F: Field> ScriptPubkeyParseState<F> {
    fn new(
        randomness: F,
    ) -> Self {
        Self {
            randomness,
            stack: [F::zero(); MAX_STACK_DEPTH],
            num_data_bytes_remaining: 0,
            next_num_data_bytes_remaining: 0,
            num_data_length_bytes_remaining: 0,
            next_num_data_length_bytes_remaining: 0,
            num_data_length_acc_constant: 0,
        }
    }

    fn update(
        &mut self,
        opcode: u8,
    ) -> () {
        let opcode = opcode as usize;
        if (
            self.num_data_bytes_remaining,
            self.next_num_data_bytes_remaining,
            self.num_data_length_bytes_remaining,
            self.next_num_data_length_bytes_remaining,
        ) == (0, 0, 0, 0) {
                if opcode == OP_0 {
                    for i in (1..MAX_STACK_DEPTH).rev() {
                        self.stack[i] = self.stack[i-1];
                    }
                    self.stack[0] = F::from(256u64);
                }
                else if opcode >= OP_1 && opcode <= OP_16 {
                    for i in (1..MAX_STACK_DEPTH).rev() {
                        self.stack[i] = self.stack[i-1];
                    }
                    self.stack[0] = F::from((opcode - OP_RESERVED) as u64);
                }
                else if opcode >= OP_PUSH_NEXT1 && opcode <= OP_PUSH_NEXT75 {
                   self.next_num_data_bytes_remaining = opcode as u64; 
                    for i in (1..MAX_STACK_DEPTH).rev() {
                        self.stack[i] = self.stack[i-1];
                    }
                    self.stack[0] = F::zero();
                }
                else if opcode >= OP_PUSHDATA1 && opcode <= OP_PUSHDATA4 {
                    self.next_num_data_length_bytes_remaining = 1u64 << (opcode - OP_PUSHDATA1);
                    self.num_data_bytes_remaining = 0;
                    for i in (1..MAX_STACK_DEPTH).rev() {
                        self.stack[i] = self.stack[i-1];
                    }
                    self.stack[0] = F::zero();
                }
        }
        else if self.next_num_data_bytes_remaining > 0 && self.num_data_bytes_remaining == 0 {
            // Accumulate data byte into stack top
            self.stack[0] = F::from(opcode as u64) + self.randomness * self.stack[0];
            // Replace num_data_bytes_remaining
            self.num_data_bytes_remaining = self.next_num_data_bytes_remaining;
            self.next_num_data_bytes_remaining = 0;
            self.num_data_length_bytes_remaining = 0;
        }
        else if self.num_data_bytes_remaining > 0 && self.num_data_length_bytes_remaining == 0 {
            // Accumulate data byte into stack top
            self.stack[0] = F::from(opcode as u64) + self.randomness * self.stack[0];
            // Decrement number of remaining data bytes
            self.num_data_bytes_remaining -= 1;
        }
        else if self.num_data_bytes_remaining > 0 && self.num_data_length_bytes_remaining == 1 {
            // Accumulate data byte into stack top
            self.stack[0] = F::from(opcode as u64) + self.randomness * self.stack[0];
            // Decrement number of remaining data length bytes
            self.num_data_length_bytes_remaining = 0;
        }
        else if self.next_num_data_length_bytes_remaining > 0 && self.num_data_length_bytes_remaining == 0 {
            self.num_data_length_bytes_remaining = self.next_num_data_length_bytes_remaining;
            self.next_num_data_length_bytes_remaining = 0;

            self.num_data_bytes_remaining = 0;
            self.num_data_length_acc_constant = 1;
            self.num_data_bytes_remaining += (opcode as u64) * self.num_data_length_acc_constant;
            if self.next_num_data_length_bytes_remaining == 1 {
                // These assignments help pick the correct if branch in the next iteration
                self.next_num_data_bytes_remaining = self.num_data_bytes_remaining;
                self.num_data_bytes_remaining = 0;
            }
        }
        else if self.num_data_length_bytes_remaining > 0 {
            self.num_data_length_acc_constant *= 256u64;
            self.num_data_bytes_remaining += (opcode as u64) * self.num_data_length_acc_constant;
            if self.num_data_length_bytes_remaining == 1 {
                // These assignments help pick the correct if branch in the next iteration
                self.next_num_data_bytes_remaining = self.num_data_bytes_remaining;
                self.num_data_bytes_remaining = 0;
            }
            else {
                // Decrement number of remaining data length bytes
                self.num_data_length_bytes_remaining -= 1;
            }
        }

    }
    
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr as BnScalar;
    use halo2_proofs::circuit::{SimpleFloorPlanner, Layouter};
    use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};
    use rand::Rng;

    use crate::bitcoinvm_circuit::constants::*;
    use crate::bitcoinvm_circuit::execution::ExecutionConfig;
    use crate::Field;

    use super::ExecutionChip;

    struct MyCircuit<F: Field> {
        pub script_pubkey: Vec<u8>,
        pub randomness: F,
    }

    impl<F: Field> Circuit<F> for MyCircuit<F> {
        type Config = ExecutionConfig<F>;

        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self {
                script_pubkey: vec![],
                randomness: F::zero(),
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            ExecutionChip::configure(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>
        ) -> Result<(), Error> {
            let chip = ExecutionChip::construct(config);

            let (script_length_cell, script_rlc_acc_init_cell,randomness_cell)  = chip.assign_script_pubkey_unroll(
                &mut layouter,
                self.script_pubkey.clone(),
                self.randomness
            )?;
            
            chip.expose_public(layouter.namespace(|| "script_length"), script_length_cell, 0)?;
            chip.expose_public(layouter.namespace(|| "script_rlc_acc"), script_rlc_acc_init_cell, 1)?;
            chip.expose_public(layouter.namespace(|| "randomness"), randomness_cell, 2)?;
            Ok(())
        }
    }

    #[test]
    fn test_script_pubkey_push_constants() {
        let k = 10;
        let mut script_pubkey = vec![];
        for i in 0..17 {
            script_pubkey.push((OP_1 + i) as u8);
        }
        
        let mut rng = rand::thread_rng();
        let r: u64 = rng.gen();
        let randomness: BnScalar = BnScalar::from(r);
        
        let circuit = MyCircuit {
            script_pubkey: script_pubkey.clone(),
            randomness,
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

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_script_pubkey_push1_to_push75() {
        let k = 10;
        let mut rng = rand::thread_rng();
        let mut script_pubkey: Vec<u8> = vec![];
        let mut data_push_len: u8 = rng.gen();
        data_push_len = (data_push_len % (OP_PUSH_NEXT75 as u8)) + 1;

        script_pubkey.push(data_push_len);
        for _i in 0..data_push_len {
            script_pubkey.push(rng.gen());
        }
        
        let r: u64 = rng.gen();
        let randomness: BnScalar = BnScalar::from(r);
        
        let circuit = MyCircuit {
            script_pubkey: script_pubkey.clone(),
            randomness,
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

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_script_pubkey_pushdata1() {
        let k = 10;
        let mut rng = rand::thread_rng();
        let mut script_pubkey: Vec<u8> = vec![];
        let mut data_push_len: u8 = rng.gen();
        data_push_len = (data_push_len % 254) + 1;

        script_pubkey.push(OP_PUSHDATA1 as u8);
        script_pubkey.push(data_push_len);
        for _i in 0..data_push_len {
            script_pubkey.push(rng.gen());
        }
        
        let r: u64 = rng.gen();
        let randomness: BnScalar = BnScalar::from(r);
        
        let circuit = MyCircuit {
            script_pubkey: script_pubkey.clone(),
            randomness,
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

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_script_pubkey_pushdata2() {
        let k = 10;
        let mut rng = rand::thread_rng();
        let mut script_pubkey: Vec<u8> = vec![];
        let data_push_len_byte0: u8 = rng.gen();
        let data_push_len_byte1: u8 = 1;

        script_pubkey.push(OP_PUSHDATA2 as u8);
        script_pubkey.push(data_push_len_byte0);
        script_pubkey.push(data_push_len_byte1);
        let data_push_len: usize =
            data_push_len_byte0 as usize +
            256 * (data_push_len_byte1 as usize);

        for _i in 0..data_push_len {
            script_pubkey.push(rng.gen());
        }
        
        let r: u64 = rng.gen();
        let randomness: BnScalar = BnScalar::from(r);
        
        let circuit = MyCircuit {
            script_pubkey: script_pubkey.clone(),
            randomness,
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

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_script_pubkey_pushdata4() {
        let k = 10;
        let mut rng = rand::thread_rng();
        let mut script_pubkey: Vec<u8> = vec![];
        let data_push_len_byte0: u8 = rng.gen();
        let data_push_len_byte1: u8 = 1;
        let data_push_len_byte2: u8 = 0;
        let data_push_len_byte3: u8 = 0;

        script_pubkey.push(OP_PUSHDATA4 as u8);
        script_pubkey.push(data_push_len_byte0);
        script_pubkey.push(data_push_len_byte1);
        script_pubkey.push(data_push_len_byte2);
        script_pubkey.push(data_push_len_byte3);
        let data_push_len: usize =
            data_push_len_byte0 as usize +
            256 * (data_push_len_byte1 as usize) +
            256 * 256 * (data_push_len_byte2 as usize) +
            256 * 256 * 256 * (data_push_len_byte3 as usize);

        for _i in 0..data_push_len {
            script_pubkey.push(rng.gen());
        }
        
        let r: u64 = rng.gen();
        let randomness: BnScalar = BnScalar::from(r);
        
        let circuit = MyCircuit {
            script_pubkey: script_pubkey.clone(),
            randomness,
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

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }
}