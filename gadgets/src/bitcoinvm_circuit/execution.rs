use halo2_proofs::plonk::{Column, Advice, Selector, ConstraintSystem, Expression};
use halo2_proofs::poly::Rotation;
use super::{constants::MAX_STACK_DEPTH};
use super::util::expr::Expr;
use super::util::is_zero::{IsZeroConfig, IsZeroChip};
use super::opcode_table::{OpcodeTableConfig, OpcodeTableChip};

use crate::Field;


#[derive(Clone, Debug)]
pub(crate) struct ExecutionConfig<F: Field> {
    // Instance column
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

impl<F: Field> ExecutionConfig<F> {
    pub(crate) fn configure(
        meta: &mut ConstraintSystem<F>,
        randomness: Expression<F>,
        script_rlc_init: Expression<F>,
        script_length: Expression<F>
    ) -> Self {
        let q_first = meta.complex_selector();
        let q_execution = meta.complex_selector();
        let opcode = meta.advice_column();
        let is_opcode_enabled = meta.advice_column();
        let is_opcode_op0 = meta.advice_column();
        let is_opcode_op1_to_op16 = meta.advice_column();
        let is_opcode_push1_to_push75 = meta.advice_column();
        let is_opcode_pushdata1 = meta.advice_column();
        let is_opcode_pushdata2 = meta.advice_column();
        let is_opcode_pushdata4 = meta.advice_column();
        let script_rlc_acc = meta.advice_column();
        let stack = [(); MAX_STACK_DEPTH].map(|_| meta.advice_column());

        let num_script_bytes_remaining = meta.advice_column();
        let num_script_bytes_remaining_inv = meta.advice_column();
        let num_script_bytes_remaining_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_execution),
            |meta| meta.query_advice(num_script_bytes_remaining, Rotation::cur()),
            num_script_bytes_remaining_inv,
        );

        let num_data_bytes_remaining = meta.advice_column();
        let num_data_bytes_remaining_inv = meta.advice_column();
        let num_data_bytes_remaining_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_execution),
            |meta| meta.query_advice(num_data_bytes_remaining, Rotation::cur()),
            num_data_bytes_remaining_inv,
        );

        let num_data_length_bytes_remaining = meta.advice_column();
        let num_data_length_bytes_remaining_inv = meta.advice_column();
        let num_data_length_bytes_remaining_is_zero = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_execution),
            |meta| meta.query_advice(num_data_length_bytes_remaining, Rotation::cur()),
            num_data_length_bytes_remaining_inv,
        );
        let num_data_length_bytes_remaining_minus_one_inv = meta.advice_column();
        let num_data_length_bytes_remaining_is_one = IsZeroChip::configure(
            meta,
            |meta| meta.query_selector(q_execution),
            |meta| meta.query_advice(num_data_length_bytes_remaining, Rotation::cur()),
            num_data_length_bytes_remaining_minus_one_inv,
        );
        let num_data_length_acc_constant = meta.advice_column();

        let opcode_table = OpcodeTableChip::configure(
            meta,
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
            let script_rlc_acc = meta.query_advice(script_rlc_acc, Rotation::cur());
            let num_script_bytes_remaining = meta.query_advice(num_script_bytes_remaining, Rotation::cur());
            // Initialize script_rlc_acc
            let mut constraints = vec![q_first.clone() * (script_rlc_acc - script_rlc_init)];
            constraints.push(q_first.clone() * (num_script_bytes_remaining - script_length));
            
            for s in stack {
                let stack_column = meta.query_advice(s, Rotation::cur());
                // All stack contents in first row are zero
                constraints.push(q_first.clone() * stack_column);
            }
            constraints
        });

        meta.create_gate("Pop byte out of script_rlc_acc", |meta| {
            let q_execution = meta.query_selector(q_execution);
            let opcode = meta.query_advice(opcode, Rotation::cur());
            let current_script_rlc_acc = meta.query_advice(script_rlc_acc, Rotation::cur());
            let prev_script_rlc_acc = meta.query_advice(script_rlc_acc, Rotation::prev());

            let mut constraints = vec![
                q_execution.clone()
                * (1u8.expr() - num_script_bytes_remaining_is_zero.expr()) // Some script bytes remain
                * (opcode + randomness.clone() * current_script_rlc_acc.clone() - prev_script_rlc_acc.clone())
            ];
            // If there are no script bytes remaining, then script_rlc_acc remains unchanged
            constraints.push(
                q_execution
                * num_script_bytes_remaining_is_zero.expr()
                * (current_script_rlc_acc - prev_script_rlc_acc)
            );
            constraints
        });

        meta.create_gate("Stack state unchanged once script is read", |meta| {
            let q_execution = meta.query_selector(q_execution);
            let is_stack_read = q_execution * num_script_bytes_remaining_is_zero.expr();
            let current_script_rlc_acc = meta.query_advice(script_rlc_acc, Rotation::cur());
            // script_rlc_acc must be zero
            let mut constraints = vec![
                is_stack_read.clone() * num_script_bytes_remaining_is_zero.expr() * current_script_rlc_acc
            ];

            // Check that the stack items remain the same
            for i in 0..MAX_STACK_DEPTH {
                let current_stack_item = meta.query_advice(stack[i], Rotation::cur());
                let prev_stack_item  = meta.query_advice(stack[i], Rotation::prev());
                constraints.push(is_stack_read.clone() * (current_stack_item - prev_stack_item));
            }
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
            let next_num_bytes_remaining = meta.query_advice(num_data_bytes_remaining, Rotation::next());
            // Number of bytes to push onto the stack equals the opcode value for opcodes 1 to 75
            let mut constraints = vec![is_relevant_opcode.clone() * (next_num_bytes_remaining - opcode)];

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

        meta.create_gate("PUSHDATA1", |meta| {
            let q_execution = meta.query_selector(q_execution);
            let data_len = 1u8;
            let is_opcode_pushdata = meta.query_advice(is_opcode_pushdata1, Rotation::cur());
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

        meta.create_gate("PUSHDATA2", |meta| {
            let q_execution = meta.query_selector(q_execution);
            let data_len = 2u8;
            let is_opcode_pushdata = meta.query_advice(is_opcode_pushdata2, Rotation::cur());
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

        meta.create_gate("PUSHDATA4", |meta| {
            let q_execution = meta.query_selector(q_execution);
            let data_len = 4u8;
            let is_opcode_pushdata = meta.query_advice(is_opcode_pushdata4, Rotation::cur());
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

        meta.create_gate("Accumulate data byte in stack top", |meta| {
            let q_execution = meta.query_selector(q_execution);
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
            let next_num_data_length_acc_constant = meta.query_advice(num_data_length_acc_constant, Rotation::next());
            // Check that num_data_length_acc_constant is multiplied by 256
            constraints.push(data_length_push_in_progress.clone() * (next_num_data_length_acc_constant - 256u64.expr() * current_num_data_length_acc_constant));

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

        Self { 
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
}