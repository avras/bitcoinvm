use super::super::constants::*;
use crate::Field;

pub(crate) struct ScriptPubkeyParseState<F: Field> {
    pub randomness: F,
    pub stack: [F; MAX_STACK_DEPTH],
    pub num_data_bytes_remaining: u64,
    pub next_num_data_bytes_remaining: u64,
    pub num_data_length_bytes_remaining: u64,
    pub next_num_data_length_bytes_remaining: u64,
    pub num_data_length_acc_constant: u64,
    pub pk_rlc_acc: F,
    pub num_checksig_opcodes: u64,
}

impl<F: Field> ScriptPubkeyParseState<F> {
    pub(crate) fn new(
        randomness: F,
        initial_stack: [F; MAX_STACK_DEPTH],
    ) -> Self {
        Self {
            randomness,
            stack: initial_stack,
            num_data_bytes_remaining: 0,
            next_num_data_bytes_remaining: 0,
            num_data_length_bytes_remaining: 0,
            next_num_data_length_bytes_remaining: 0,
            num_data_length_acc_constant: 0,
            pk_rlc_acc: F::zero(),
            num_checksig_opcodes: 0,
        }
    }

    pub(crate) fn update(
        &mut self,
        opcode: u8,
    ) -> () {
        let opcode = opcode as usize;
        let (a,b,c,d) = (
            self.num_data_bytes_remaining,
            self.next_num_data_bytes_remaining,
            self.num_data_length_bytes_remaining,
            self.next_num_data_length_bytes_remaining,
        );
        if (a, b, c, d) == (0, 0, 0, 0) || (a, b, c, d) == (1, 0, 0, 0) {
                if self.num_data_bytes_remaining == 1 {
                    self.num_data_bytes_remaining = 0;
                }
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
                else if opcode == OP_CHECKSIG {
                    self.pk_rlc_acc = self.pk_rlc_acc * self.randomness + self.stack[0];
                    self.stack[0] = self.stack[1]; // Signature is assumed to be F::zero or F::one
                    // Shift stack elements on step to the left (up)
                    for i in 2..MAX_STACK_DEPTH {
                        self.stack[i-1] = self.stack[i];
                    }
                    // Last element is forced to be zero
                    self.stack[MAX_STACK_DEPTH-1] = F::zero();
                    // Increment num_checksig_opcodes
                    self.num_checksig_opcodes += 1;
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

pub fn opcode_enabled(opcode: u8) -> u64 {
    let opcode = opcode as usize;
    if (opcode <= OP_NOP && opcode != OP_1NEGATE && opcode != OP_RESERVED)
    || opcode == OP_CHECKSIG {
        1
    }
    else {
        0
    }
}

macro_rules! opcode_indicator {
    ($name:ident, $opval:expr) => {
        pub fn $name(opcode: u8) -> u64 {
            let opcode = opcode as usize;
            if opcode == $opval {
                1
            }
            else {
                0
            }

        }
    };
}

opcode_indicator!(op0_indicator, OP_0);
opcode_indicator!(pushdata1_indicator, OP_PUSHDATA1);
opcode_indicator!(pushdata2_indicator, OP_PUSHDATA2);
opcode_indicator!(pushdata4_indicator, OP_PUSHDATA4);
opcode_indicator!(checksig_indicator, OP_CHECKSIG);

macro_rules! opcode_range_indicator {
    ($name:ident, $opval_min:expr, $opval_max:expr) => {
        pub fn $name(opcode: u8) -> u64 {
            let opcode = opcode as usize;
            if opcode >= $opval_min && opcode <= $opval_max {
                1
            }
            else {
                0
            }

        }
    };
}

opcode_range_indicator!(op1_to_op16_indicator, OP_1, OP_16);
opcode_range_indicator!(push1_to_push75_indicator, OP_PUSH_NEXT1, OP_PUSH_NEXT75);


