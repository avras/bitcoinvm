pub mod expr;
pub mod is_zero;

pub(crate) mod opcode{
    use super::super::constants::*;

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

}
