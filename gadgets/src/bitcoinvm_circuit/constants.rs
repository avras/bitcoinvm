pub const MAX_SCRIPT_PUBKEY_SIZE : usize = 520;
pub const MAX_STACK_DEPTH : usize = 33;

// Data push opcodes https://en.bitcoin.it/wiki/Script#Constants
pub const OP_0: usize                       = 0x00;
pub const OP_PUSH_NEXT1: usize              = 0x01;
pub const OP_PUSH_NEXT75: usize             = 0x4b;
pub const OP_PUSHDATA1: usize               = 0x4c;
pub const OP_PUSHDATA2: usize               = 0x4d;
pub const OP_PUSHDATA4: usize               = 0x4e;
pub const OP_1NEGATE: usize                 = 0x4f;
pub const OP_RESERVED: usize                = 0x50;
pub const OP_1: usize                       = 0x51;
pub const OP_16: usize                      = 0x60;
