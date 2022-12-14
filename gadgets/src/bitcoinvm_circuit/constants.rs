pub const MAX_SCRIPT_PUBKEY_SIZE : usize = 520;
pub const MAX_STACK_DEPTH : usize = 33;
pub const MAX_CHECKSIG_COUNT: usize = 1;

// A stack element is evaluates to true if it consists of non-zero bytes,
// except when the non-zero bytes encode a negative zero (0x80).
pub const NEGATIVE_ZERO : u64 = 0x80;

// OP_0 pushes an empty array of bytes onto the stack in Bitcoin. The empty array evaluates to false.
// So we represent the empty array by the negative zero.
pub const EMPTY_ARRAY_REPRESENTATION : u64 = NEGATIVE_ZERO;

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

// Flow control opcodes https://en.bitcoin.it/wiki/Script#Flow_control
pub const OP_NOP: usize                     = 0x61;

// Cryptographic operations opcodes https://en.bitcoin.it/wiki/Script#Crypto
pub const OP_CHECKSIG: usize                = 0xac;

// Prefix bytes of secp256k1 public key serializations
pub const PREFIX_PK_COMPRESSED_EVEN_Y: u64 = 0x02;
pub const PREFIX_PK_COMPRESSED_ODD_Y: u64 = 0x03;
pub const PREFIX_PK_UNCOMPRESSED: u64 = 0x04;

// Message hash that will be signed in all ECDSA invocations in BitcoinVM
// Since the goal is to prove UTXO ownership and not actual spending, the
// message hash is not a transaction hash
pub const ECDSA_MESSAGE_HASH: u64 = 0x01;

// Integer chip configuration parameters
pub const NUMBER_OF_LIMBS: usize = 4;
pub const BIT_LEN_LIMB: usize = 72;