pub const MAX_SCRIPT_PUBKEY_SIZE : usize = 520;
pub const MAX_OPCODE_COUNT: usize = 20; // tentative

// Integer chip configuration parameters
pub const NUMBER_OF_LIMBS: usize = 4;
pub const BIT_LEN_LIMB: usize = 72;

// Power of randomness vector size for public key RLC (includes prefix byte)
pub const PK_POW_RAND_SIZE: usize = 64;

// Prefix bytes of secp256k1 public key serializations
pub const PREFIX_PK_COMPRESSED_EVEN_Y: u64 = 0x02;
pub const PREFIX_PK_COMPRESSED_ODD_Y: u64 = 0x03;
pub const PREFIX_PK_UNCOMPRESSED: u64 = 0x04;

// Message hash that will be signed in all ECDSA invocations in BitcoinVM
// Since the goal is to prove UTXO ownership and not actual spending, the
// message hash is not a transaction hash
pub const ECDSA_MESSAGE_HASH: u64 = 0x01;