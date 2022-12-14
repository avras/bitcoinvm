use std::convert::TryInto;
use super::constants::*;
use super::helper_functions::*;

#[derive(Default, Debug, PartialEq, Clone, Copy)]
pub struct State {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
}

#[derive(Clone, Copy)]
pub struct MessageBlock([u32; BLOCK_SIZE]);

impl MessageBlock {
    pub fn get_word(&self, index: usize) -> u32 {
        self.0[index]
    }
}

impl From<[u32; DIGEST_SIZE]> for State {
    fn from(s: [u32; DIGEST_SIZE]) -> Self {
       State { a: s[0], b: s[1], c: s[2], d: s[3], e: s[4] } 
    }
}

impl From<State> for [u32; DIGEST_SIZE] {
    fn from(s: State) -> Self {
        [s.a, s.b, s.c, s.d, s.e]
    }
}

impl From<State> for [u8; DIGEST_SIZE_BYTES] {
    fn from(s: State) -> Self {
        [   
            s.a.to_le_bytes(),
            s.b.to_le_bytes(),
            s.c.to_le_bytes(), 
            s.d.to_le_bytes(),
            s.e.to_le_bytes()
        ].concat().try_into().expect("Failed conversion")
    }
}

impl From<[u8; BLOCK_SIZE_BYTES]> for MessageBlock {
    fn from(s: [u8; BLOCK_SIZE_BYTES]) -> Self {
        assert!(s.len() == BLOCK_SIZE_BYTES);
        let mut v: Vec<u32> = vec![];
        for i in 0..BLOCK_SIZE {
            v.push(u32::from_le_bytes([s[4*i], s[4*i+1], s[4*i+2], s[4*i+3]]));
        }
        let a = v.as_slice();
        MessageBlock(a.try_into().expect("Incorrect length"))
    }
}

const ROUND_FUNC_LEFT: [fn(u32,u32,u32) -> u32; 5] = [f1, f2, f3, f4, f5];
const ROUND_FUNC_RIGHT: [fn(u32,u32,u32) -> u32; 5] = [f5, f4, f3, f2, f1];

pub fn pad_message_bytes(
    msg_bytes: Vec<u8>,
) -> Vec<[u8; BLOCK_SIZE_BYTES]> {
    const PAD_BYTE: u8 = 0b1000_0000;
    let mut padded_msg: Vec<u8> = vec![];
    padded_msg.extend(msg_bytes.clone());
    padded_msg.push(PAD_BYTE);
    
    let gap: usize = BLOCK_SIZE_BYTES - (padded_msg.len() % BLOCK_SIZE_BYTES);
    if gap < 8 {
        padded_msg.extend(vec![0_u8; gap + 56])
    }
    else {
        padded_msg.extend(vec![0_u8; gap - 8]);
    }

    let msg_len_in_bits = (msg_bytes.len() << 3) as u64;
    padded_msg.extend(msg_len_in_bits.to_le_bytes());
    assert!(padded_msg.len() % BLOCK_SIZE_BYTES == 0);

    let mut vec_blocks : Vec<[u8; BLOCK_SIZE_BYTES]> = vec![];
    let iter = padded_msg.chunks(BLOCK_SIZE_BYTES);
    for block in iter {
        vec_blocks.push(block.try_into().expect("Incorrect length"));
    }
    vec_blocks
}

pub fn left_step(
    round_idx: usize,
    s: State,
    msg_block: MessageBlock,
) -> State {
    let f = ROUND_FUNC_LEFT[round_idx/ROUND_PHASE_SIZE];
    let m = msg_block.get_word(MSG_SEL_IDX_LEFT[round_idx]);
    let k = ROUND_CONSTANTS_LEFT[round_idx/ROUND_PHASE_SIZE];
    let shift = ROL_AMOUNT_LEFT[round_idx];
    let t =
    rol(
        s.a.overflowing_add(f(s.b, s.c, s.d)).0
            .overflowing_add(m).0
            .overflowing_add(k).0,
        shift,
    ).overflowing_add(s.e).0;

    State {
        a: s.e,
        b: t,
        c: s.b,
        d: rol(s.c, 10),
        e: s.d
    }
}

pub fn right_step(
    round_idx: usize,
    s: State,
    msg_block: MessageBlock
) -> State {
    let f = ROUND_FUNC_RIGHT[round_idx/ROUND_PHASE_SIZE];
    let m = msg_block.get_word(MSG_SEL_IDX_RIGHT[round_idx]);
    let k = ROUND_CONSTANTS_RIGHT[round_idx/ROUND_PHASE_SIZE];
    let shift = ROL_AMOUNT_RIGHT[round_idx];
    let t =
    rol(
        s.a.overflowing_add(f(s.b, s.c, s.d)).0
            .overflowing_add(m).0
            .overflowing_add(k).0,
        shift,
    ).overflowing_add(s.e).0;

    State {
        a: s.e,
        b: t,
        c: s.b,
        d: rol(s.c, 10),
        e: s.d
    }
}

pub fn combine_left_right_states(
    prev: State,
    l: State,
    r: State,
) -> State {
    let mut next = State::default();
    next.a = prev.b
        .overflowing_add(l.c).0
        .overflowing_add(r.d).0;
    next.b = prev.c
        .overflowing_add(l.d).0
        .overflowing_add(r.e).0;
    next.c = prev.d
        .overflowing_add(l.e).0
        .overflowing_add(r.a).0;
    next.d = prev.e
        .overflowing_add(l.a).0
        .overflowing_add(r.b).0;
    next.e = prev.a
        .overflowing_add(l.b).0
        .overflowing_add(r.c).0;
    next
}

// This helper function exists to enable easier testing in the RIPEMD160 gadget
pub fn get_compress_state(
    s: State,
    msg_block: MessageBlock,
) -> State {
    let mut left_state = s;
    let mut right_state = s;
    for j in 0..ROUNDS {
        left_state = left_step(j, left_state.clone(), msg_block);
        right_state = right_step(j, right_state.clone(), msg_block);
    }
    let chain_state = combine_left_right_states(s, left_state, right_state);
    chain_state
}

pub fn hash(
    msg: Vec<u8>
) -> [u8; DIGEST_SIZE_BYTES] {
    let msg_blocks: Vec<[u8; BLOCK_SIZE_BYTES]> = pad_message_bytes(msg);
    assert!(msg_blocks.len() > 0);
    let mut state = get_compress_state(INITIAL_VALUES.into(), msg_blocks[0].into());
    for block in &msg_blocks[1..] {
        state = get_compress_state(state, (*block).into());
    }
    state.into()
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use crate::ripemd160::ref_impl::ripemd160::hash;
    use crate::ripemd160::ref_impl::ripemd160::pad_message_bytes;

    use super::super::constants::*;
    use super::super::helper_functions::*;
    use super::{left_step, right_step, MessageBlock, State};
    use rand::Rng;

    #[test]
    fn test_left_step () {
        let mut rng = rand::thread_rng();
        let mut msg_block_bytes = [0_u8; BLOCK_SIZE_BYTES];
        rng.fill(&mut msg_block_bytes);
        let msg_block: MessageBlock = msg_block_bytes.into();

        let s = State::default();
        let mut s_next = State::default();
        let sum = msg_block.get_word(0).overflowing_add(ROUND_CONSTANTS_LEFT[0]);
        s_next.b = rol(sum.0, ROL_AMOUNT_LEFT[0]);

        assert_eq!(left_step(0, s, msg_block), s_next);
    }

    #[test]
    fn test_right_step () {
        let mut rng = rand::thread_rng();
        let mut msg_block_bytes = [0_u8; BLOCK_SIZE_BYTES];
        rng.fill(&mut msg_block_bytes);
        let msg_block: MessageBlock = msg_block_bytes.into();

        let s = State::default();
        let mut s_next = State::default();
        let sum = msg_block.get_word(5)
                                .overflowing_add(0xFFFF_FFFF).0
                                .overflowing_add(ROUND_CONSTANTS_RIGHT[0]);
        s_next.b = rol(sum.0, ROL_AMOUNT_RIGHT[0]);

        assert_eq!(right_step(0, s, msg_block), s_next);
    }

    #[test]
    fn test_hash () {
        assert_eq!(hash(b"abc".to_vec()), TEST_INPUT_HASH_ABC);
        assert_eq!(hash(b"abcdefghijklmnopqrstuvwxyz".to_vec()), TEST_INPUT_HASH_A2Z);
        
        // Test case from https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
        let mut h = [0; DIGEST_SIZE_BYTES];
        hex::decode_to_slice("b0e20b6e3116640286ed3a87a5713079b21f5189", &mut h).expect("Error");
        assert_eq!(
            hash(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_vec()),
            h,
        );
    }

    #[test]
    fn test_padding () {
        {
            let msg: Vec<u8> = b"abc".to_vec();
            let blocks: Vec<[u8; BLOCK_SIZE_BYTES]> = pad_message_bytes(msg);
            assert_eq!(blocks.len(), 1);
            assert_eq!(blocks[0], PADDED_TEST_INPUT_ABC);
        }
        {
            let msg: Vec<u8> = b"abcdefghijklmnopqrstuvwxyz".to_vec();
            let blocks: Vec<[u8; BLOCK_SIZE_BYTES]> = pad_message_bytes(msg);
            assert_eq!(blocks.len(), 1);
            assert_eq!(blocks[0], PADDED_TEST_INPUT_A2Z);
        }
        {
            let msg: Vec<u8> = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".to_vec();
            let blocks: Vec<[u8; BLOCK_SIZE_BYTES]> = pad_message_bytes(msg.clone());
            assert_eq!(blocks.len(), 2);
            assert_eq!(blocks[0][..msg.len()].to_vec(), msg);

            // Check pad byte
            pub const PAD_BYTE: u8 = 0b1000_0000;
            assert_eq!(blocks[0][msg.len()], PAD_BYTE);

            // Checks zeros and length
            assert_eq!(blocks[0][msg.len()+1..], vec![0_u8; BLOCK_SIZE_BYTES-msg.len()-1]);
            assert_eq!(blocks[1][..BLOCK_SIZE_BYTES-8], vec![0_u8; BLOCK_SIZE_BYTES-8]);
            assert_eq!(u64::from_le_bytes(blocks[1][56..].try_into().expect("error")), (msg.len() << 3) as u64);
        }
    }
}