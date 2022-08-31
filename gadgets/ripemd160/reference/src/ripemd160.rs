use crate::constants::*;
use crate::helper_functions::*;

#[derive(Default, Debug, PartialEq, Clone, Copy)]
pub struct State {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
}

impl From<[u32; DIGEST_SIZE]> for State {
    fn from(s: [u32; DIGEST_SIZE]) -> Self {
       State { a: s[0], b: s[1], c: s[2], d: s[3], e: s[4] } 
    }
}

impl From<State> for [u32; DIGEST_SIZE] {
    fn from(s: State) -> Self {
        [s.a.to_be(), s.b.to_be(), s.c.to_be(), s.d.to_be(), s.e.to_be()]
    }
}

const ROUND_FUNC_LEFT: [fn(u32,u32,u32) -> u32; 5] = [f1, f2, f3, f4, f5];
const ROUND_FUNC_RIGHT: [fn(u32,u32,u32) -> u32; 5] = [f5, f4, f3, f2, f1];

pub fn left_step(
    round_idx: usize,
    s: State,
    msg_block: [u32; BLOCK_SIZE],
) -> State {
    let f = ROUND_FUNC_LEFT[round_idx/ROUND_PHASE_SIZE];
    let m = msg_block[MSG_SEL_IDX_LEFT[round_idx]];
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
        d: rol10(s.c),
        e: s.d
    }
}

pub fn right_step(
    round_idx: usize,
    s: State,
    msg_block: [u32; BLOCK_SIZE],
) -> State {
    let f = ROUND_FUNC_RIGHT[round_idx/ROUND_PHASE_SIZE];
    let m = msg_block[MSG_SEL_IDX_RIGHT[round_idx]];
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
        d: rol10(s.c),
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

pub fn compress(
    s: State,
    msg_block: [u32; BLOCK_SIZE],
) -> [u32; DIGEST_SIZE] {
    let mut left_state = s;
    let mut right_state = s;
    for j in 0..ROUNDS {
        left_state = left_step(j, left_state.clone(), msg_block);
        right_state = right_step(j, right_state.clone(), msg_block);
    }
    println!("{:?}", left_state);
    println!("{:?}", right_state);
    let chain_state = combine_left_right_states(s, left_state, right_state);
    println!("{:?}", chain_state);
    chain_state.into()
}

pub fn compress_first_block(
    msg_block: [u32; BLOCK_SIZE],
) -> [u32; DIGEST_SIZE] {
    compress(INITIAL_VALUES.into(), msg_block)
}

#[cfg(test)]
mod tests {
    use crate::constants::*;
    use crate::helper_functions::*;
    use crate::ripemd160::right_step;
    use super::compress_first_block;
    use super::{left_step, State};
    use rand::Rng;

    #[test]
    fn test_left_step () {
        let mut rng = rand::thread_rng();
        let msg_block: [u32; BLOCK_SIZE] = rng.gen();

        let s = State::default();
        let mut s_next = State::default();
        let sum = msg_block[0].overflowing_add(ROUND_CONSTANTS_LEFT[0]);
        s_next.b = rol(sum.0, ROL_AMOUNT_LEFT[0]);

        assert_eq!(left_step(0, s, msg_block), s_next);
    }

    #[test]
    fn test_right_step () {
        let mut rng = rand::thread_rng();
        let msg_block: [u32; BLOCK_SIZE] = rng.gen();

        let s = State::default();
        let mut s_next = State::default();
        let sum = msg_block[5].overflowing_add(0xFFFF_FFFF).0.overflowing_add(ROUND_CONSTANTS_RIGHT[0]);
        s_next.b = rol(sum.0, ROL_AMOUNT_RIGHT[0]);

        assert_eq!(right_step(0, s, msg_block), s_next);
    }

    #[test]
    fn test_compress_first_block () {
        assert_eq!(compress_first_block(PADDED_TEST_INPUT), TEST_INPUT_HASH);
    }
}