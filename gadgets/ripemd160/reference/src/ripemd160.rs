use crate::constants::*;
use crate::helper_functions::*;

#[derive(Default, Debug, PartialEq)]
pub struct State {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    e: u32,
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

#[cfg(test)]
mod tests {
    use crate::constants::*;
    use crate::helper_functions::*;
    use crate::ripemd160::right_step;
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
}