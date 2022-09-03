/*
use super::{
    super::DIGEST_SIZE,
    util::{i2lebsp, lebs2ip},
    AssignedBits, BlockWord, SpreadInputs, SpreadVar, Table16Assignment, ROUNDS, STATE,
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};
use halo2curves::pasta::pallas;
use std::convert::TryInto;
use std::ops::Range;
*/

mod compression_gates;
// mod compression_util;
// mod subregion_digest;
// mod subregion_initial;
// mod subregion_main;

// use compression_gates::CompressionGate;
