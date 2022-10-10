#![allow(dead_code)]
pub mod bitcoinvm_circuit;
pub mod ripemd160;

use halo2_proofs::arithmetic::{Field as Halo2Field, FieldExt};
use halo2_proofs::halo2curves::group::ff::PrimeField;
use halo2_proofs::halo2curves::bn256::{Fq, Fr};


pub trait Field: FieldExt + Halo2Field + PrimeField<Repr = [u8; 32]> {}

impl Field for Fr {}
impl Field for Fq {}