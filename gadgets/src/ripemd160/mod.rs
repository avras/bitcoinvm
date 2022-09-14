//! The [RIPEMD-160] hash function.
//!
//! [RIPEMD-160]: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
//! 
pub mod ref_impl;
pub mod table16;
use std::fmt;

use halo2::{
    arithmetic::FieldExt,
    circuit::{Chip, Layouter},
    plonk::Error,
};

use self::ref_impl::constants::{BLOCK_SIZE, DIGEST_SIZE};

/// The set of circuit instructions required to use the [`RIPEMD160`] gadget.
pub trait RIPEMD160Instructions<F: FieldExt>: Chip<F> {
    /// Variable representing the RIPEMD-160 internal state.
    type State: Clone + fmt::Debug;
    /// Variable representing a 32-bit word of the input block to the RIPEMD-160 compression
    /// function.
    type BlockWord: Copy + fmt::Debug + Default;

    /// Places the RIPEMD-160 IV in the circuit, returning the initial state variable.
    fn initialization_vector(&self, layouter: &mut impl Layouter<F>) -> Result<Self::State, Error>;

    /// Starting from the given initialized state, processes a block of input and returns the
    /// final state.
    fn compress(
        &self,
        layouter: &mut impl Layouter<F>,
        initialized_state: &Self::State,
        input: [Self::BlockWord; BLOCK_SIZE],
    ) -> Result<Self::State, Error>;

    /// Converts the given state into a message digest.
    fn digest(
        &self,
        layouter: &mut impl Layouter<F>,
        state: &Self::State,
    ) -> Result<[Self::BlockWord; DIGEST_SIZE], Error>;
}

/// The output of a RIPEMD-160 circuit invocation.
#[derive(Debug)]
pub struct RIPEMD160Digest<BlockWord>([BlockWord; DIGEST_SIZE]);

/// A gadget that constrains a RIPEMD-160 invocation. It supports input at a granularity of
/// 32 bits.
#[derive(Debug)]
pub struct RIPEMD160<F: FieldExt, CS: RIPEMD160Instructions<F>> {
    chip: CS,
    state: CS::State,
}

impl<F: FieldExt, RIPEMD160Chip: RIPEMD160Instructions<F>> RIPEMD160<F, RIPEMD160Chip> {
    /// Create a new hasher instance.
    pub fn new(chip: RIPEMD160Chip, mut layouter: impl Layouter<F>) -> Result<Self, Error> {
        let state = chip.initialization_vector(&mut layouter)?;
        Ok(RIPEMD160 {
            chip,
            state,
        })
    }

    /// Updating the internal state by consuming all message blocks
    /// The input is assumed to be already padded to a multiple of 16 Blockwords
    pub fn update(
        &mut self,
        mut layouter: impl Layouter<F>,
        data: &Vec<[RIPEMD160Chip::BlockWord; BLOCK_SIZE]>,
    ) -> Result<(), Error> {

        // Process all blocks.
        for b in data {
            self.state = self.chip.compress(
                &mut layouter,
                &self.state,
                *b,
            )?;
        }

        Ok(())
    }

    /// Retrieve result and consume hasher instance.
    pub fn finalize(
        self,
        mut layouter: impl Layouter<F>,
    ) -> Result<RIPEMD160Digest<RIPEMD160Chip::BlockWord>, Error> {
        self.chip
            .digest(&mut layouter, &self.state)
            .map(RIPEMD160Digest)
    }

    /// Convenience function to compute hash of the data.
    /// data feeding and finalization.
    pub fn digest(
        chip: RIPEMD160Chip,
        mut layouter: impl Layouter<F>,
        data: &Vec<[RIPEMD160Chip::BlockWord; BLOCK_SIZE]>,
    ) -> Result<RIPEMD160Digest<RIPEMD160Chip::BlockWord>, Error> {
        let mut hasher = Self::new(chip, layouter.namespace(|| "init"))?;
        hasher.update(layouter.namespace(|| "update"), data)?;
        hasher.finalize(layouter.namespace(|| "finalize"))
    }
}