use mcore::rand::{RAND_impl, RAND};

pub enum RNG {
    MarsagliaZaman(RAND_impl)
}

impl RAND for RNG {
    fn seed(&mut self, rawlen: usize, raw: &[u8]) {
        match self {
            RNG::MarsagliaZaman(rng) => rng.seed(rawlen, raw)
        }
    }

    fn getbyte(&mut self) -> u8 {
        match self {
            RNG::MarsagliaZaman(rng) => return rng.getbyte()
        }
    }
}