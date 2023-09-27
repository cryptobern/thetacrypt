use std::time::SystemTime;

use mcore::rand::{RAND_impl, RAND};
use rand::{rngs::OsRng, RngCore};

pub enum RngAlgorithm {
    MarsagliaZaman, // should only be used for testing
    OsRng           // use this for production
}

pub enum RNG {
    MarsagliaZaman(RAND_impl),
    OsRng(OsRng)
}

impl RAND for RNG {
    fn seed(&mut self, rawlen: usize, raw: &[u8]) {
        match self {
            RNG::MarsagliaZaman(rng) => rng.seed(rawlen, raw),
            RNG::OsRng(_rng) => {}
        }
    }

    fn getbyte(&mut self) -> u8 {
        match self {
            RNG::MarsagliaZaman(rng) => return rng.getbyte(),
            RNG::OsRng(rng) => { 
                return rng.next_u32().to_be_bytes()[0];
            }
        }
    }
}

impl RNG {
    pub fn new(alg: RngAlgorithm) -> RNG {
        let mut raw: [u8; 100] = [0; 100];
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);
    
        match now {
            Ok(_n) => {
                let ms = _n.as_millis();
                for i in 0..15 {
                    raw[i] = (ms << i) as u8
                }
            },
            Err(_) => {
                panic!("Error initializing random number generator")
            }
        }

        match alg {
            RngAlgorithm::MarsagliaZaman => {
                let mut rng = RAND_impl::new();
                rng.clean();
                rng.seed(16, &raw);
                return RNG::MarsagliaZaman(rng);
            },

            RngAlgorithm::OsRng => {
                let rng = OsRng::default();
                return RNG::OsRng(rng);
            }
        }
    
        
    }

    pub fn random_bytes(&mut self, num: usize) -> Vec<u8> {
        let mut result = Vec::new();
        for i in 0..num {
            result.push(self.getbyte());
        }
        result
    }
}