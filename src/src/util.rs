use std::time::SystemTime;

use mcore::rand::{RAND_impl, RAND};

use crate::rand::RNG;

/// print a vector of bytes to the console
pub fn printbinary(array: &[u8], caption: Option<&str>) {
    if caption.is_some() {
        print!("{}", caption.unwrap());
    }
    for i in 0..array.len() {
        print!("{:02X}", array[i])
    }
    println!("")
}

/// create new RAND_impl instance and feed it with some entropy (current time)
pub fn new_rand() -> RNG {
    let mut raw: [u8; 100] = [0; 100];
    let mut rng = RAND_impl::new();
    rng.clean();

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH);

    match now {
        Ok(_n) => {
            let ms = _n.as_millis();
            for i in 0..15 {
                raw[i] = (ms << i) as u8
            }

            rng.seed(16, &raw);
        },
        Err(_) => {
            for i in 0..100 {
                raw[i] = i as u8
            }

            rng.seed(100, &raw);
        }
    }

    RNG::MarsagliaZaman(rng)
}

/// convert a vector of bytes to an ASCII string
pub fn hex2string(msg: &Vec<u8>) -> String {
    let mut res: String = String::new();
    for i in 0..msg.len() {
        res.push(msg[i] as char);
    }

    res
}