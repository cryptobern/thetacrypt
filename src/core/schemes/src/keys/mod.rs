pub mod key_generator;
pub mod key_store;
mod key_store_tests;
pub mod keys;

#[macro_export]
macro_rules! unwrap_enum_vec {
    ($vec:expr, $variant:path, $err:expr) => {{
        let mut vec = Vec::new();
        for i in 0..$vec.len() {
            let val = &$vec[i];
            match val {
                $variant(x) => {
                    vec.push((*x).clone());
                }
                _ => Err($err)?,
            }
        }
        Ok(vec)
    }};
}
