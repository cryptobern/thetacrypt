use std::fmt::{self, Debug, Display};

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

pub enum KeyStoreError {
    DuplicateEntry(String),
    IdMismatch,
    IdNotFound(String),
}

impl Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateEntry(id) => write!(f, "Key with id '{}' already exists", id),
            Self::IdNotFound(id) => {
                write!(f, "Could not find a key with the given key_id '{}'", id)
            }
            KeyStoreError::IdMismatch => write!(f, "Key id does not match key"),
        }
    }
}

impl Debug for KeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self, f)
    }
}
