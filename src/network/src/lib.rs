pub mod channel;
pub mod network_info;
pub mod p2p;

pub mod lib {
    use std::any::type_name;

    // get data type
    pub fn type_of<T>(_: T) -> &'static str {
        type_name::<T>()
    }
}