pub mod threshold_cipher_protocol;
pub mod keychain;
// pub mod server;
// pub mod client;

pub mod requests {
    tonic::include_proto!("requests");
}
