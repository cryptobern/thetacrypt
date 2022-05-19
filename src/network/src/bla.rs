
// use cosmos_crypto::dl_schemes::ciphers::sg02::SG02_ThresholdCipher;
// use libp2p::{identity, PeerId};
// use std::error::Error;

// use crate::send::send::SendMessage;
// use crate::deliver::deliver::DeliverMessage;

// mod send;
// mod deliver;

// #[async_std::main]
// fn main() {
    // let bc_msg = SendMessage { from: 123, msg: "hello world" };
    // bc_msg.broadcast();
    // let p2p_msg = SendMessage { from: 123, msg: "hello p2p world" };
    // p2p_msg.p2p(789);

    // let deliver_msg = DeliverMessage { from: 789, msg: "hello back" };
    // deliver_msg.deliver();

    // generate secret shares for SG02 scheme over Bls12381 curve
    // let sk = SG02_ThresholdCipher::generate_keys(K, N, Bls12381::new(), &mut rng);
    // println!("Keys generated");

    // a public key is stored inside each secret share, so those can be used for encryption
    // let ciphertext = SG02_ThresholdCipher::encrypt(&msg, label, &sk[0].get_public_key(), &mut rng);

// }