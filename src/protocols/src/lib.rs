pub mod threshold_cipher_protocol;
// pub mod server;
// pub mod client;

pub mod requests {
    tonic::include_proto!("requests");
}

#[cfg(test)]
mod tests {
    use mcore::rand::RAND_impl;
    use rand::{thread_rng, prelude::SliceRandom};
    use cosmos_crypto::{dl_schemes::{ciphers::{sg02::{Sg02ThresholdCipher}, bz03::Bz03ThresholdCipher}, dl_groups::{bls12381::Bls12381, dl_group::DlGroup}}, interface::{Ciphertext, ThresholdCipher, PrivateKey, ThresholdCipherParams}, rand::{RNG, RngAlgorithm}};

    use super::requests;

    #[test]
    pub fn threshold_decryption() {
        const k: usize = 11; // threshold
    const N: usize = 15; // total number of secret shares

    let mut rng = RNG::new(RngAlgorithm::MarsagliaZaman);
    let sk_sg02_bls12381 = Sg02ThresholdCipher::generate_keys(k, N, Bls12381::new(), &mut rng);
    let sk_bz03_bls12381 = Bz03ThresholdCipher::generate_keys(k, N, Bls12381::new(), &mut rng);
    
    // Create decryption request
    let sn = 1;
    let (ctxt_sg02_bls12381, req)= create_decryption_request::<Sg02ThresholdCipher<Bls12381>>(sn, k,&sk_sg02_bls12381[0].get_public_key());
    let shares = get_decryption_shares_permuted::<Sg02ThresholdCipher<Bls12381>>(k, &ctxt_sg02_bls12381, &sk_sg02_bls12381);
    let (ctxt_bz003_bls12381, req)= create_decryption_request::<Bz03ThresholdCipher<Bls12381>>(sn, k,&sk_bz03_bls12381[0].get_public_key());

    // Create the request handler for party with id 1
    
        // println!("Starting instance {}.", &sn);
        // instance.on_init();
            
        // for share in shares {
        //     // Protocol instance has calculated share 0 by itself
        //     if share.get_id() == 1 {
        //         continue;
        //     }
        //     println!("Passing share with id={} to instance {}", share.get_id(), &sn);
        //     instance.on_receive_decryption_share(share);  
        // }
        // match instance.get_plaintext(){
        //     Some(msg) => {
        //         let decrypted_msg = String::from_utf8(msg).unwrap();
        //         if decrypted_msg != orig_msg {
        //             panic!("Wrong plaintext from instance {}.", sn);
        //         } else {
        //             println!("Decryption from instance {} succesful.", sn);
        //         }
        //     },   
        //     None => panic!("Problem with instance {}.", sn),
        // };
    }

    fn create_decryption_request<C:ThresholdCipher>(sn: u32, k: usize, pk: &C::TPubKey) -> (C::CT, requests::ThresholdDecryptionRequest) {
        let mut params = ThresholdCipherParams::new();
        let msg_string = format!("Test message {}", sn);
        let msg: Vec<u8> = msg_string.as_bytes().to_vec();
        let label = format!("Label {}", sn);
        let ciphertext = C::encrypt(&msg, label.as_bytes(), pk, &mut params);
        let req = requests::ThresholdDecryptionRequest {
            algorithm: requests::ThresholdCipher::Sg02 as i32,
            dl_group: requests::DlGroup::Bls12381 as i32,
            ciphertext: ciphertext.get_msg(),
        };
        (ciphertext, req)
    }
    
    fn get_decryption_shares_permuted<C: ThresholdCipher>(K: usize, ctxt: &C::CT, sk: &Vec<C::TPrivKey>) -> Vec<C::TShare> {
        let mut params = ThresholdCipherParams::new();
        let mut shares = Vec::new();
        for i in 0..K {
            shares.push(C::partial_decrypt(ctxt,&sk[i as usize], &mut params));
        }
        shares.shuffle(&mut thread_rng());
        shares
    }
}