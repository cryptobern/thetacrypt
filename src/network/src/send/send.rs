use cosmos_crypto::dl_schemes::ciphers::sg02::SG02_ThresholdCipher;

pub struct SendMessage<T> {
    pub from: u32,
    pub msg: T,
}

impl<T> SendMessage<T> {
    pub fn broadcast(&self) {
        println!("broadcast msg from: {}", &self.from);
    }

    pub fn p2p(&self, to: u32) {
        println!("p2p msg from: {}", &self.from);
        println!("p2p msg to: {:#?}", to);
    }
}