/*use rasn::{types::ObjectIdentifier, AsnType, Decode, Encode, Encoder, der::{decode, encode}};

use crate::interface::{Serializable, PrivateKey};

use super::{keygen::DlPrivateKey, DlDomain};

struct Attribute {

}

#[derive(Clone, Decode, Copy, Encode, AsnType)]
#[rasn(enumerated)]
pub enum AlgorithmIdentifier {
    SG02_BLS12381,
    SG02_BN254,
    SG02_ED25519,
    BLS04_BLS12381,
    BLS04_BN254,
    BLS04_ED25519,
    BZ03_BLS12381,
    BZ03_BN254,
    BZ03_ED25519
}

#[derive(Clone, AsnType)]
pub struct Pkcs8PrivateKeyInfo {
    version:i32,
    privateKeyAlgorithm: AlgorithmIdentifier,
    privateKey:Vec<u8>
}

impl Decode for Pkcs8PrivateKeyInfo {
    fn decode_with_tag<Dec: rasn::Decoder>(decoder: &mut Dec, tag: rasn::Tag) -> Result<Self, Dec::Error> {
        decoder.decode_sequence(tag, |sequence| {
            let version = i32::decode(sequence)?;
            let privateKeyAlgorithm = AlgorithmIdentifier::decode(sequence)?;
            let privateKey = Vec::<u8>::decode(sequence)?;

            Ok(Self {version, privateKeyAlgorithm, privateKey})
        })
    }
}

impl Encode for Pkcs8PrivateKeyInfo{
    fn encode_with_tag<E: rasn::Encoder>(&self, encoder: &mut E, tag: rasn::Tag) -> Result<(), E::Error> {
        encoder.encode_sequence(tag, |sequence| {
            self.version.encode(sequence)?;
            self.privateKeyAlgorithm.encode(sequence)?;
            self.privateKey.encode(sequence)?;
            Ok(())
        })?;

        Ok(())
    }
}

impl Pkcs8PrivateKeyInfo {
    pub fn encodePrivateKey<D: DlDomain>(privateKey: &DlPrivateKey<D>) -> Vec<u8> {
        match privateKey {
            DlPrivateKey::BZ03(key) => {
                let bytes = key.serialize().unwrap();

                println!("{}", std::any::type_name::<D>());
                

                let pkcs8PrivateKey = Pkcs8PrivateKeyInfo {version:1, privateKeyAlgorithm:AlgorithmIdentifier::BZ03_BLS12381, privateKey:bytes};
                encode(&pkcs8PrivateKey).unwrap()
            },
            _ => {
                panic!("error encoding private key");
            }
        }
    }

    pub fn decodeParams(bytes: &[u8]) -> (AlgorithmIdentifier, Vec<u8>) {
        let privateKeyInfo: Pkcs8PrivateKeyInfo = decode(bytes).unwrap();
        (privateKeyInfo.privateKeyAlgorithm, privateKeyInfo.privateKey)
    }
}*/