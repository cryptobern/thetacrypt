use crate::keys::key_generator::KeyGenerator;
use crate::rand::StaticRNG;
use crate::{
    dl_schemes::{
        bigint::SizedBigInt,
        common::shamir_share,
        signatures::frost::{FrostRoundResult, FrostThresholdSignature},
    },
    group::GroupElement,
    interface::{
        InteractiveThresholdSignature, RoundResult, Serializable, Signature, ThresholdScheme,
    },
    keys::keys::PrivateKeyShare,
    rand::{RngAlgorithm, RNG},
};
use hex::FromHex;
use theta_proto::scheme_types::Group;

use super::frost::{FrostPrivateKey, FrostPublicKey, PublicCommitment};
use hex::ToHex;

#[test]
fn test_interface() {
    let k = 3;
    let n = 5;

    let keys = KeyGenerator::generate_keys(
        k,
        n,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Frost,
        &Group::Ed25519,
        &Option::None,
    )
    .unwrap();
    assert!(keys.len() == n);

    let msg = b"Test message!";
    let pk = keys[0].get_public_key();

    let mut instances = Vec::new();

    for i in 0..k {
        let mut I = InteractiveThresholdSignature::new(&keys[i]).unwrap();
        assert!(I.set_msg(msg).is_ok());
        instances.push(I);
    }

    let mut round_results = Vec::new();

    while !instances[0].is_finished() {
        for i in 0..k {
            round_results.push(instances[i].do_round().unwrap());
        }

        for i in 0..k {
            let mut j = 0;
            while !instances[i].is_ready_for_next_round() {
                assert!(instances[i].update(&round_results[j]).is_ok());
                j += 1;
            }
        }

        round_results.clear();
    }

    let signature = instances[0].get_signature().unwrap();

    assert!(InteractiveThresholdSignature::verify(&signature, &pk, msg).unwrap());
}

#[test]
fn test_private_key_serialization() {
    let keys = KeyGenerator::generate_keys(
        3,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Frost,
        &Group::Ed25519,
        &Option::None,
    )
    .unwrap();

    let bytes = keys[0].to_bytes();
    assert!(bytes.is_ok());
    let bytes = bytes.unwrap();
    let key = PrivateKeyShare::from_bytes(&bytes);
    assert!(key.is_ok());
    assert!(key.unwrap().eq(&keys[0]));
}

#[test]
fn test_round_result_serialization() {
    let keys = KeyGenerator::generate_keys(
        2,
        5,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Frost,
        &Group::Ed25519,
        &Option::None,
    )
    .unwrap();

    let mut I = InteractiveThresholdSignature::new(&keys[0]).unwrap();
    let mut I1 = InteractiveThresholdSignature::new(&keys[1]).unwrap();
    I.set_msg("msg".as_bytes());
    let rr = I.do_round().unwrap();
    let rr1 = I1.do_round().unwrap();
    let bytes = rr.to_bytes().unwrap();
    let rr0 = RoundResult::from_bytes(&bytes);
    assert!(rr0.is_ok());
    assert!(rr0.unwrap().eq(&rr));

    I.update(&rr);
    I.update(&rr1);
    let rr2 = I.do_round();
    assert!(rr2.is_ok());
    let rr2 = rr2.unwrap();
    let bytes = rr2.to_bytes().unwrap();
    let rr0 = RoundResult::from_bytes(&bytes);
    assert!(rr0.is_ok());
    assert!(rr0.unwrap().eq(&rr2));
}

#[test]
fn test_signature_serialization() {
    let k = 3;
    let n = 5;

    let keys = KeyGenerator::generate_keys(
        k,
        n,
        &mut RNG::new(RngAlgorithm::OsRng),
        &ThresholdScheme::Frost,
        &Group::Ed25519,
        &Option::None,
    )
    .unwrap();
    assert!(keys.len() == n);

    let msg = b"Test message!";
    let pk = keys[0].get_public_key();

    let mut instances = Vec::new();

    for i in 0..k {
        let mut I = InteractiveThresholdSignature::new(&keys[i]).unwrap();
        assert!(I.set_msg(msg).is_ok());
        instances.push(I);
    }

    let mut round_results = Vec::new();

    while !instances[0].is_finished() {
        for i in 0..k {
            round_results.push(instances[i].do_round().unwrap());
        }

        for i in 0..k {
            let mut j = 0;
            while !instances[i].is_ready_for_next_round() {
                assert!(instances[i].update(&round_results[j]).is_ok());
                j += 1;
            }
        }

        round_results.clear();
    }

    let signature = instances[0].get_signature().unwrap();

    let serialized = signature.to_bytes().unwrap();
    println!("serialized");
    let re = Signature::from_bytes(&serialized).unwrap();

    assert!(signature.eq(&re));
}

/* ToDo: verify assemble */
#[test]
fn test_vector() {
    let group = Group::Ed25519;
    let x = SizedBigInt::from_hex(
        &group,
        "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304",
    );
    let y = GroupElement::new_pow_big(&group, &x);

    println!("y: {}", hex::encode(y.to_bytes()));

    let msg = Vec::from_hex("74657374").expect("invalid hex");
    let coeff = SizedBigInt::from_hex(
        &group,
        "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204",
    );

    let k = 2;
    let n = 3;

    let share1 = SizedBigInt::from_hex(
        &group,
        "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509",
    );
    let share2 = SizedBigInt::from_hex(
        &group,
        "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d",
    );
    let share3 = SizedBigInt::from_hex(
        &group,
        "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02",
    );

    let c1 = GroupElement::new_pow_big(&group, &share1);
    let c2 = GroupElement::new_pow_big(&group, &share2);
    let c3 = GroupElement::new_pow_big(&group, &share3);

    let h = vec![c1, c2, c3];

    let pk = FrostPublicKey::new(n, k, &group, &y, &h);
    let sk1 = FrostPrivateKey::new(1, &share1, &pk);
    let sk2 = FrostPrivateKey::new(2, &share2, &pk);
    let sk3 = FrostPrivateKey::new(3, &share3, &pk);

    let mut i1 = FrostThresholdSignature::new(&sk1);
    let mut i3 = FrostThresholdSignature::new(&sk3);

    assert!(i1.set_msg(&msg).is_ok());
    assert!(i3.set_msg(&msg).is_ok());

    let rr1 = i1.commit(&mut RNG::Static(StaticRNG::new(String::from(
        "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501",
    ))));

    let hiding_nonce_1 = SizedBigInt::from_hex(
        &group,
        "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407",
    );
    let hiding_nonce_3 = SizedBigInt::from_hex(
        &group,
        "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e",
    );

    let binding_nonce_1 = SizedBigInt::from_hex(
        &group,
        "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301",
    );
    let binding_nonce_3 = SizedBigInt::from_hex(
        &group,
        "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d",
    );

    // TODO: Fix failing test here
    //assert_eq!(hiding_nonce_1, i1.get_nonce().clone().unwrap().hiding_nonce);

    /*

    let comm1 = PublicCommitment::new(
        1,
        GroupElement::new_pow_big(&group, &hiding_nonce_1),
        GroupElement::new_pow_big(&group, &binding_nonce_1),
    );

    let comm3 = PublicCommitment::new(
        3,
        GroupElement::new_pow_big(&group, &hiding_nonce_3),
        GroupElement::new_pow_big(&group, &binding_nonce_3),
    );

    let _ = i1.do_round().unwrap();
    let _ = i3.do_round().unwrap();

    i1.set_commitment(&comm1);
    i3.set_commitment(&comm3);

    let r1 = super::frost::FrostRoundResult::RoundOne(comm1);
    let r3 = super::frost::FrostRoundResult::RoundOne(comm3);

    i1.update(&r1).expect("error updating rr with r1");
    i1.update(&r3).expect("error updating rr with r3");
    i3.update(&r1).expect("error updating rr with r1");
    i3.update(&r3).expect("error updating rr with r3");

    assert!(i1.is_ready_for_next_round());
    assert!(i3.is_ready_for_next_round());

    let r1 = i1.do_round().unwrap();
    let r3 = i3.do_round().unwrap();
    let e1 = BigImpl::from_hex(
        &group,
        "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603",
    );
    let e3 = BigImpl::from_hex(
        &group,
        "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007",
    );*/

    /*if let FrostRoundResult::RoundTwo(r) = r1 {
        println!("{}", hex::encode(r.get_share().to_bytes()));
        assert!(e1.equals(&r.get_share()));
    }

    if let FrostRoundResult::RoundTwo(r) = r3 {
        assert!(e3.equals(&r.get_share()));
    }*/
}
