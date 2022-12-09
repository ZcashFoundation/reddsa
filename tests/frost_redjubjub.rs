#![cfg(feature = "frost")]

use rand::thread_rng;

use reddsa::{frost_redjubjub::JubjubBlake2b512, sapling};

#[test]
fn check_sign_with_dealer() {
    let rng = thread_rng();

    frost_rerandomized::frost_core::tests::check_sign_with_dealer::<JubjubBlake2b512, _>(rng);
}

#[test]
fn check_randomized_sign_with_dealer() {
    let rng = thread_rng();

    let (msg, group_signature, group_pubkey) =
        frost_rerandomized::tests::check_randomized_sign_with_dealer::<JubjubBlake2b512, _>(rng);

    // Check that the threshold signature can be verified by the `reddsa` crate
    // public key (interoperability test)

    let sig = {
        let bytes: [u8; 64] = group_signature.to_bytes().as_ref().try_into().unwrap();
        reddsa::Signature::<sapling::SpendAuth>::from(bytes)
    };
    let pk_bytes = {
        let bytes: [u8; 32] = group_pubkey.to_bytes().as_ref().try_into().unwrap();
        reddsa::VerificationKeyBytes::<sapling::SpendAuth>::from(bytes)
    };

    // Check that the verification key is a valid RedDSA verification key.
    let pub_key = reddsa::VerificationKey::try_from(pk_bytes)
        .expect("The test verification key to be well-formed.");

    // Check that signature validation has the expected result.
    assert!(pub_key.verify(&msg, &sig).is_ok());
}

#[test]
fn check_sign_with_dkg() {
    let rng = thread_rng();

    frost_rerandomized::frost_core::tests::check_sign_with_dkg::<JubjubBlake2b512, _>(rng);
}
