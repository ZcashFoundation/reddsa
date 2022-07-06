use std::{collections::HashMap, convert::TryFrom};

use frost_core::{frost, Ciphersuite, Field, Group};
use group::GroupEncoding;
use rand::thread_rng;
use reddsa::{frost_redpallas::*, orchard};

#[test]
fn check_sign_with_dealer() {
    let rng = thread_rng();

    frost_core::tests::check_sign_with_dealer::<PallasBlake2b512, _>(rng);
}

#[test]
fn check_randomized_sign_with_dealer() {
    let mut rng = thread_rng();

    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let numsigners = 5;
    let threshold = 3;
    let (shares, pubkeys) = keys::keygen_with_dealer(numsigners, threshold, &mut rng).unwrap();

    // Verifies the secret shares from the dealer
    let key_packages: HashMap<frost::Identifier<_>, frost::keys::KeyPackage<_>> = shares
        .into_iter()
        .map(|share| {
            (
                share.identifier,
                frost::keys::KeyPackage::try_from(share).unwrap(),
            )
        })
        .collect();

    let mut nonces: HashMap<frost::Identifier<_>, frost::round1::SigningNonces<_>> = HashMap::new();
    let mut commitments: HashMap<frost::Identifier<_>, frost::round1::SigningCommitments<_>> =
        HashMap::new();

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    for participant_index in 1..(threshold as u16 + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _threshold_.
        let (nonce, commitment) = frost::round1::commit(
            participant_identifier,
            key_packages
                .get(&participant_identifier)
                .unwrap()
                .secret_share(),
            &mut rng,
        );
        nonces.insert(participant_identifier, nonce);
        commitments.insert(participant_identifier, commitment);
    }

    let randomizer = PallasScalarField::random(&mut rng);
    let randomizer_point =
        <<PallasBlake2b512 as Ciphersuite>::Group as Group>::generator() * randomizer;

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares: Vec<frost::round2::SignatureShare<_>> = Vec::new();
    let message = "message to sign".as_bytes();
    let comms = commitments.clone().into_values().collect();
    let signing_package =
        frost::SigningPackage::with_randomizer(comms, message.to_vec(), randomizer_point);

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    for participant_identifier in nonces.keys() {
        let key_package = key_packages.get(participant_identifier).unwrap();

        let nonces_to_use = &nonces.get(participant_identifier).unwrap();

        // Each participant generates their signature share.
        let signature_share =
            frost::round2::sign(&signing_package, nonces_to_use, key_package).unwrap();
        signature_shares.push(signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate (also verifies the signature shares)
    let group_signature_res = frost::aggregate(
        &signing_package,
        &signature_shares[..],
        &pubkeys,
        Some(randomizer),
    );

    assert!(group_signature_res.is_ok());

    let group_signature = group_signature_res.unwrap();

    let group_public_point = PallasGroup::deserialize(&pubkeys.group_public.to_bytes())
        .expect("should deserialize since it was just serialized");
    let randomized_group_public_point = group_public_point + PallasGroup::generator() * randomizer;
    let randomized_group_public =
        VerifyingKey::from_bytes(randomized_group_public_point.to_bytes())
            .expect("should work since it was just serialized");

    // Check that the threshold signature can be verified by the randomized group public
    // key (the verification key).
    assert!(randomized_group_public
        .verify(message, &group_signature)
        .is_ok());

    // Note that key_package.group_public can't be used to verify the signature
    // since those are non-randomized.

    // Check that the threshold signature can be verified by the `reddsa` crate
    // public key (interoperability test)

    let sig = {
        let bytes: [u8; 64] = group_signature.to_bytes();
        reddsa::Signature::<orchard::SpendAuth>::from(bytes)
    };
    let pk_bytes = {
        let bytes: [u8; 32] = randomized_group_public.to_bytes();
        reddsa::VerificationKeyBytes::<orchard::SpendAuth>::from(bytes)
    };

    // Check that the verification key is a valid RedDSA verification key.
    let pub_key = reddsa::VerificationKey::try_from(pk_bytes)
        .expect("The test verification key to be well-formed.");

    // Check that signature validation has the expected result.
    assert!(pub_key.verify(message, &sig).is_ok());
}
