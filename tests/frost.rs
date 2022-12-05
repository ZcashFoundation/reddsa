use std::{collections::HashMap, convert::TryFrom};

use frost_rerandomized::{self, frost_core::frost, frost_core::Ciphersuite, RandomizedParams};
use rand_core::{CryptoRng, RngCore};

use reddsa::orchard;

pub fn check_randomized_sign_with_dealer<C: Ciphersuite, R: RngCore + CryptoRng>(mut rng: R) {
    ////////////////////////////////////////////////////////////////////////////
    // Key generation
    ////////////////////////////////////////////////////////////////////////////

    let max_signers = 5;
    let min_signers = 3;
    let (shares, pubkeys) =
        frost::keys::keygen_with_dealer(max_signers, min_signers, &mut rng).unwrap();

    // Verifies the secret shares from the dealer
    let key_packages: HashMap<frost::Identifier<C>, frost::keys::KeyPackage<C>> = shares
        .into_iter()
        .map(|share| {
            (
                share.identifier,
                frost::keys::KeyPackage::try_from(share).unwrap(),
            )
        })
        .collect();

    let mut nonces: HashMap<frost::Identifier<C>, frost::round1::SigningNonces<C>> = HashMap::new();
    let mut commitments: HashMap<frost::Identifier<C>, frost::round1::SigningCommitments<C>> =
        HashMap::new();

    let randomizer_params = RandomizedParams::new(&pubkeys, &mut rng);

    ////////////////////////////////////////////////////////////////////////////
    // Round 1: generating nonces and signing commitments for each participant
    ////////////////////////////////////////////////////////////////////////////

    for participant_index in 1..(min_signers as u16 + 1) {
        let participant_identifier = participant_index.try_into().expect("should be nonzero");
        // Generate one (1) nonce and one SigningCommitments instance for each
        // participant, up to _min_signers_.
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

    // This is what the signature aggregator / coordinator needs to do:
    // - decide what message to sign
    // - take one (unused) commitment per signing participant
    let mut signature_shares: Vec<frost::round2::SignatureShare<_>> = Vec::new();
    let message = "message to sign".as_bytes();
    let comms = commitments.clone().into_values().collect();
    let signing_package = frost::SigningPackage::new(comms, message.to_vec());

    ////////////////////////////////////////////////////////////////////////////
    // Round 2: each participant generates their signature share
    ////////////////////////////////////////////////////////////////////////////

    for participant_identifier in nonces.keys() {
        let key_package = key_packages.get(participant_identifier).unwrap();

        let nonces_to_use = &nonces.get(participant_identifier).unwrap();

        // Each participant generates their signature share.
        let signature_share = frost_rerandomized::sign(
            &signing_package,
            nonces_to_use,
            key_package,
            randomizer_params.randomizer_point(),
        )
        .unwrap();
        signature_shares.push(signature_share);
    }

    ////////////////////////////////////////////////////////////////////////////
    // Aggregation: collects the signing shares from all participants,
    // generates the final signature.
    ////////////////////////////////////////////////////////////////////////////

    // Aggregate (also verifies the signature shares)
    let group_signature_res = frost_rerandomized::aggregate(
        &signing_package,
        &signature_shares[..],
        &pubkeys,
        &randomizer_params,
    );

    assert!(group_signature_res.is_ok());

    let group_signature = group_signature_res.unwrap();

    // Check that the threshold signature can be verified by the randomized group public
    // key (the verification key).
    assert!(randomizer_params
        .randomized_group_public_key()
        .verify(message, &group_signature)
        .is_ok());

    // Note that key_package.group_public can't be used to verify the signature
    // since those are non-randomized.

    // Check that the threshold signature can be verified by the `reddsa` crate
    // public key (interoperability test)

    let sig = {
        let bytes: [u8; 64] = group_signature.to_bytes().as_ref().try_into().unwrap();
        reddsa::Signature::<orchard::SpendAuth>::from(bytes)
    };
    let pk_bytes = {
        let bytes: [u8; 32] = randomizer_params
            .randomized_group_public_key()
            .to_bytes()
            .as_ref()
            .try_into()
            .unwrap();
        reddsa::VerificationKeyBytes::<orchard::SpendAuth>::from(bytes)
    };

    // Check that the verification key is a valid RedDSA verification key.
    let pub_key = reddsa::VerificationKey::try_from(pk_bytes)
        .expect("The test verification key to be well-formed.");

    // Check that signature validation has the expected result.
    assert!(pub_key.verify(message, &sig).is_ok());
}
