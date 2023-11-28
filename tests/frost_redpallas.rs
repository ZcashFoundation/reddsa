#![cfg(feature = "frost")]

use std::collections::BTreeMap;

use frost_rerandomized::frost_core::{self as frost, Ciphersuite, Group, GroupError};
use rand::thread_rng;

use reddsa::{
    frost::redpallas::{keys::EvenY, PallasBlake2b512},
    orchard,
};

#[test]
fn check_sign_with_dealer() {
    let rng = thread_rng();

    frost::tests::ciphersuite_generic::check_sign_with_dealer::<PallasBlake2b512, _>(rng);
}

#[test]
fn check_randomized_sign_with_dealer() {
    let rng = thread_rng();

    let (msg, group_signature, group_pubkey) =
        frost_rerandomized::tests::check_randomized_sign_with_dealer::<PallasBlake2b512, _>(rng);

    // Check that the threshold signature can be verified by the `reddsa` crate
    // public key (interoperability test)

    let sig = {
        let bytes: [u8; 64] = group_signature.serialize().as_ref().try_into().unwrap();
        reddsa::Signature::<orchard::SpendAuth>::from(bytes)
    };
    let pk_bytes = {
        let bytes: [u8; 32] = group_pubkey.serialize().as_ref().try_into().unwrap();
        reddsa::VerificationKeyBytes::<orchard::SpendAuth>::from(bytes)
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

    frost::tests::ciphersuite_generic::check_sign_with_dkg::<PallasBlake2b512, _>(rng);
}

#[test]
fn check_deserialize_identity() {
    let encoded_identity = <PallasBlake2b512 as Ciphersuite>::Group::serialize(
        &<PallasBlake2b512 as Ciphersuite>::Group::identity(),
    );
    let r = <PallasBlake2b512 as Ciphersuite>::Group::deserialize(&encoded_identity);
    assert_eq!(r, Err(GroupError::InvalidIdentityElement));
}

#[test]
fn check_deserialize_non_canonical() {
    let encoded_generator = <PallasBlake2b512 as Ciphersuite>::Group::serialize(
        &<PallasBlake2b512 as Ciphersuite>::Group::generator(),
    );
    let r = <PallasBlake2b512 as Ciphersuite>::Group::deserialize(&encoded_generator);
    assert!(r.is_ok());

    // This is x = p + 3 which is non-canonical and maps to a valid point.
    let encoded_point =
        hex::decode("04000000ed302d991bf94c09fc98462200000000000000000000000000000040")
            .unwrap()
            .try_into()
            .unwrap();
    let r = <PallasBlake2b512 as Ciphersuite>::Group::deserialize(&encoded_point);
    assert_eq!(r, Err(GroupError::MalformedElement));
}

#[test]
fn check_even_y_frost_core() {
    let mut rng = thread_rng();

    // Since there is a 50% chance of the public key having an odd Y (which
    // we need to actually test), loop until we get an odd Y.
    loop {
        let max_signers = 5;
        let min_signers = 3;
        // Generate keys with frost-core function, which doesn't ensure even Y
        let (shares, public_key_package) =
            frost::keys::generate_with_dealer::<PallasBlake2b512, _>(
                max_signers,
                min_signers,
                frost::keys::IdentifierList::Default,
                &mut rng,
            )
            .unwrap();

        if !public_key_package.has_even_y() {
            // Test consistency of into_even_y() for PublicKeyPackage
            let even_public_key_package_is_even_none = public_key_package.clone().into_even_y(None);
            let even_public_key_package_is_even_false =
                public_key_package.clone().into_even_y(Some(false));
            assert_eq!(
                even_public_key_package_is_even_false,
                even_public_key_package_is_even_none
            );
            assert_ne!(public_key_package, even_public_key_package_is_even_false);
            assert_ne!(public_key_package, even_public_key_package_is_even_none);

            // Test consistency of into_even_y() for SecretShare (arbitrarily on
            // the first secret share)
            let secret_share = shares.first_key_value().unwrap().1.clone();
            let even_secret_share_is_even_none = secret_share.clone().into_even_y(None);
            let even_secret_share_is_even_false = secret_share.clone().into_even_y(Some(false));
            assert_eq!(
                even_secret_share_is_even_false,
                even_secret_share_is_even_none
            );
            assert_ne!(secret_share, even_secret_share_is_even_false);
            assert_ne!(secret_share, even_secret_share_is_even_none);

            // Make secret shares even, then convert into KeyPackages
            let key_packages_evened_before: BTreeMap<_, _> = shares
                .clone()
                .into_iter()
                .map(|(identifier, share)| {
                    Ok((
                        identifier,
                        frost::keys::KeyPackage::try_from(share.into_even_y(None))?,
                    ))
                })
                .collect::<Result<_, frost::Error<PallasBlake2b512>>>()
                .unwrap();
            // Convert into KeyPackages, then make them even
            let key_packages_evened_after: BTreeMap<_, _> = shares
                .into_iter()
                .map(|(identifier, share)| {
                    Ok((
                        identifier,
                        frost::keys::KeyPackage::try_from(share)?.into_even_y(None),
                    ))
                })
                .collect::<Result<_, frost::Error<PallasBlake2b512>>>()
                .unwrap();
            // Make sure they are equal
            assert_eq!(key_packages_evened_after, key_packages_evened_before);

            // Check if signing works with evened keys
            frost::tests::ciphersuite_generic::check_sign(
                min_signers,
                key_packages_evened_after,
                &mut rng,
                even_public_key_package_is_even_none,
            )
            .unwrap();

            // We managed to test it; break the loop and return
            break;
        }
    }
}

#[test]
fn check_even_y_reddsa() {
    let mut rng = thread_rng();

    // Since there is a ~50% chance of having a odd Y internally, to make sure
    // that odd Ys are converted to even, we test multiple times to increase
    // the chance of an odd Y being generated internally
    for _ in 0..16 {
        let max_signers = 5;
        let min_signers = 3;
        // Generate keys with reexposed reddsa function, which ensures even Y
        let (shares, public_key_package) =
            reddsa::frost::redpallas::keys::generate_with_dealer::<_>(
                max_signers,
                min_signers,
                frost::keys::IdentifierList::Default,
                &mut rng,
            )
            .unwrap();

        assert!(public_key_package.has_even_y());
        assert!(shares.values().all(|s| s.has_even_y()));
    }
}
