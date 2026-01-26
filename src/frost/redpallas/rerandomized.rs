//! FROST implementation supporting re-randomizable keys.

use crate::frost::redpallas as frost;

use alloc::collections::btree_map::BTreeMap;

/// Re-randomized FROST signing using the given `randomizer_seed`, which should
/// be sent from the Coordinator using a confidential channel.
///
/// See [`crate::round2::sign`] for documentation on the other parameters.
pub fn sign_with_randomizer_seed(
    signing_package: &frost::SigningPackage,
    signer_nonces: &frost::round1::SigningNonces,
    key_package: &frost::keys::KeyPackage,
    randomizer_seed: &[u8],
) -> Result<frost::round2::SignatureShare, frost::Error> {
    frost_rerandomized::sign_with_randomizer_seed::<frost::PallasBlake2b512>(
        signing_package,
        signer_nonces,
        key_package,
        randomizer_seed,
    )
}

/// Re-randomized FROST signature share aggregation with the given
/// [`RandomizedParams`].
///
/// See [`frost_core::aggregate`] for documentation on the other parameters.
pub fn aggregate(
    signing_package: &frost::SigningPackage,
    signature_shares: &BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
    pubkeys: &frost::keys::PublicKeyPackage,
    randomized_params: &RandomizedParams,
) -> Result<frost::Signature, frost::Error> {
    frost_rerandomized::aggregate::<frost::PallasBlake2b512>(
        signing_package,
        signature_shares,
        pubkeys,
        randomized_params,
    )
}

/// Re-randomized FROST signature share aggregation with the given
/// [`RandomizedParams`] using the given cheater detection strategy.
///
/// See [`frost_core::aggregate_custom`] for documentation on the other parameters.
pub fn aggregate_custom(
    signing_package: &frost::SigningPackage,
    signature_shares: &BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
    pubkeys: &frost::keys::PublicKeyPackage,
    cheater_detection: frost::CheaterDetection,
    randomized_params: &RandomizedParams,
) -> Result<frost::Signature, frost::Error> {
    frost_rerandomized::aggregate_custom::<frost::PallasBlake2b512>(
        signing_package,
        signature_shares,
        pubkeys,
        cheater_detection,
        randomized_params,
    )
}

/// A randomizer. A random scalar which is used to randomize the key.
pub type Randomizer = frost_rerandomized::Randomizer<frost::PallasBlake2b512>;

/// Randomized parameters for a signing instance of randomized FROST.
pub type RandomizedParams = frost_rerandomized::RandomizedParams<frost::PallasBlake2b512>;
