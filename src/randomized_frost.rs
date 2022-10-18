//! Randomized FROST support.
//!
#![allow(non_snake_case)]

use alloc::vec::Vec;
use frost_core::{frost::keys::PublicKeyPackage, VerifyingKey};
#[cfg(feature = "alloc")]
use frost_core::{
    frost::{self},
    Ciphersuite, Field, Group,
};

pub use frost_core::Error;
use rand_core::{CryptoRng, RngCore};

/// Compute the preimages to H3 to compute the per-signer rhos
// We separate this out into its own method so it can be tested
fn binding_factor_preimages<C: Ciphersuite>(
    signing_package: &frost::SigningPackage<C>,
    randomizer_point: &<C::Group as Group>::Element,
) -> Vec<(frost::Identifier<C>, Vec<u8>)> {
    let mut binding_factor_input_prefix = vec![];

    binding_factor_input_prefix
        .extend_from_slice(C::H4(signing_package.message().as_slice()).as_ref());
    binding_factor_input_prefix.extend_from_slice(
        C::H5(&frost::round1::encode_group_commitments(signing_package.signing_commitments())[..])
            .as_ref(),
    );
    binding_factor_input_prefix
        .extend_from_slice(<C::Group as Group>::serialize(randomizer_point).as_ref());

    signing_package
        .signing_commitments()
        .iter()
        .map(|c| {
            let mut binding_factor_input = vec![];

            binding_factor_input.extend_from_slice(&binding_factor_input_prefix);
            binding_factor_input.extend_from_slice(c.identifier.serialize().as_ref());
            (c.identifier, binding_factor_input)
        })
        .collect()
}

fn compute_binding_factor_list<C>(
    signing_package: &frost::SigningPackage<C>,
    randomizer_point: &<C::Group as Group>::Element,
) -> frost::BindingFactorList<C>
where
    C: Ciphersuite,
{
    let preimages = binding_factor_preimages(signing_package, randomizer_point);

    frost::BindingFactorList::new(
        preimages
            .iter()
            .map(|(identifier, preimage)| {
                let binding_factor = C::H1(preimage);
                (*identifier, frost::BindingFactor::new(binding_factor))
            })
            .collect(),
    )
}

/// Performed once by each participant selected for the signing operation.
///
/// Implements [`sign`] from the spec.
///
/// Receives the message to be signed and a set of signing commitments and a set
/// of randomizing commitments to be used in that signing operation, including
/// that for this participant.
///
/// Assumes the participant has already determined which nonce corresponds with
/// the commitment that was assigned by the coordinator in the SigningPackage.
///
/// [`sign`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-10.html#name-round-two-signature-share-g
pub fn sign<C: Ciphersuite>(
    signing_package: &frost::SigningPackage<C>,
    signer_nonces: &frost::round1::SigningNonces<C>,
    key_package: &frost::keys::KeyPackage<C>,
    randomizer_point: &<C::Group as Group>::Element,
) -> Result<frost::round2::SignatureShare<C>, &'static str> {
    let public_key = key_package.group_public.to_element() + *randomizer_point;

    // Encodes the signing commitment list produced in round one as part of generating [`Rho`], the
    // binding factor.
    let binding_factor_list = compute_binding_factor_list(signing_package, randomizer_point);

    let rho: frost::BindingFactor<C> = binding_factor_list[key_package.identifier].clone();

    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = frost::compute_group_commitment(signing_package, &binding_factor_list)?;

    // Compute Lagrange coefficient.
    let lambda_i = frost::derive_lagrange_coeff(key_package.identifier(), signing_package)?;

    // Compute the per-message challenge.
    let challenge = frost_core::challenge::<C>(
        &group_commitment.to_element(),
        &public_key,
        signing_package.message().as_slice(),
    );

    // Compute the Schnorr signature share.
    let z_share: <<C::Group as Group>::Field as Field>::Scalar =
        signer_nonces.hiding.clone().to_scalar()
            + (signer_nonces.binding.clone().to_scalar() * rho.to_scalar())
            + (lambda_i * key_package.secret_share.to_scalar() * challenge.to_scalar());

    let signature_share = frost::round2::SignatureShare::<C> {
        identifier: *key_package.identifier(),
        signature: frost::round2::SignatureResponse::<C> { z_share },
    };

    Ok(signature_share)
}

/// Verifies each participant's signature share, and if all are valid,
/// aggregates the shares into a signature to publish.
///
/// Resulting signature is compatible with verification of a plain SpendAuth
/// signature.
///
/// This operation is performed by a coordinator that can communicate with all
/// the signing participants before publishing the final signature. The
/// coordinator can be one of the participants or a semi-trusted third party
/// (who is trusted to not perform denial of service attacks, but does not learn
/// any secret information). Note that because the coordinator is trusted to
/// report misbehaving parties in order to avoid publishing an invalid
/// signature, if the coordinator themselves is a signer and misbehaves, they
/// can avoid that step. However, at worst, this results in a denial of
/// service attack due to publishing an invalid signature.
pub fn aggregate<C>(
    signing_package: &frost::SigningPackage<C>,
    signature_shares: &[frost::round2::SignatureShare<C>],
    pubkeys: &frost::keys::PublicKeyPackage<C>,
    randomized_params: &RandomizedParams<C>,
) -> Result<frost_core::Signature<C>, &'static str>
where
    C: Ciphersuite,
{
    let public_key = pubkeys.group_public.to_element() + *randomized_params.randomizer_point();

    // Encodes the signing commitment list produced in round one as part of generating [`Rho`], the
    // binding factor.
    let binding_factor_list =
        compute_binding_factor_list(signing_package, randomized_params.randomizer_point());

    // Compute the group commitment from signing commitments produced in round one.
    let group_commitment = frost::compute_group_commitment(signing_package, &binding_factor_list)?;

    // Compute the per-message challenge.
    let challenge = frost_core::challenge::<C>(
        &group_commitment.clone().to_element(),
        &public_key,
        signing_package.message().as_slice(),
    );

    // Verify the signature shares.
    for signature_share in signature_shares {
        // Look up the public key for this signer, where `signer_pubkey` = _G.ScalarBaseMult(s[i])_,
        // and where s[i] is a secret share of the constant term of _f_, the secret polynomial.
        let signer_pubkey = pubkeys
            .signer_pubkeys
            .get(&signature_share.identifier)
            .unwrap();

        // Compute Lagrange coefficient.
        let lambda_i = frost::derive_lagrange_coeff(&signature_share.identifier, signing_package)?;

        let rho = binding_factor_list[signature_share.identifier].clone();

        // Compute the commitment share.
        let R_share = signing_package
            .signing_commitment(&signature_share.identifier)
            .to_group_commitment_share(&rho);

        // Compute relation values to verify this signature share.
        signature_share.verify(&R_share, signer_pubkey, lambda_i, &challenge)?;
    }

    // The aggregation of the signature shares by summing them up, resulting in
    // a plain Schnorr signature.
    //
    // Implements [`aggregate`] from the spec.
    //
    // [`aggregate`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-10.html#section-5.3
    let mut z = <<C::Group as Group>::Field as Field>::zero();

    for signature_share in signature_shares {
        z = z + signature_share.signature.z_share;
    }

    z = z + challenge.to_scalar() * randomized_params.randomizer;

    Ok(frost_core::Signature::new(group_commitment.to_element(), z))
}

/// Randomized params for a signing instance of randomized FROST.
pub struct RandomizedParams<C: Ciphersuite> {
    /// The randomizer, also called `alpha`
    randomizer: frost_core::Scalar<C>,
    /// The generator multiplied by the randomizer.
    randomizer_point: <C::Group as Group>::Element,
    /// The randomized group public key. The group public key added to the randomizer point.
    randomized_group_public_key: frost_core::VerifyingKey<C>,
}

impl<C> RandomizedParams<C>
where
    C: Ciphersuite,
{
    /// Create a new RandomizedParams for the given [`PublicKeyPackage`]
    pub fn new<R: RngCore + CryptoRng>(
        public_key_package: &PublicKeyPackage<C>,
        mut rng: R,
    ) -> Self {
        let randomizer = <<C::Group as Group>::Field as Field>::random(&mut rng);
        let randomizer_point = <C::Group as Group>::generator() * randomizer;

        let group_public_point = public_key_package.group_public.to_element();

        let randomized_group_public_point = group_public_point + randomizer_point;
        let randomized_group_public_key = VerifyingKey::new(randomized_group_public_point);

        Self {
            randomizer,
            randomizer_point,
            randomized_group_public_key,
        }
    }

    /// Return the randomizer point.
    ///
    /// It must be sent by the coordinator to each participant when signing.
    pub fn randomizer_point(&self) -> &<C::Group as Group>::Element {
        &self.randomizer_point
    }

    /// Return the randomizer point.
    ///
    /// It must be sent by the coordinator to each participant when signing.
    pub fn randomized_group_public_key(&self) -> &frost_core::VerifyingKey<C> {
        &self.randomized_group_public_key
    }
}