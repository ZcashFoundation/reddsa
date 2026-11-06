use super::*;
use crate::private::Sealed;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

type SaplingItem = Item<sapling::SpendAuth, sapling::Binding>;

#[test]
fn retained_keys_are_omitted_from_batch_decoding() {
    let bytes = jubjub::AffinePoint::identity().to_bytes();
    let key = VerificationKey::<sapling::Binding>::try_from(bytes).unwrap();
    let sig = Signature::from([42; 64]);
    let retained = SaplingItem::from_binding_key(key, sig, b"message");
    let encoded = SaplingItem::from_binding(key.into(), sig, b"message");
    let spend = SaplingItem::from_spendauth(bytes.into(), [43; 64].into(), b"message");
    let spend_key = VerificationKey::<sapling::SpendAuth>::try_from(bytes).unwrap();
    let retained_spend = SaplingItem::from_spendauth_key(spend_key, [44; 64].into(), b"message");
    let encodings: Vec<_> = [retained, encoded, spend, retained_spend]
        .iter()
        .flat_map(Item::point_encodings)
        .collect();
    assert_eq!(
        encodings,
        [[42; 32], [42; 32], bytes, [43; 32], bytes, [44; 32]]
    );
    // Retaining a native point should not require boxing or a large stack item.
    assert!(core::mem::size_of::<SaplingItem>() <= 320);
}

#[test]
fn batch_decoding_matches_individual_decoding_including_zip216() {
    let mut rng = ChaChaRng::from_seed([91; 32]);
    let mut encodings = vec![[0xff; 32], jubjub::AffinePoint::identity().to_bytes()];
    let minus_one = jubjub::AffinePoint::from_raw_unchecked(jubjub::Fq::zero(), -jubjub::Fq::one());
    encodings.push(minus_one.to_bytes());
    // ZIP 216 rejects a set sign bit when u is zero, for both v = +/-1.
    for mut bytes in [encodings[1], encodings[2]] {
        bytes[31] |= 0x80;
        assert!(bool::from(
            jubjub::ExtendedPoint::from_bytes(&bytes).is_none()
        ));
        encodings.push(bytes);
    }
    for _ in 0..256 {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes);
        encodings.push(bytes);
    }
    let decoded = sapling::SpendAuth::batch_decode_points(encodings.iter().copied()).unwrap();
    for (bytes, batch_point) in encodings.into_iter().zip(decoded) {
        assert_eq!(
            batch_point,
            Option::<jubjub::ExtendedPoint>::from(jubjub::ExtendedPoint::from_bytes(&bytes))
        );
    }
}

#[test]
fn retained_and_byte_keys_preserve_nontrivial_torsion_components() {
    // The canonical v = 0 encoding is an order-four point on Jubjub.
    let torsion = jubjub::AffinePoint::from_bytes([0; 32])
        .unwrap()
        .to_extended();
    let secret = jubjub::Scalar::from(7);
    let nonce = jubjub::Scalar::from(11);
    let point = sapling::SpendAuth::basepoint() * secret + torsion;
    let bytes = point.to_bytes();
    let key = VerificationKey::<sapling::SpendAuth>::try_from(bytes).unwrap();
    let r_bytes = (sapling::SpendAuth::basepoint() * nonce + torsion).to_bytes();
    let c = HStar::<sapling::SpendAuth>::default()
        .update(r_bytes)
        .update(bytes)
        .update(b"torsion")
        .finalize();
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&r_bytes);
    signature[32..].copy_from_slice(&(nonce + c * secret).to_bytes());
    let items = [
        SaplingItem::from_spendauth(bytes.into(), signature.into(), b"torsion"),
        SaplingItem::from_spendauth_key(key, signature.into(), b"torsion"),
    ];
    for item in &items {
        assert_eq!(item.clone().verify_single(), Ok(()));
    }
    assert_eq!(legacy_verify(&items), Ok(()));
    let mut verifier = Verifier::new();
    for item in items {
        verifier.queue(item);
    }
    assert_eq!(verifier.verify(ChaChaRng::from_seed([42; 32])), Ok(()));
}

// Original per-point decoding and arithmetic, without the batch decoder or MSM.
fn legacy_verify(items: &[SaplingItem]) -> Result<(), Error> {
    let mut rng = ChaChaRng::from_seed([42; 32]);
    let mut check = jubjub::ExtendedPoint::identity();
    for item in items {
        let (s_bytes, r_bytes, c, basepoint, bytes) = match &item.inner {
            Inner::SpendAuth { vk, sig, c } => (
                sig.s_bytes,
                sig.r_bytes,
                *c,
                sapling::SpendAuth::basepoint(),
                vk.bytes().bytes,
            ),
            Inner::Binding { vk, sig, c } => (
                sig.s_bytes,
                sig.r_bytes,
                *c,
                sapling::Binding::basepoint(),
                vk.bytes().bytes,
            ),
        };
        let s = Option::<jubjub::Scalar>::from(jubjub::Scalar::from_repr(s_bytes))
            .ok_or(Error::InvalidSignature)?;
        let r = Option::<jubjub::ExtendedPoint>::from(jubjub::ExtendedPoint::from_bytes(&r_bytes))
            .ok_or(Error::InvalidSignature)?;
        let vk = Option::<jubjub::ExtendedPoint>::from(jubjub::ExtendedPoint::from_bytes(&bytes))
            .ok_or(Error::MalformedVerificationKey)?;
        let z = if items.len() == 1 {
            jubjub::Scalar::ONE
        } else {
            jubjub::Scalar::from_raw(gen_128_bits(&mut rng))
        };
        check += r * z + vk * (z * c) - basepoint * (z * s);
    }
    if bool::from(check.is_small_order()) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

#[test]
fn mixed_retained_and_byte_keys_match_legacy_arithmetic() {
    let mut rng = ChaChaRng::from_seed([73; 32]);
    let msg = b"retained key differential";
    let mut items = Vec::new();
    for i in 0..16 {
        let spend = SigningKey::<sapling::SpendAuth>::new(&mut rng);
        let binding = SigningKey::<sapling::Binding>::new(&mut rng);
        let spend_key: VerificationKey<_> = (&spend).into();
        let binding_key: VerificationKey<_> = (&binding).into();
        let spend_sig = spend.sign(&mut rng, msg);
        let binding_sig = binding.sign(&mut rng, msg);
        items.push(if i % 2 == 0 {
            SaplingItem::from_spendauth_key(spend_key, spend_sig, msg)
        } else {
            SaplingItem::from_spendauth(spend_key.into(), spend_sig, msg)
        });
        items.push(if i % 2 == 0 {
            SaplingItem::from_binding(binding_key.into(), binding_sig, msg)
        } else {
            SaplingItem::from_binding_key(binding_key, binding_sig, msg)
        });
    }
    let compare = |items: &[SaplingItem]| {
        let mut verifier = Verifier::new();
        for item in items {
            verifier.queue(item.clone());
        }
        assert_eq!(
            verifier.verify(ChaChaRng::from_seed([42; 32])),
            legacy_verify(items)
        );
    };
    compare(&[]);
    for n in [1, 2, 8, 32] {
        compare(&items[..n]);
        for index in [0, n - 1] {
            // Exercise malformed R, noncanonical s, bad keys, and an
            // algebraically invalid signature at both ends of each batch.
            for mutation in 0..5 {
                let mut changed = items[..n].to_vec();
                match &mut changed[index].inner {
                    Inner::SpendAuth { vk, sig, c } => match mutation {
                        0 => sig.r_bytes.fill(0xff),
                        1 => sig.s_bytes.fill(0xff),
                        2 => *vk = BatchKey::Bytes([0xff; 32].into()),
                        3 => {
                            *vk = BatchKey::Bytes([0xff; 32].into());
                            sig.r_bytes.fill(0xff);
                        }
                        _ => *c += jubjub::Scalar::ONE,
                    },
                    Inner::Binding { vk, sig, c } => match mutation {
                        0 => sig.r_bytes.fill(0xff),
                        1 => sig.s_bytes.fill(0xff),
                        2 => *vk = BatchKey::Bytes([0xff; 32].into()),
                        3 => {
                            *vk = BatchKey::Bytes([0xff; 32].into());
                            sig.r_bytes.fill(0xff);
                        }
                        _ => *c += jubjub::Scalar::ONE,
                    },
                }
                compare(&changed);
            }
        }
    }
}
