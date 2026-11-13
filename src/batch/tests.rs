use super::*;
use crate::private::Sealed;
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng;

fn verify<S: SpendAuth, B: Binding<Scalar = S::Scalar, Point = S::Point>>(
    items: &[Item<S, B>],
) -> (Result<(), Error>, u128) {
    let mut verifier = Verifier::new();
    for item in items {
        verifier.queue(item.clone());
    }
    let mut rng = ChaChaRng::from_seed([42; 32]);
    let result = verifier.verify(&mut rng);
    (result, rng.get_word_pos())
}

fn retained_keys_match_bytes<S: SpendAuth, B: Binding<Scalar = S::Scalar, Point = S::Point>>() {
    let mut rng = ChaChaRng::from_seed([73; 32]);
    let msg = b"canonical challenge";
    let mut retained = Vec::new();
    let mut encoded = Vec::new();
    for _ in 0..8 {
        let spend = SigningKey::<S>::new(&mut rng);
        let binding = SigningKey::<B>::new(&mut rng);
        let spend_key: VerificationKey<_> = (&spend).into();
        let binding_key: VerificationKey<_> = (&binding).into();
        let spend_sig = spend.sign(&mut rng, msg);
        let binding_sig = binding.sign(&mut rng, msg);
        retained.push(Item::<S, B>::from_spendauth_key(spend_key, spend_sig, msg));
        retained.push(Item::<S, B>::from_binding_key(
            binding_key,
            binding_sig,
            msg,
        ));
        encoded.push(Item::<S, B>::from_spendauth(
            spend_key.into(),
            spend_sig,
            msg,
        ));
        encoded.push(Item::<S, B>::from_binding(
            binding_key.into(),
            binding_sig,
            msg,
        ));
    }
    for n in [0, 1, 2, 8, 16] {
        assert_eq!(verify(&retained[..n]), verify(&encoded[..n]));
        assert_eq!(verify(&retained[..n]).0, Ok(()));
        let mixed: Vec<_> = retained[..n]
            .iter()
            .zip(&encoded[..n])
            .enumerate()
            .map(|(i, (key, bytes))| {
                if i % 2 == 0 {
                    key.clone()
                } else {
                    bytes.clone()
                }
            })
            .collect();
        assert_eq!(verify(&mixed), verify(&encoded[..n]));
        for index in 0..n {
            assert_eq!(retained[index].clone().verify_single(), Ok(()));
            for mutation in 0..4 {
                let mutate = |item: &mut Item<S, B>| {
                    let (sig, c) = match &mut item.inner {
                        Inner::SpendAuth { sig, c, .. } => (&mut sig.s_bytes, c),
                        Inner::Binding { sig, c, .. } => (&mut sig.s_bytes, c),
                    };
                    match mutation {
                        0 => sig.fill(0xff),
                        1 => *c += S::Scalar::ONE,
                        _ => match &mut item.inner {
                            Inner::SpendAuth { sig, vk, .. } => {
                                sig.r_bytes.fill(0xff);
                                if mutation == 3 {
                                    *vk = BatchKey::Bytes([0xff; 32].into());
                                }
                            }
                            Inner::Binding { sig, vk, .. } => {
                                sig.r_bytes.fill(0xff);
                                if mutation == 3 {
                                    *vk = BatchKey::Bytes([0xff; 32].into());
                                }
                            }
                        },
                    }
                };
                let mut keys = retained[..n].to_vec();
                let mut bytes = encoded[..n].to_vec();
                mutate(&mut keys[index]);
                mutate(&mut bytes[index]);
                assert_eq!(verify(&keys), verify(&bytes));
                assert_eq!(
                    keys[index].clone().verify_single(),
                    bytes[index].clone().verify_single()
                );
                assert!(verify(&keys).0.is_err());
            }
        }
    }
}

#[test]
fn redjubjub_retained_keys_match_bytes() {
    retained_keys_match_bytes::<sapling::SpendAuth, sapling::Binding>();
}

#[test]
fn redpallas_retained_keys_match_bytes() {
    retained_keys_match_bytes::<orchard::SpendAuth, orchard::Binding>();
}

#[test]
fn native_points_preserve_canonical_encodings_and_small_order_points() {
    use group::Group;
    for point in [
        pasta_curves::pallas::Point::identity(),
        pasta_curves::pallas::Point::generator(),
        -pasta_curves::pallas::Point::generator(),
    ] {
        let key: VerificationKey<orchard::Binding> = point.into();
        assert_eq!(key, VerificationKey::try_from(point.to_bytes()).unwrap());
        let spend = VerificationKey::<orchard::SpendAuth>::try_from(point.to_bytes()).unwrap();
        assert_eq!(pasta_curves::pallas::Point::from(spend), point);
    }
    let torsion = jubjub::AffinePoint::from_bytes([0; 32])
        .unwrap()
        .to_extended();
    for point in [
        jubjub::ExtendedPoint::identity(),
        torsion,
        sapling::SpendAuth::basepoint() + torsion,
    ] {
        let key: VerificationKey<sapling::Binding> = point.into();
        assert_eq!(key, VerificationKey::try_from(point.to_bytes()).unwrap());
        let spend = VerificationKey::<sapling::SpendAuth>::try_from(point.to_bytes()).unwrap();
        assert_eq!(jubjub::AffinePoint::from(spend).to_extended(), point);
    }
}

#[test]
fn retained_keys_preserve_jubjub_torsion_in_verification() {
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
        Item::<sapling::SpendAuth, sapling::Binding>::from_spendauth(
            bytes.into(),
            signature.into(),
            b"torsion",
        ),
        Item::from_spendauth_key(key, signature.into(), b"torsion"),
    ];
    for item in &items {
        assert_eq!(item.clone().verify_single(), Ok(()));
    }
    assert_eq!(verify(&items).0, Ok(()));
}
