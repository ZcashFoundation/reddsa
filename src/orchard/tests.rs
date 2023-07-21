use std::println;

use crate::scalar_mul::{self, VartimeMultiscalarMul};
use crate::{orchard, Signature, SigningKey, VerificationKey, VerificationKeyBytes};
use alloc::vec::Vec;
use group::ff::Field;
use group::{ff::PrimeField, GroupEncoding};
use rand::thread_rng;

use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;

#[test]
fn orchard_sign() {
    let msg =
        hex::decode("8ca86a5e2f89da4dd6b8f26f740f360667ec1526cdb0ac7719ddd1c4a1e62981").unwrap();

    // Generate a secret key and sign the message
    let sk_bytes: [u8; 32] =
        hex::decode("6a0df875bb9747883d518dd12223c986bb8166468263f0ab27f235c90d07db30")
            .unwrap()
            .try_into()
            .unwrap();
    let sk = SigningKey::<orchard::SpendAuth>::try_from(sk_bytes).unwrap();
    let ak: VerificationKey<_> = (&sk).into();
    let ak: VerificationKeyBytes<_> = ak.into();
    let ak: [u8; 32] = ak.into();
    println!("ak: {}", hex::encode(ak));

    let randomizer_bytes: [u8; 32] =
        hex::decode("10e10752b172b0bfbce1fcc577da34023b67749aa37c50845a35fdc04dc4d51f")
            .unwrap()
            .try_into()
            .unwrap();
    let randomizer = pasta_curves::pallas::Scalar::from_repr(randomizer_bytes).unwrap();

    let sk = sk.randomize(&randomizer);

    let sig = sk.sign(thread_rng(), &msg);

    // Types can be converted to raw byte arrays using From/Into
    let sig_bytes: [u8; 64] = sig.into();
    println!("Signature: {}", hex::encode(sig_bytes));
    let pk: VerificationKey<orchard::SpendAuth> = (&sk).into();
    let pk_bytes: [u8; 32] = pk.into();

    // Deserialize and verify the signature.
    let sig: Signature<orchard::SpendAuth> = sig_bytes.into();
    assert!(VerificationKey::try_from(pk_bytes)
        .and_then(|pk| pk.verify(&msg, &sig))
        .is_ok());
}

#[test]
fn orchard_spendauth_basepoint() {
    use super::ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES;
    assert_eq!(
        pallas::Point::hash_to_curve("z.cash:Orchard")(b"G").to_bytes(),
        ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES
    );
}

#[test]
fn orchard_binding_basepoint() {
    use super::ORCHARD_BINDINGSIG_BASEPOINT_BYTES;
    assert_eq!(
        pallas::Point::hash_to_curve("z.cash:Orchard-cv")(b"r").to_bytes(),
        ORCHARD_BINDINGSIG_BASEPOINT_BYTES
    );
}

/// Generates test vectors for [`test_pallas_vartime_multiscalar_mul`].
// #[test]
#[allow(dead_code)]
fn gen_pallas_test_vectors() {
    use group::Group;

    let rng = thread_rng();

    let scalars = [
        pallas::Scalar::random(rng.clone()),
        pallas::Scalar::random(rng.clone()),
    ];
    println!("Scalars:");
    for scalar in scalars {
        println!("{:?}", scalar.to_repr());
    }

    let points = [
        pallas::Point::random(rng.clone()),
        pallas::Point::random(rng),
    ];
    println!("Points:");
    for point in points {
        println!("{:?}", point.to_bytes());
    }

    let res = pallas::Point::vartime_multiscalar_mul(scalars, points);
    println!("Result:");
    println!("{:?}", res.to_bytes());
}

/// Checks if the vartime multiscalar multiplication on Pallas produces the expected product.
/// The test vectors were generated by [`gen_pallas_test_vectors`].
#[test]
fn test_pallas_vartime_multiscalar_mul() {
    let scalars: [[u8; 32]; 2] = [
        [
            235, 211, 155, 231, 188, 225, 161, 143, 148, 66, 177, 18, 246, 175, 177, 55, 1, 185,
            115, 175, 208, 12, 252, 5, 168, 198, 26, 166, 129, 252, 158, 8,
        ],
        [
            1, 8, 55, 59, 168, 56, 248, 199, 77, 230, 228, 96, 35, 65, 191, 56, 137, 226, 161, 184,
            105, 223, 98, 166, 248, 160, 156, 74, 18, 228, 122, 44,
        ],
    ];

    let points: [[u8; 32]; 2] = [
        [
            81, 113, 73, 111, 90, 141, 91, 248, 252, 201, 109, 74, 99, 75, 11, 228, 152, 144, 254,
            104, 240, 69, 211, 23, 201, 128, 236, 187, 233, 89, 59, 133,
        ],
        [
            177, 3, 100, 162, 246, 15, 81, 236, 51, 73, 69, 43, 45, 202, 226, 99, 27, 58, 133, 52,
            231, 244, 125, 221, 88, 155, 192, 4, 164, 102, 34, 143,
        ],
    ];

    let expected_product: [u8; 32] = [
        68, 54, 98, 93, 238, 28, 229, 186, 127, 154, 101, 209, 216, 214, 66, 45, 141, 210, 70, 119,
        100, 245, 164, 155, 213, 45, 126, 17, 199, 8, 84, 143,
    ];

    let scalars: Vec<pallas::Scalar> = scalars
        .into_iter()
        .map(|s| {
            pallas::Scalar::from_repr_vartime(s).expect("Could not deserialize a `pallas::Scalar`.")
        })
        .collect();

    let points: Vec<pallas::Point> = points
        .into_iter()
        .map(|p| pallas::Point::from_bytes(&p).expect("Could not deserialize a `pallas::Point`."))
        .collect();

    let expected_product = pallas::Point::from_bytes(&expected_product)
        .expect("Could not deserialize a `pallas::Point`.");

    let product = pallas::Point::vartime_multiscalar_mul(scalars, points);
    assert_eq!(expected_product, product);
}

/// Tests the non-adjacent form for a Pallas scalar.
#[test]
fn test_non_adjacent_form() {
    let rng = thread_rng();

    let scalar = pallas::Scalar::random(rng);
    scalar_mul::tests::test_non_adjacent_form_for_scalar(5, scalar);
}
