use crate::scalar_mul::VartimeMultiscalarMul;
use alloc::vec::Vec;
use group::{ff::PrimeField, GroupEncoding};

use pasta_curves::arithmetic::CurveExt;
use pasta_curves::pallas;

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

// /// This function can be used to generate the data for [`test_pallas_vartime_multiscalar_mul`].
// #[test]
// fn gen_pallas_data() {
//     use group::{ff::Field, Group};
//     use rand::thread_rng;
//     use std::println;

//     let rng = thread_rng();

//     let scalars = [
//         pallas::Scalar::random(rng.clone()),
//         pallas::Scalar::random(rng.clone()),
//     ];
//     println!("Scalars:");
//     for scalar in scalars {
//         println!("{:?}", scalar.to_repr());
//     }

//     let points = [
//         pallas::Point::random(rng.clone()),
//         pallas::Point::random(rng),
//     ];
//     println!("Points:");
//     for point in points {
//         println!("{:?}", point.to_bytes());
//     }

//     let res = pallas::Point::vartime_multiscalar_mul(scalars, points);
//     println!("Result:");
//     println!("{:?}", res.to_bytes());
// }

// Test vectors generated with `gen_pallas_data`
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

    let expected_res: [u8; 32] = [
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

    let expected_res =
        pallas::Point::from_bytes(&expected_res).expect("Could not deserialize a `pallas::Point`.");

    let res = pallas::Point::vartime_multiscalar_mul(scalars, points);
    assert_eq!(expected_res, res);
}
