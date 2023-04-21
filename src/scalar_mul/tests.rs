use alloc::vec::Vec;
use group::GroupEncoding;
use jubjub::{ExtendedPoint, Scalar};

use crate::scalar_mul::VartimeMultiscalarMul;

// /// This function can be used to generate the data for [`test_jubjub_vartime_multiscalar_mul`].
// #[test]
// fn gen_jubjub_data() {
//     use group::{ff::Field, Group};
//     use rand::thread_rng;
//     use std::println;

//     let rng = thread_rng();

//     let scalars = [Scalar::random(rng.clone()), Scalar::random(rng.clone())];
//     println!("Scalars:");
//     for scalar in scalars {
//         println!("{:?}", scalar.to_bytes());
//     }

//     let points = [
//         ExtendedPoint::random(rng.clone()),
//         ExtendedPoint::random(rng),
//     ];
//     println!("Points:");
//     for point in points {
//         println!("{:?}", point.to_bytes());
//     }

//     let res = ExtendedPoint::vartime_multiscalar_mul(scalars, points);
//     println!("Result:");
//     println!("{:?}", res.to_bytes());
// }

// Test vectors generated with `gen_jubjub_data`
#[test]
fn test_jubjub_vartime_multiscalar_mul() {
    let scalars: [[u8; 32]; 2] = [
        [
            147, 209, 135, 83, 133, 175, 29, 28, 22, 161, 0, 220, 100, 218, 103, 47, 134, 242, 49,
            19, 254, 204, 107, 185, 189, 155, 33, 110, 100, 141, 59, 0,
        ],
        [
            138, 136, 196, 249, 144, 2, 9, 103, 233, 93, 253, 46, 181, 12, 41, 158, 62, 201, 35,
            198, 108, 139, 136, 78, 210, 12, 1, 223, 231, 22, 92, 13,
        ],
    ];

    let points: [[u8; 32]; 2] = [
        [
            93, 252, 67, 45, 63, 170, 103, 247, 53, 37, 164, 250, 32, 210, 38, 71, 162, 68, 205,
            176, 116, 46, 209, 66, 131, 209, 107, 193, 210, 153, 222, 31,
        ],
        [
            139, 112, 204, 231, 187, 141, 159, 122, 210, 164, 7, 162, 185, 171, 47, 199, 5, 33, 80,
            207, 129, 24, 165, 90, 204, 253, 38, 27, 55, 86, 225, 52,
        ],
    ];

    let expected_res: [u8; 32] = [
        64, 228, 212, 168, 76, 90, 248, 218, 86, 22, 182, 130, 227, 52, 170, 88, 220, 193, 166,
        131, 180, 48, 148, 72, 212, 148, 212, 240, 77, 244, 91, 213,
    ];

    let scalars: Vec<Scalar> = scalars
        .into_iter()
        .map(|s| Scalar::from_bytes(&s).expect("Could not deserialize a `jubjub::Scalar`."))
        .collect();

    let points: Vec<ExtendedPoint> = points
        .into_iter()
        .map(|p| {
            ExtendedPoint::from_bytes(&p).expect("Could not deserialize a `jubjub::ExtendedPoint`.")
        })
        .collect();

    let expected_res = ExtendedPoint::from_bytes(&expected_res)
        .expect("Could not deserialize a `jubjub::ExtendedPoint`.");

    let res = ExtendedPoint::vartime_multiscalar_mul(scalars, points);
    assert_eq!(expected_res, res);
}
