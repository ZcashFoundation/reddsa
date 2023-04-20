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
