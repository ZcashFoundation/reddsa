//! Signature types for the Orchard protocol.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
#[cfg(feature = "alloc")]
use core::borrow::Borrow;

use group::GroupEncoding;
#[cfg(feature = "alloc")]
use group::{ff::PrimeField, Group};
use pasta_curves::pallas;

use crate::{private, SigType};

#[cfg(feature = "alloc")]
use crate::scalar_mul::{LookupTable5, NonAdjacentForm, VartimeMultiscalarMul};

/// The byte-encoding of the basepoint for `OrchardSpendAuthSig`.
const ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES: [u8; 32] = [
    99, 201, 117, 184, 132, 114, 26, 141, 12, 161, 112, 123, 227, 12, 127, 12, 95, 68, 95, 62, 124,
    24, 141, 59, 6, 214, 241, 40, 179, 35, 85, 183,
];

/// The byte-encoding of the basepoint for `OrchardBindingSig`.
const ORCHARD_BINDINGSIG_BASEPOINT_BYTES: [u8; 32] = [
    145, 90, 60, 136, 104, 198, 195, 14, 47, 128, 144, 238, 69, 215, 110, 64, 72, 32, 141, 234, 91,
    35, 102, 79, 187, 9, 164, 15, 85, 68, 244, 7,
];

/// A type variable corresponding to Zcash's `OrchardSpendAuthSig`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SpendAuth {}
// This should not exist, but is necessary to use zeroize::DefaultIsZeroes.
impl Default for SpendAuth {
    fn default() -> Self {
        unimplemented!()
    }
}
impl SigType for SpendAuth {}
impl super::SpendAuth for SpendAuth {}

/// A type variable corresponding to Zcash's `OrchardBindingSig`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Binding {}
// This should not exist, but is necessary to use zeroize::DefaultIsZeroes.
impl Default for Binding {
    fn default() -> Self {
        unimplemented!()
    }
}
impl SigType for Binding {}
impl super::Binding for Binding {}

impl private::SealedScalar for pallas::Scalar {
    fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
        <pallas::Scalar as pasta_curves::arithmetic::FieldExt>::from_bytes_wide(bytes)
    }
    fn from_raw(val: [u64; 4]) -> Self {
        pallas::Scalar::from_raw(val)
    }
}
impl private::Sealed<SpendAuth> for SpendAuth {
    const H_STAR_PERSONALIZATION: &'static [u8; 16] = b"Zcash_RedPallasH";
    type Point = pallas::Point;
    type Scalar = pallas::Scalar;

    fn basepoint() -> pallas::Point {
        pallas::Point::from_bytes(&ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES).unwrap()
    }
}
impl private::Sealed<Binding> for Binding {
    const H_STAR_PERSONALIZATION: &'static [u8; 16] = b"Zcash_RedPallasH";
    type Point = pallas::Point;
    type Scalar = pallas::Scalar;

    fn basepoint() -> pallas::Point {
        pallas::Point::from_bytes(&ORCHARD_BINDINGSIG_BASEPOINT_BYTES).unwrap()
    }
}

#[cfg(feature = "alloc")]
impl NonAdjacentForm for pallas::Scalar {
    /// Compute a width-\\(w\\) "Non-Adjacent Form" of this scalar.
    ///
    /// Thanks to curve25519-dalek
    fn non_adjacent_form(&self, w: usize) -> [i8; 256] {
        // required by the NAF definition
        debug_assert!(w >= 2);
        // required so that the NAF digits fit in i8
        debug_assert!(w <= 8);

        use byteorder::{ByteOrder, LittleEndian};

        let mut naf = [0i8; 256];

        let mut x_u64 = [0u64; 5];
        LittleEndian::read_u64_into(&self.to_repr().as_ref(), &mut x_u64[0..4]);

        let width = 1 << w;
        let window_mask = width - 1;

        let mut pos = 0;
        let mut carry = 0;
        while pos < 256 {
            // Construct a buffer of bits of the scalar, starting at bit `pos`
            let u64_idx = pos / 64;
            let bit_idx = pos % 64;
            let bit_buf: u64;
            if bit_idx < 64 - w {
                // This window's bits are contained in a single u64
                bit_buf = x_u64[u64_idx] >> bit_idx;
            } else {
                // Combine the current u64's bits with the bits from the next u64
                bit_buf = (x_u64[u64_idx] >> bit_idx) | (x_u64[1 + u64_idx] << (64 - bit_idx));
            }

            // Add the carry into the current window
            let window = carry + (bit_buf & window_mask);

            if window & 1 == 0 {
                // If the window value is even, preserve the carry and continue.
                // Why is the carry preserved?
                // If carry == 0 and window & 1 == 0, then the next carry should be 0
                // If carry == 1 and window & 1 == 0, then bit_buf & 1 == 1 so the next carry should be 1
                pos += 1;
                continue;
            }

            if window < width / 2 {
                carry = 0;
                naf[pos] = window as i8;
            } else {
                carry = 1;
                naf[pos] = (window as i8).wrapping_sub(width as i8);
            }

            pos += w;
        }

        naf
    }
}

#[cfg(feature = "alloc")]
impl<'a> From<&'a pallas::Point> for LookupTable5<pallas::Point> {
    #[allow(non_snake_case)]
    fn from(A: &'a pallas::Point) -> Self {
        let mut Ai = [*A; 8];
        let A2 = A.double();
        for i in 0..7 {
            Ai[i + 1] = &A2 + Ai[i];
        }
        // Now Ai = [A, 3A, 5A, 7A, 9A, 11A, 13A, 15A]
        LookupTable5(Ai)
    }
}

#[cfg(feature = "alloc")]
impl VartimeMultiscalarMul for pallas::Point {
    type Scalar = pallas::Scalar;
    type Point = pallas::Point;

    #[allow(non_snake_case)]
    fn optional_multiscalar_mul<I, J>(scalars: I, points: J) -> Option<pallas::Point>
    where
        I: IntoIterator,
        I::Item: Borrow<Self::Scalar>,
        J: IntoIterator<Item = Option<pallas::Point>>,
    {
        let nafs: Vec<_> = scalars
            .into_iter()
            .map(|c| c.borrow().non_adjacent_form(5))
            .collect();

        let lookup_tables = points
            .into_iter()
            .map(|P_opt| P_opt.map(|P| LookupTable5::<pallas::Point>::from(&P)))
            .collect::<Option<Vec<_>>>()?;

        let mut r = pallas::Point::identity();

        for i in (0..256).rev() {
            let mut t = r.double();

            for (naf, lookup_table) in nafs.iter().zip(lookup_tables.iter()) {
                if naf[i] > 0 {
                    t = &t + &lookup_table.select(naf[i] as usize);
                } else if naf[i] < 0 {
                    t = &t - &lookup_table.select(-naf[i] as usize);
                }
            }

            r = t;
        }

        Some(r)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn orchard_spendauth_basepoint() {
        use super::ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES;
        use group::GroupEncoding;
        use pasta_curves::{arithmetic::CurveExt, pallas};

        assert_eq!(
            pallas::Point::hash_to_curve("z.cash:Orchard")(b"G").to_bytes(),
            ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES
        );
    }

    #[test]
    fn orchard_binding_basepoint() {
        use super::ORCHARD_BINDINGSIG_BASEPOINT_BYTES;
        use group::GroupEncoding;
        use pasta_curves::{arithmetic::CurveExt, pallas};

        assert_eq!(
            pallas::Point::hash_to_curve("z.cash:Orchard-cv")(b"r").to_bytes(),
            ORCHARD_BINDINGSIG_BASEPOINT_BYTES
        );
    }
}
