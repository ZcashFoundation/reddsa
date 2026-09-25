//! Internal functions exposed for use by other crates, e.g. the FROST
//! ciphersuite implementations for RedPallas and RedJubjub.
//!
//! This module is only available with the `internal` feature. It is not
//! covered by SemVer guarantees and may change at any time.

use crate::{private::Sealed, SigType};

pub use crate::hash::HStar;

/// Return the basepoint (generator) used for the given signature type.
pub fn basepoint<T: SigType>() -> <T as Sealed<T>>::Point {
    T::basepoint()
}
