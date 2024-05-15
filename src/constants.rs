// -*- mode: rust; -*-
//
// This file is part of reddsa.
// Copyright (c) 2019-2021 Zcash Foundation
// See LICENSE for licensing information.
//
// Authors:
// - Henry de Valence <hdevalence@hdevalence.ca>

/// The byte-encoding of the basepoint for `SpendAuthSig`.
// Extracted ad-hoc from the MASP trusted setup
// XXX add tests for this value.
pub const SPENDAUTHSIG_BASEPOINT_BYTES: [u8; 32] = [
    177, 180, 134, 161, 35, 38, 182, 20, 82, 253, 36, 246, 49, 208, 18, 32, 242, 158, 244, 241,
    207, 254, 222, 117, 171, 224, 82, 30, 159, 95, 188, 12,
];

/// The byte-encoding of the basepoint for `BindingSig`.
// Extracted ad-hoc from the MASP trusted setup
// XXX add tests for this value.
pub const BINDINGSIG_BASEPOINT_BYTES: [u8; 32] = [
    208, 146, 230, 156, 233, 252, 229, 40, 254, 2, 3, 54, 170, 45, 76, 249, 80, 17, 174, 184, 212,
    12, 144, 188, 11, 213, 32, 183, 249, 17, 95, 85,
];
