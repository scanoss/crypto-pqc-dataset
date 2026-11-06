// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

// Package pqcdataset classifies cryptographic algorithm families by post-quantum
// status, with the cited deadlines that apply. It reads only the algorithm
// names and families a finding carries, never source code.
//
// The data is embedded and loaded on first use. Every function is safe for
// concurrent use, and every function panics if the embedded data is invalid,
// which the package's own tests rule out before a release.
package pqcdataset
