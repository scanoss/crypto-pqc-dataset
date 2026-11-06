// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import "testing"

// A trailing number is a parameter only when what precedes it is a family that
// takes one; digits that belong to the name stay in the name.
func TestResolveSplitsTheParameter(t *testing.T) {
	for _, tt := range []struct {
		spelling  string
		family    string
		parameter int
	}{
		{"AES256", "AES", 256},
		{"RSA-2048", "RSA", 2048},
		{"ML-KEM-768", "ML-KEM", 768},
		{"SM4-128", "SM4", 128},
		{"BLAKE2-256", "BLAKE2", 256},
		{"CAST5-128", "CAST5", 128},
		{"3DES-168", "3DES", 168},
		{"SHA-2-256", "SHA-2", 256},
		{"MD5", "MD5", 0},
		{"3DES", "3DES", 0},
	} {
		f, parameter, ok := Resolve(tt.spelling)
		if !ok || f.Name != tt.family || parameter != tt.parameter {
			t.Errorf("Resolve(%q) = %s, %d, %v; want %s, %d", tt.spelling, f.Name, parameter, ok, tt.family, tt.parameter)
		}
	}
	// RIPEMD-160 takes no parameter, so RIPEMD-128 is a different algorithm.
	if f, _, ok := Resolve("RIPEMD-128"); ok {
		t.Errorf("RIPEMD-128 resolved to %s", f.Name)
	}
}
