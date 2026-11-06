// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import "testing"

// PLONK can be pairing-based or hash-based, so the bare name does not say
// whether a quantum computer breaks it; the pairing-based spellings still do.
func TestZkSNARKCoversPairingBasedProofsOnly(t *testing.T) {
	if f, _, ok := Resolve("PLONK"); ok {
		t.Errorf("PLONK resolved to %s %s", f.Name, f.PQCStatus)
	}
	for _, name := range []string{"Groth16", "FFLONK", "KZG"} {
		if got := StatusOf(name); got != Vulnerable {
			t.Errorf("%s = %s, want vulnerable", name, got)
		}
	}
}

// NIST IR 8547 dates only the algorithms NIST approves; these are vulnerable
// but NIST never approved them, so they carry no NIST schedule and no CNSA one.
func TestNoNISTDatesForAlgorithmsNISTDoesNotApprove(t *testing.T) {
	for _, spelling := range []string{"secp256k1", "ECDSA-secp256k1", "BLS12-381 hash-to-curve", "Rabin"} {
		f, _, ok := Resolve(spelling)
		if !ok || f.PQCStatus != Vulnerable {
			t.Errorf("%s = %s %s, %v; want vulnerable", spelling, f.Name, f.PQCStatus, ok)
			continue
		}
		if len(f.Deadlines) != 0 {
			t.Errorf("%s (%s) carries dates: %v", spelling, f.Name, f.Deadlines)
		}
	}
}

// GOST names both a block cipher and an elliptic-curve signature; only the
// signature is quantum-vulnerable.
func TestGOSTSignatureIsNotTheCipher(t *testing.T) {
	for _, name := range []string{"GOST-R-34.10-2012", "GOST R 34.10-2001", "GOST3410-2012-256", "ECGOST3410", "ECGOST3410-2012"} {
		f, ok := Classify(map[string]string{"algorithmName": name})
		if !ok || f.Name != "GOST R 34.10" || f.PQCStatus != Vulnerable || len(f.Deadlines) != 0 {
			t.Errorf("%s = %s %s, %v; want GOST R 34.10 vulnerable without dates", name, f.Name, f.PQCStatus, ok)
		}
	}
	for _, name := range []string{"GOST", "GOST28147-89", "Magma"} {
		if f, ok := Classify(map[string]string{"algorithmName": name}); !ok || f.Name != "GOST" || f.PQCStatus != NotApplicable {
			t.Errorf("%s = %s %s, %v; want the GOST cipher", name, f.Name, f.PQCStatus, ok)
		}
	}
}

// Spellings whose status was right but whose family or parameter was not.
func TestSpellingsResolveToTheRightFamily(t *testing.T) {
	for _, tt := range []struct {
		spelling, family string
		parameter        int
	}{
		{"SHA", "SHA-1", 0}, // Java's "SHA" is SHA-1
		{"SHA-160", "SHA-1", 0},
		{"SHA-256", "SHA-2", 0},
		{"DES-EDE3", "3DES", 0},
		{"DH14", "DH", 0}, // IKE group numbers, not key sizes
		{"DH2048", "DH", 2048},
		{"DH3072", "DH", 3072},
		{"DH19", "ECDH", 0},
		{"DH31", "ECDH", 0},
		{"GOST3411-94", "GOST R 34.11-94", 0},
		{"GOST3411", "GOST R 34.11-94", 0},
		{"GOST3411-2012", "Streebog", 0},
	} {
		f, parameter, ok := Resolve(tt.spelling)
		if !ok || f.Name != tt.family || parameter != tt.parameter {
			t.Errorf("Resolve(%q) = %s, %d, %v; want %s, %d", tt.spelling, f.Name, parameter, ok, tt.family, tt.parameter)
		}
	}
	if f, ok := Classify(map[string]string{"algorithmName": "DES-EDE3-CBC"}); !ok || f.Name != "3DES" {
		t.Errorf("DES-EDE3-CBC = %s, %v; want 3DES", f.Name, ok)
	}
}
