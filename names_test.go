// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import "testing"

// PQC-relevant names that producers emit only as algorithmName.
func TestPQCRelevantNamesResolve(t *testing.T) {
	for name, want := range map[string]Status{
		"RSA/ECDSA": Vulnerable, "Edwards25519": Vulnerable, "P-256": Vulnerable, "MuSig2-BIP327-secp256k1": Vulnerable,
		"BLS12-381 pairing": Vulnerable, "Groth16": Vulnerable, "Paillier": Vulnerable,
		"FrodoKEM": Safe, "SNTRUP761": Safe, "McEliece": Safe,
		"X-Wing": Hybrid, "ML-KEM-768-P256": Hybrid, "KitchenSink-ML-KEM-768-X25519": Hybrid,
	} {
		if got := StatusOf(name); got != want {
			t.Errorf("StatusOf(%q) = %s, want %s", name, got, want)
		}
	}
}
