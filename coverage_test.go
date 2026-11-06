// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import "testing"

// Common spellings from protocols, libraries and standards resolve to their family.
func TestCommonSpellingsResolve(t *testing.T) {
	for _, tt := range []struct {
		name, family string
		status       Status
	}{
		// Hybrid key exchange, as TLS and OpenSSH name it.
		{"X25519Kyber768", "X25519MLKEM768", Hybrid},
		{"SecP256r1Kyber768", "SecP256r1MLKEM768", Hybrid},
		{"mlkem768x25519-sha256", "X25519MLKEM768", Hybrid},
		{"sntrup761x25519-sha512", "Hybrid", Hybrid},
		{"Composite-ML-DSA", "Composite-ML-DSA", Hybrid},
		{"ML-DSA-65-ECDSA-P256", "Hybrid", Hybrid},
		// Post-quantum KEMs.
		{"HQC", "HQC", Safe},
		{"HQC-128", "HQC", Safe},
		{"BIKE", "BIKE", Safe},
		// JOSE algorithm names.
		{"RS256", "RSA", Vulnerable},
		{"PS512", "RSA", Vulnerable},
		{"ES384", "ECDSA", Vulnerable},
		{"ES256K", "secp256k1", Vulnerable},
		// RSA schemes as PKCS #1 names them.
		{"RSASSA-PKCS1-v1_5", "RSA", Vulnerable},
		{"RSAES-PKCS1-v1_5", "RSA", Vulnerable},
		{"RSA-PSS", "RSA", Vulnerable},
		// Curve names.
		{"secp256r1", "EC", Vulnerable},
		{"prime256v1", "EC", Vulnerable},
		{"secp384r1", "EC", Vulnerable},
		{"secp521r1", "EC", Vulnerable},
		{"brainpoolP256r1", "Brainpool", Vulnerable},
		{"brainpoolP384t1", "Brainpool", Vulnerable},
		// Other public-key spellings.
		{"ElGamal-2048", "ElGamal", Vulnerable},
		{"Dual_EC_DRBG", "Dual_EC_DRBG", Vulnerable},
		{"ECDHE", "ECDH", Vulnerable},
		{"DHE", "DH", Vulnerable},
		{"Ed25519ph", "EdDSA", Vulnerable},
		{"BN254", "Pairing", Vulnerable},
		{"BLS12-377", "Pairing", Vulnerable},
		{"SM2DSA", "SM2", Vulnerable},
		{"HSS", "LMS", Safe},
		// Symmetric spellings.
		{"HmacSHA1", "HMAC", NotApplicable},
		{"HmacMD5", "HMAC", NotApplicable},
		{"XChaCha20-Poly1305", "ChaCha20", NotApplicable},
		{"KMAC256", "KMAC", NotApplicable},
		{"GMAC", "GMAC", NotApplicable},
		{"SHAKE", "SHA-3", NotApplicable},
		{"CAST-256", "CAST6", NotApplicable},
		{"HC-128", "HC", NotApplicable},
	} {
		f, _, ok := Resolve(tt.name)
		if !ok || f.Name != tt.family || f.PQCStatus != tt.status {
			c, cok := Classify(map[string]string{"algorithmName": tt.name})
			if !cok || c.Name != tt.family || c.PQCStatus != tt.status {
				t.Errorf("%s = %s %s; want %s %s", tt.name, c.Name, c.PQCStatus, tt.family, tt.status)
			}
		}
	}
}
