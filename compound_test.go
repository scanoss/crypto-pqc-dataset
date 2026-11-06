// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import (
	"strings"
	"testing"
	"time"
)

// A compound algorithm name is judged by its public-key part, and a classical
// part beside a post-quantum one makes a hybrid.
func TestClassifyCompoundNames(t *testing.T) {
	for _, tt := range []struct {
		name   string
		family string
		status Status
	}{
		// Signatures name the hash first.
		{"SHA256-RSA", "RSA", Vulnerable},
		{"SHA-256-RSA", "RSA", Vulnerable},
		{"SHA1-RSA", "RSA", Vulnerable},
		{"SHA256withRSA", "RSA", Vulnerable},
		{"SHA384withECDSA", "ECDSA", Vulnerable},
		{"SM3-SM2", "SM2", Vulnerable},
		{"RSA-PKCS1v15-SHA256", "RSA", Vulnerable},
		// Hybrids, in either order.
		{"X25519-Kyber768", "X25519MLKEM768", Hybrid},
		{"Kyber768-X25519", "Hybrid", Hybrid},
		{"sntrup761-x25519", "Hybrid", Hybrid},
		{"MLDSA65-Ed25519", "Hybrid", Hybrid},
		{"Ed25519-ML-DSA-65", "Hybrid", Hybrid},
		{"P256-ML-KEM-768", "Hybrid", Hybrid},
		// A curated hybrid keeps its own row.
		{"X25519-ML-KEM-768", "X25519MLKEM768", Hybrid},
		// Symmetric compounds stay not applicable.
		{"AES-256-GCM", "AES", NotApplicable},
		{"HMAC-SHA256", "HMAC", NotApplicable},
	} {
		f, ok := Classify(map[string]string{"algorithmName": tt.name})
		if !ok || f.Name != tt.family || f.PQCStatus != tt.status {
			t.Errorf("Classify(%q) = %s %s, %v; want %s %s", tt.name, f.Name, f.PQCStatus, ok, tt.family, tt.status)
		}
	}
	// The declared family still wins over the name.
	if f, _ := Classify(map[string]string{"algorithmFamily": "SHA-2", "algorithmName": "SHA256-RSA"}); f.Name != "SHA-2" {
		t.Errorf("algorithmFamily lost to algorithmName: %s", f.Name)
	}
}

// An unknown part beside parts that are only not-applicable could be the
// public-key algorithm, so the name stays unassessed rather than "not applicable".
func TestClassifyCompoundNamesNeverHideAnUnknownPart(t *testing.T) {
	for _, tt := range []struct {
		name   string
		family string
		status Status
	}{
		{"sha256WithRSAEncryption", "RSA", Vulnerable},
		{"SHA256WithRSAEncryption", "RSA", Vulnerable},
		{"DHKEM(P-256, HKDF-SHA256)", "EC", Vulnerable},
		{"AES-GCM-256", "AES", NotApplicable},
	} {
		f, ok := Classify(map[string]string{"algorithmName": tt.name})
		if !ok || f.Name != tt.family || f.PQCStatus != tt.status {
			t.Errorf("Classify(%q) = %s %s, %v; want %s %s", tt.name, f.Name, f.PQCStatus, ok, tt.family, tt.status)
		}
	}
	for _, name := range []string{
		"SHA256withRSAandMGF1",         // the hash is known, the signature spelling is not
		"SHA256withECDSAinP1363Format", // likewise
		"TLS_ECCPWD_WITH_AES_128_GCM_SHA256",
		"RIPEMD-128", // RIPEMD-160 takes no parameter, so 128 names another algorithm
		"SHA-0",
	} {
		if f, ok := Classify(map[string]string{"algorithmName": name}); ok {
			t.Errorf("Classify(%q) = %s %s; want unassessed", name, f.Name, f.PQCStatus)
		}
	}
}

// Classifying a very long name stays fast: the search never tries a run of
// parts longer than any curated spelling.
func TestClassifyLongNamesStayFast(t *testing.T) {
	name := strings.Repeat("x-", 20000)
	start := time.Now()
	Classify(map[string]string{"algorithmName": name})
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("a %d-part name took %s", 20000, elapsed)
	}
}
