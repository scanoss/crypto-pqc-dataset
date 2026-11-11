// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import "testing"

// The migration path falls back to the family kind, so every vulnerable family needs one.
func TestEveryVulnerableFamilyHasAKind(t *testing.T) {
	for _, f := range Families() {
		switch {
		case f.PQCStatus == Vulnerable && f.Kind == "":
			t.Errorf("%s is vulnerable and has no kind", f.Name)
		case f.PQCStatus != Vulnerable && f.Kind != "":
			t.Errorf("%s is %s and has kind %q", f.Name, f.PQCStatus, f.Kind)
		}
	}
}

func TestFamilyKinds(t *testing.T) {
	for name, want := range map[string]Kind{"EdDSA": KindSignature, "ECDH": KindKeyAgreement, "RSA": KindDual} {
		if f, _, ok := Resolve(name); !ok || f.Kind != want {
			t.Errorf("%s: kind %q, want %q", name, f.Kind, want)
		}
	}
}

func TestReferenceLoads(t *testing.T) {
	r, err := loadReference()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Paths) != 3 || len(r.Sizes) == 0 || len(r.JWTLibraries) == 0 {
		t.Fatalf("paths %d, sizes %d, JWT libraries %d", len(r.Paths), len(r.Sizes), len(r.JWTLibraries))
	}
}

func TestReferenceRejectsUncitedRows(t *testing.T) {
	for _, data := range []string{
		"paths: [{primitive: signature, path: swap, reason: r}]",
		"sizes: [{algorithm: X25519, item: public key, bytes: 32}]",
		"jwt_libraries: [{library: go/go-jose-v4}]",
		"paths: [{primitive: signature, path: rewrite, reason: r, citation: c}]",
	} {
		if _, err := parseReference([]byte(data)); err == nil {
			t.Errorf("accepted %q", data)
		}
	}
}

func TestSizes(t *testing.T) {
	for _, s := range Sizes() {
		if s.Algorithm == "ML-DSA-65" && s.Item == "signature" && s.Bytes != 3309 {
			t.Errorf("ML-DSA-65 signature: %d bytes", s.Bytes)
		}
	}
}
