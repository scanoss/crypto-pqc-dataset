// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import (
	"os"
	"strings"
	"testing"
)

// Statuses that depend on how the family is instantiated, not on the family.
var intentionallyUnassessed = map[string]string{
	"HPKE": "status depends on the KEM it is instantiated with",
}

// A producer that follows CycloneDX 1.7 emits only these families, so every
// family it can emit is classified.
func TestEveryCycloneDXFamilyResolves(t *testing.T) {
	b, err := os.ReadFile("testdata/cyclonedx-1.7-algorithm-families.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range strings.Fields(string(b)) {
		if _, skip := intentionallyUnassessed[family]; skip {
			continue
		}
		if _, _, ok := Resolve(family); !ok {
			t.Errorf("CycloneDX family %q has no dataset row", family)
		}
	}
}

// Common spellings resolve to their family; a near miss does not.
func TestResolveCommonSpellings(t *testing.T) {
	for spelling, want := range map[string]string{
		"rsa-2048": "RSA", "RSASSA-PSS": "RSA", "RSAES-OAEP": "RSA", "Kyber": "ML-KEM",
		"DES3": "3DES", "X25519": "ECDH", "FFDH": "DH",
	} {
		if f, _, ok := Resolve(spelling); !ok || f.Name != want {
			t.Errorf("Resolve(%q) = %s, %v; want %s", spelling, f.Name, ok, want)
		}
	}
	if f, _, ok := Resolve("RIPEMD-128"); ok {
		t.Errorf("RIPEMD-128 resolved to %s", f.Name)
	}
}
