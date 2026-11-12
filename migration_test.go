// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import "testing"

const goJose = "pkg:golang/github.com/go-jose/go-jose/v4"

func testLibraries(t *testing.T) *Libraries {
	t.Helper()
	l, err := ParseLibraries([]byte(`
- library: go/go-jose-v4
  purls: [pkg:golang/github.com/go-jose/go-jose/v4]
  kem: { status: none }
  signature: { status: planned, note: "JOSE ML-DSA is an IETF draft", sources: ["https://example.org/draft"] }
  checked_at: 2026-11-10
- library: java/example-pqc
  purls: [pkg:maven/org.example/pqc]
  kem: { status: available, since: "2.0.0", apis: ["org.example.MLKEM.encapsulate"], sources: ["https://example.org/notes"] }
  signature: { status: available, since: "2.0.0", apis: ["org.example.MLDSA.sign"], sources: ["https://example.org/notes"] }
  checked_at: 2026-11-10
- library: java/example-legacy
  purls: [pkg:maven/org.example/legacy]
  kem: { status: none }
  signature: { status: none }
  checked_at: 2026-11-10
`))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// Reference examples, with the metadata a finding carries.
func TestMigrationPathExamples(t *testing.T) {
	libs := testLibraries(t)
	for _, tt := range []struct {
		name string
		in   Finding
		want Migration
	}{
		{
			"A: ECDH key agreement in the project",
			Finding{Status: Vulnerable, Family: "ECDH", Primitive: "key-agree", Source: "direct"},
			Migration{Path: Redesign, Reason: "key agreement → KEM (Encapsulate/Decapsulate)"},
		},
		{
			"B: Ed25519 signature in the project",
			Finding{Status: Vulnerable, Family: "EdDSA", Primitive: "signature", Operation: "sign", Source: "direct"},
			Migration{Path: Swap, Reason: "same sign/verify shape, different algorithm"},
		},
		{
			"C: Ed25519 inside go-jose",
			Finding{
				Status: Vulnerable, Family: "EdDSA", Primitive: "signature", Source: "indirect",
				DependencyModule: "github.com/go-jose/go-jose/v4", DependencyPurl: goJose + "@v4.1.7", DependencyVersion: "v4.1.7",
			},
			Migration{Path: Blocked, Reason: "no PQC in github.com/go-jose/go-jose/v4 (planned)", SizeRisk: SizeRiskJWT},
		},
		{
			"D: RSA key generation in the project",
			Finding{Status: Vulnerable, Family: "RSA", Primitive: "pke", Operation: "keygen", Source: "direct"},
			Migration{Path: Redesign, Reason: "operation unknown, inferred from RSA", Inferred: true},
		},
		{
			"RSA encryption in the project",
			Finding{Status: Vulnerable, Family: "RSA", Primitive: "pke", Operation: "encrypt", Source: "direct"},
			Migration{Path: Redesign, Reason: "key transport → KEM + AEAD"},
		},
		{
			"key material of a signature-only family",
			Finding{Status: Vulnerable, Family: "ECDSA", Primitive: "other", Source: "direct"},
			Migration{Path: Swap, Reason: "operation unknown, inferred from ECDSA", Inferred: true},
		},
		{
			"dependency with a PQC release",
			Finding{
				Status: Vulnerable, Family: "RSA", Primitive: "pke", Operation: "encrypt", Source: "dependency",
				DependencyModule: "org.example:pqc", DependencyPurl: "pkg:maven/org.example/pqc@1.0.0", DependencyVersion: "1.0.0",
			},
			Migration{Path: Upgrade, Reason: "upgrade org.example:pqc to >= 2.0.0"},
		},
		{
			"dependency already at the PQC release",
			Finding{
				Status: Vulnerable, Family: "RSA", Primitive: "signature", Operation: "sign", Source: "dependency",
				DependencyModule: "org.example:pqc", DependencyPurl: "pkg:maven/org.example/pqc@2.0.0", DependencyVersion: "2.0.0",
			},
			Migration{Path: Upgrade, Reason: "org.example:pqc 2.0.0 already supports ML-DSA: switch to it"},
		},
		{
			"dependency past the PQC release",
			Finding{
				Status: Vulnerable, Family: "ECDH", Primitive: "key-agree", Source: "indirect",
				DependencyModule: "org.example:pqc", DependencyPurl: "pkg:maven/org.example/pqc@v2.1.3", DependencyVersion: "v2.1.3",
			},
			Migration{Path: Upgrade, Reason: "org.example:pqc v2.1.3 already supports ML-KEM: switch to it"},
		},
		{
			"dependency on a pre-release of the PQC version",
			Finding{
				Status: Vulnerable, Family: "RSA", Primitive: "signature", Operation: "sign", Source: "dependency",
				DependencyModule: "org.example:pqc", DependencyPurl: "pkg:maven/org.example/pqc@2.0.0-rc1", DependencyVersion: "2.0.0-rc1",
			},
			Migration{Path: Upgrade, Reason: "upgrade org.example:pqc to >= 2.0.0"},
		},
		{
			"dependency without a version",
			Finding{
				Status: Vulnerable, Family: "ECDH", Primitive: "key-agree", Source: "dependency",
				DependencyModule: "org.example:pqc", DependencyPurl: "pkg:maven/org.example/pqc",
			},
			Migration{Path: Upgrade, Reason: "ensure org.example:pqc >= 2.0.0"},
		},
		{
			"dependency without a purl",
			Finding{Status: Vulnerable, Family: "EdDSA", Primitive: "signature", Source: "dependency", DependencyModule: "example.org/lib"},
			Migration{Path: Blocked, Reason: "no PQC in example.org/lib (no entry)"},
		},
		{
			"dependency with no entry",
			Finding{
				Status: Vulnerable, Family: "ECDSA", Primitive: "signature", Source: "indirect",
				DependencyPurl: "pkg:npm/unknown@1.0.0", DependencyVersion: "1.0.0",
			},
			Migration{Path: Blocked, Reason: "no PQC in unknown (no entry)"},
		},
		{
			"project code on a library with no PQC",
			Finding{Status: Vulnerable, Family: "ECDSA", Primitive: "signature", Source: "direct", LibraryPurl: "pkg:maven/org.example/legacy"},
			Migration{Path: Blocked, Reason: "no PQC in org.example/legacy; replace the library"},
		},
		{
			"project code calling a JWT library",
			Finding{Status: Vulnerable, Family: "RSA", Primitive: "signature", Source: "direct", LibraryPurl: goJose},
			Migration{Path: Swap, Reason: "same sign/verify shape, different algorithm", SizeRisk: SizeRiskJWT},
		},
	} {
		got, ok := MigrationPath(tt.in, libs)
		if !ok || got != tt.want {
			t.Errorf("%s:\n got  %+v (%v)\n want %+v", tt.name, got, ok, tt.want)
		}
	}
}

func TestMigrationPathOnlyForVulnerable(t *testing.T) {
	for _, s := range []Status{Safe, Hybrid, NotApplicable, Unassessed} {
		if m, ok := MigrationPath(Finding{Status: s, Family: "SHA-2", Primitive: "hash", Source: "direct"}, testLibraries(t)); ok {
			t.Errorf("%s finding got %+v", s, m)
		}
	}
}

// A finding inside a dependency is upgrade or blocked, whatever its primitive.
func TestDependencyFindingsNeverSwapOrRedesign(t *testing.T) {
	libs := testLibraries(t)
	for _, primitive := range []string{"signature", "key-agree", "pke", "other", ""} {
		for _, purl := range []string{goJose + "@v4.1.7", "pkg:maven/org.example/pqc@1.0.0", "pkg:npm/unknown@1.0.0", ""} {
			m, ok := MigrationPath(Finding{Status: Vulnerable, Family: "RSA", Primitive: primitive, Source: "indirect", DependencyPurl: purl}, libs)
			if !ok || (m.Path != Upgrade && m.Path != Blocked) {
				t.Errorf("%s in %s: %+v", primitive, purl, m)
			}
		}
	}
}

func TestComponentPath(t *testing.T) {
	worst, counts := ComponentPath([]Path{Swap, Redesign, Swap})
	if worst != Redesign || counts[Swap] != 2 || counts[Redesign] != 1 {
		t.Errorf("got %s %v", worst, counts)
	}
	if worst, _ := ComponentPath([]Path{Upgrade, Blocked, Swap}); worst != Blocked {
		t.Errorf("worst %s, want blocked", worst)
	}
	if _, counts := ComponentPath([]Path{"", Swap}); len(counts) != 1 {
		t.Errorf("an empty path was counted: %v", counts)
	}
	if worst, counts := ComponentPath(nil); worst != "" || len(counts) != 0 {
		t.Errorf("empty: %s %v", worst, counts)
	}
}

func TestJWTLibraries(t *testing.T) {
	r := mustReference()
	if len(r.JWTLibraries) != 34 {
		t.Errorf("%d JWT libraries, want 34", len(r.JWTLibraries))
	}
	for _, purl := range []string{"pkg:npm/jsonwebtoken", "pkg:cargo/jsonwebtoken", "pkg:golang/github.com/go-jose/go-jose/v4"} {
		if sizeRisk(r, Finding{LibraryPurl: purl}) != SizeRiskJWT {
			t.Errorf("%s is not a JWT library", purl)
		}
	}
}

func TestVersionAtLeast(t *testing.T) {
	for _, tt := range []struct {
		version, since string
		want           bool
	}{
		{"4.1.8", "4.1.8", true},
		{"v4.1.9", "4.1.8", true},
		{"4.2", "4.1.8", true},
		{"4.1.7", "4.1.8", false},
		{"v0.31.0", "0.38.0", false},
		{"1.79", "1.79", true},
		{"1.80", "1.79", true},
		{"0.10.79", "0.10.8", true},
		{"10", "9.9.9", true},
		{"4.1", "4.1.0", true},
		{"4.1.8-rc1", "4.1.8", false},
		{"v0.0.0-20240101-abcdef", "0.1.0", false},
		{"latest", "1.0.0", false},
		{"", "1.0.0", false},
		{"1.0.0", "", false},
		{"1..2", "1.0", false},
		{"+1.0", "1.0", false},
		{"v2.0.0+incompatible", "2.0.0", true},
		{"1.2.3+meta", "1.2.3", true},
		{"4.1.9-rc1", "4.1.8", true},
		{"4.1.8-rc1", "4.1.8", false},
		{" v4.1.9 ", "4.1.8", true},
		{"1.-0", "1.0", false},
		{"4.1.9.Final", "4.1.8", false},
		{"1.2.3.4", "1.2.3", false},
	} {
		if got := versionAtLeast(tt.version, tt.since); got != tt.want {
			t.Errorf("versionAtLeast(%q, %q) = %v, want %v", tt.version, tt.since, got, tt.want)
		}
	}
}

// Every available since in libraries.yaml is a dotted number, so the comparison
// can tell a dependency already at it.
func TestAvailableSinceIsComparable(t *testing.T) {
	for _, e := range DefaultLibraries().Entries() {
		for _, s := range []Support{e.KEM, e.Signature} {
			if s.Status == SupportAvailable && !versionAtLeast(s.Since, s.Since) {
				t.Errorf("%s: since %q is not a dotted number", e.Library, s.Since)
			}
		}
	}
}

// A dependency purl with a lowercased Go namespace gets the library's path and
// its JWT size risk.
func TestMigrationPathProducerSpelledPurl(t *testing.T) {
	libs := DefaultLibraries()
	m, _ := MigrationPath(Finding{
		Status: Vulnerable, Family: "ECDH", Primitive: "key-agree", Source: "indirect",
		DependencyModule: "github.com/ProtonMail/go-crypto", DependencyPurl: "pkg:golang/github.com/protonmail/go-crypto@v1.8.0", DependencyVersion: "v1.8.0",
	}, libs)
	if m.Path != Upgrade || m.Reason != "github.com/ProtonMail/go-crypto v1.8.0 already supports ML-KEM: switch to it" {
		t.Errorf("protonmail/go-crypto: %+v", m)
	}
	m, _ = MigrationPath(Finding{
		Status: Vulnerable, Family: "ECDSA", Primitive: "signature", Operation: "sign", Source: "indirect",
		DependencyPurl: "pkg:golang/github.com/Go-Jose/go-jose/v4@v4.1.4", DependencyVersion: "v4.1.4",
	}, libs)
	if m.SizeRisk != SizeRiskJWT {
		t.Errorf("go-jose in another case lost its size risk: %+v", m)
	}
}
