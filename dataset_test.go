// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import (
	"os"
	"regexp"
	"testing"
)

// The CNSA 2.0 deadline covers exactly these quantum-vulnerable families.
func TestCNSADeadline(t *testing.T) {
	listed := map[string]bool{
		"RSA": true, "DSA": true, "DH": true, "ECDSA": true, "ECDH": true,
		"EC": true, "EdDSA": true, "ElGamal": true, "SM2": true,
	}
	for _, f := range Families() {
		d, ok := f.Deadline(SourceCNSA2)
		if ok != listed[f.Name] {
			t.Errorf("%s: has CNSA 2.0 deadline = %v, want %v", f.Name, ok, listed[f.Name])
		}
		if ok && (d.MigrateBy != 2030 || d.DeprecatedAfter != 0 || d.DisallowedAfter != 0) {
			t.Errorf("%s: CNSA 2.0 deadline %+v, want migrate by 2030 only", f.Name, d)
		}
	}
}

// NIST IR 8547 Tables 2 and 4 list exactly these quantum-vulnerable families.
func TestNISTDeadline(t *testing.T) {
	listed := map[string]bool{"RSA": true, "ECDSA": true, "EdDSA": true, "EC": true, "DH": true, "ECDH": true, "MQV": true}
	for _, f := range Families() {
		d, ok := f.Deadline(SourceNISTIR8547)
		if ok != listed[f.Name] {
			t.Errorf("%s: has NIST IR 8547 deadline = %v, want %v", f.Name, ok, listed[f.Name])
		}
		if ok && (d.DeprecatedAfter != 2030 || d.DisallowedAfter != 2035) {
			t.Errorf("%s: NIST IR 8547 deadline %d/%d, want 2030/2035", f.Name, d.DeprecatedAfter, d.DisallowedAfter)
		}
	}
}

// The worst case is the earliest year any source sets.
func TestEarliestDeadline(t *testing.T) {
	for name, want := range map[string]int{"RSA": 2030, "MQV": 2030, "SM2": 2030} {
		f, _, _ := Resolve(name)
		if got, ok := f.EarliestDeadline(); !ok || got != want {
			t.Errorf("%s: earliest deadline %d, %v; want %d", name, got, ok, want)
		}
	}
	if f, _, _ := Resolve("BLS"); len(f.Deadlines) != 0 {
		t.Errorf("BLS has deadlines: %v", f.Deadlines)
	} else if _, ok := f.EarliestDeadline(); ok {
		t.Error("BLS reports an earliest deadline")
	}
}

// A certificate names its signature algorithm in its own keys, often as a
// compound name.
func TestClassifyReadsCertificateAlgorithms(t *testing.T) {
	for _, metadata := range []map[string]string{
		{"assetType": "certificate", "certificateAlgorithm": "sha256WithRSAEncryption"},
		{"assetType": "certificate", "signatureAlgorithm": "SHA384withECDSA"},
	} {
		if !NamesAlgorithm(metadata) {
			t.Errorf("%v names no algorithm", metadata)
		}
		if f, ok := Classify(metadata); !ok || f.PQCStatus != Vulnerable {
			t.Errorf("Classify(%v) = %s %s, %v; want vulnerable", metadata, f.Name, f.PQCStatus, ok)
		}
	}
	// The algorithm's own keys still come first.
	f, _ := Classify(map[string]string{"algorithmName": "ML-DSA-65", "certificateAlgorithm": "sha256WithRSAEncryption"})
	if f.Name != "ML-DSA" {
		t.Errorf("certificateAlgorithm won over algorithmName: %s", f.Name)
	}
}

// The newest released changelog entry, once there is one, must name the embedded dataset version.
func TestChangelogMatchesVersion(t *testing.T) {
	b, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	m := releasedHeading.FindSubmatch(b)
	if m == nil {
		return // nothing released yet; the release workflow checks the tag
	}
	if got := string(m[1]); got != Version() {
		t.Errorf("latest changelog entry %q, dataset version %q", got, Version())
	}
}

// releasedHeading is a Keep a Changelog release heading: "## [1.2.3] - 2026-01-31".
var releasedHeading = regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$`)

func TestClassify(t *testing.T) {
	for _, tt := range []struct {
		meta map[string]string
		want Status
	}{
		{map[string]string{"algorithmFamily": "RSAES-OAEP"}, Vulnerable},
		{map[string]string{"algorithmFamily": "ECDH"}, Vulnerable},
		{map[string]string{"materialAlgorithm": "RSA"}, Vulnerable},
		{map[string]string{"algorithmName": "RSA-PKCS1v15-SHA256"}, Vulnerable},
		{map[string]string{"algorithmFamily": "ML-KEM"}, Safe},
		{map[string]string{"algorithmFamily": "SHA-2"}, NotApplicable},
	} {
		f, ok := Classify(tt.meta)
		if !ok || f.PQCStatus != tt.want {
			t.Errorf("Classify(%v) = %s, %v; want %s", tt.meta, f.PQCStatus, ok, tt.want)
		}
	}
	if _, ok := Classify(map[string]string{"algorithmFamily": "HPKE"}); ok {
		t.Error("HPKE should stay unassessed")
	}
}
