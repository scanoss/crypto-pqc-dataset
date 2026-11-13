// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestMigrationPriority(t *testing.T) {
	for _, tt := range []struct {
		name string
		f    Finding
		r    Reachability
		want PriorityRule
	}{
		{"reachable key agreement", Finding{Family: "ECDH", Primitive: "key-agree"}, ReachabilityReachable, PriorityRuleReachableKeyExchange},
		{"reachable KEM", Finding{Family: "RSA", Primitive: "kem"}, ReachabilityReachable, PriorityRuleReachableKeyExchange},
		{"reachable encryption", Finding{Family: "RSA", Primitive: "pke", Operation: "encrypt"}, ReachabilityReachable, PriorityRuleReachableKeyExchange},
		{"reachable decryption", Finding{Family: "RSA", Primitive: "pke", Operation: "decrypt"}, ReachabilityReachable, PriorityRuleReachableKeyExchange},
		{"reachable encapsulation", Finding{Family: "RSA", Operation: "encapsulate"}, ReachabilityReachable, PriorityRuleReachableKeyExchange},
		{"reachable decapsulation", Finding{Family: "RSA", Operation: "decapsulate"}, ReachabilityReachable, PriorityRuleReachableKeyExchange},
		{"a signature primitive wins over key derivation", Finding{Family: "EdDSA", Primitive: "signature", Operation: "keyderive"}, ReachabilityReachable, PriorityRuleReachableSignature},
		{"a signature primitive wins over encryption", Finding{Family: "RSA", Primitive: "signature", Operation: "encrypt"}, ReachabilityReachable, PriorityRuleReachableSignature},
		{"key derivation of a key-agreement primitive", Finding{Family: "ECDH", Primitive: "key-agree", Operation: "keyderive"}, ReachabilityReachable, PriorityRuleReachableKeyExchange},
		{"key derivation alone falls back to the family kind", Finding{Family: "ECDSA", Primitive: "other", Operation: "keyderive"}, ReachabilityReachable, PriorityRuleReachableSignature},
		{"reachable signature", Finding{Family: "EdDSA", Primitive: "signature", Operation: "sign"}, ReachabilityReachable, PriorityRuleReachableSignature},
		{"reachable signature primitive without an operation", Finding{Family: "ECDSA", Primitive: "signature"}, ReachabilityReachable, PriorityRuleReachableSignature},
		{"a signing operation wins over a pke primitive", Finding{Family: "RSA", Primitive: "pke", Operation: "sign"}, ReachabilityReachable, PriorityRuleReachableSignature},
		{"a verify operation wins over a pke primitive", Finding{Family: "RSA", Primitive: "pke", Operation: "verify"}, ReachabilityReachable, PriorityRuleReachableSignature},
		{"a signing operation on key material", Finding{Family: "RSA", Primitive: "key-material", Operation: "sign"}, ReachabilityReachable, PriorityRuleReachableSignature},
		{"key material of a signature family", Finding{Family: "ECDSA", Primitive: "key-material"}, ReachabilityReachable, PriorityRuleReachableSignature},
		{"key material of a key-agreement family", Finding{Family: "ECDH", Primitive: "key-material"}, ReachabilityReachable, PriorityRuleReachableKeyExchange},
		{"pke key generation of a dual family is an unknown use", Finding{Family: "RSA", Primitive: "pke", Operation: "keygen"}, ReachabilityReachable, PriorityRuleReachableUseUnknown},
		{"no primitive on an unknown family is an unknown use", Finding{Family: "NotAFamily"}, ReachabilityReachable, PriorityRuleReachableUseUnknown},
		{"unreachable signature", Finding{Family: "EdDSA", Primitive: "signature"}, ReachabilityUnreachable, PriorityRuleUnreachable},
		{"unreachable key agreement", Finding{Family: "ECDH", Primitive: "key-agree"}, ReachabilityUnreachable, PriorityRuleUnreachable},
		{"unknown reachability", Finding{Family: "ECDH", Primitive: "key-agree"}, ReachabilityUnknown, PriorityRuleReachabilityUnknown},
		{"empty reachability reads as unknown", Finding{Family: "ECDH", Primitive: "key-agree"}, "", PriorityRuleReachabilityUnknown},
		{"misspelled reachability reads as unknown", Finding{Family: "ECDH", Primitive: "key-agree"}, "Reachable", PriorityRuleReachabilityUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.f.Status = Vulnerable
			got, ok := MigrationPriority(tt.f, Migration{Path: Redesign}, tt.r)
			if !ok {
				t.Fatal("MigrationPriority() ok = false, want true")
			}
			want := priorityRules[tt.want]
			if got.Rule != tt.want || got.Level != want.level || got.Reason != want.reason {
				t.Errorf("got %s %s %q, want %s %s %q", got.Level, got.Rule, got.Reason, want.level, tt.want, want.reason)
			}
			if got.Path != Redesign {
				t.Errorf("path %q, want the migration's path", got.Path)
			}
		})
	}
}

func TestMigrationPriorityOnlyForVulnerable(t *testing.T) {
	for _, s := range []Status{Safe, Hybrid, NotApplicable, Unassessed, ""} {
		if p, ok := MigrationPriority(Finding{Status: s, Family: "RSA"}, Migration{Path: Redesign}, ReachabilityReachable); ok || p != (Priority{}) {
			t.Errorf("status %q: got %+v, %v; want no priority", s, p, ok)
		}
	}
}

// The family-kind cases above rely on these kinds.
func TestMigrationPriorityFamilyKinds(t *testing.T) {
	for name, want := range map[string]Kind{"RSA": KindDual, "ECDSA": KindSignature, "EdDSA": KindSignature, "ECDH": KindKeyAgreement} {
		if f, _, ok := Resolve(name); !ok || f.Kind != want {
			t.Errorf("%s kind = %q, want %q", name, f.Kind, want)
		}
	}
}

func TestPriorityJSON(t *testing.T) {
	got, err := json.Marshal(Priority{Level: PriorityLevelP3, Rule: PriorityRuleUnreachable, Reason: "x", Path: Swap})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"level":"P3","rule":"unreachable","reason":"x","path":"swap"}`; string(got) != want {
		t.Errorf("JSON = %s, want %s (no deadline_year when there is none)", got, want)
	}
}

func TestPriorityRulesCoverEveryLevel(t *testing.T) {
	levels := map[PriorityLevel]bool{}
	for rule, r := range priorityRules {
		if r.reason == "" || levelRank[r.level] == 0 {
			t.Errorf("rule %s: level %q, reason %q", rule, r.level, r.reason)
		}
		levels[r.level] = true
	}
	for level := range levelRank {
		if !levels[level] {
			t.Errorf("no rule sets %s", level)
		}
	}
}

func TestMigrationPriorityDeadlineIsTheFamilysEarliest(t *testing.T) {
	for _, family := range Families() {
		if family.PQCStatus != Vulnerable {
			continue
		}
		want, _ := family.EarliestDeadline()
		got, _ := MigrationPriority(Finding{Status: Vulnerable, Family: family.Name}, Migration{}, ReachabilityReachable)
		if got.DeadlineYear != want {
			t.Errorf("%s: deadline %d, want %d", family.Name, got.DeadlineYear, want)
		}
	}
	rsa, _, _ := Resolve("RSA")
	want, _ := rsa.EarliestDeadline()
	if got, _ := MigrationPriority(Finding{Status: Vulnerable, Family: "rsa-2048"}, Migration{}, ReachabilityReachable); got.DeadlineYear != want {
		t.Errorf("alias rsa-2048: deadline %d, want RSA's %d", got.DeadlineYear, want)
	}
	if got, _ := MigrationPriority(Finding{Status: Vulnerable, Family: "NotAFamily"}, Migration{}, ReachabilityReachable); got.DeadlineYear != 0 {
		t.Errorf("unknown family: deadline %d, want none", got.DeadlineYear)
	}
}

func TestReachabilityValid(t *testing.T) {
	for _, r := range []Reachability{ReachabilityReachable, ReachabilityUnreachable, ReachabilityUnknown} {
		if !r.Valid() {
			t.Errorf("%q is not valid", r)
		}
	}
	for _, r := range []Reachability{"", "Reachable", "reached", "not_applicable"} {
		if r.Valid() {
			t.Errorf("%q is valid", r)
		}
	}
}

func TestPriorityCompare(t *testing.T) {
	plan := []Priority{
		{Level: PriorityLevelP3, Path: Upgrade},
		{Level: PriorityLevelP3, DeadlineYear: 2030, Path: Upgrade},
		{Level: PriorityLevelP1, Path: Upgrade},
		{Level: PriorityLevelP1, DeadlineYear: 2030, Path: Blocked},
		{Level: "P9", DeadlineYear: 2030, Path: Upgrade},
		{Level: PriorityLevelP1, DeadlineYear: 2030, Path: ""},
		{Level: PriorityLevelP2, Path: Swap},
		{Level: PriorityLevelP2, DeadlineYear: 2029, Path: Redesign},
		{Level: PriorityLevelP1, DeadlineYear: 2030, Path: Upgrade},
		{Level: PriorityLevelP1, DeadlineYear: 2028, Path: Redesign},
	}
	want := []Priority{
		{Level: PriorityLevelP1, DeadlineYear: 2028, Path: Redesign},
		{Level: PriorityLevelP1, DeadlineYear: 2030, Path: Upgrade},
		{Level: PriorityLevelP1, DeadlineYear: 2030, Path: Blocked},
		{Level: PriorityLevelP1, DeadlineYear: 2030, Path: ""},
		{Level: PriorityLevelP1, Path: Upgrade},
		{Level: PriorityLevelP2, DeadlineYear: 2029, Path: Redesign},
		{Level: PriorityLevelP2, Path: Swap},
		{Level: PriorityLevelP3, DeadlineYear: 2030, Path: Upgrade},
		{Level: PriorityLevelP3, Path: Upgrade},
		{Level: "P9", DeadlineYear: 2030, Path: Upgrade},
	}
	slices.SortStableFunc(plan, Priority.Compare)
	if !slices.Equal(plan, want) {
		t.Errorf("sorted plan:\n got  %+v\n want %+v", plan, want)
	}
}

func TestPriorityCompareIgnoresRuleAndReason(t *testing.T) {
	a := Priority{Level: PriorityLevelP3, Rule: PriorityRuleUnreachable, Reason: "x", DeadlineYear: 2030, Path: Swap}
	b := Priority{Level: PriorityLevelP3, Rule: PriorityRuleReachabilityUnknown, Reason: "y", DeadlineYear: 2030, Path: Swap}
	if a.Compare(b) != 0 || b.Compare(a) != 0 {
		t.Errorf("Compare = %d, %d; want a tie both ways", a.Compare(b), b.Compare(a))
	}
}
