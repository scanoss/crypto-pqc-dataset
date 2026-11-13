// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import (
	"cmp"
	"math"
)

// PriorityLevel is how soon a quantum-vulnerable finding should migrate to
// post-quantum, P1 first.
type PriorityLevel string

// Priority levels, most urgent first.
const (
	PriorityLevelP1 PriorityLevel = "P1"
	PriorityLevelP2 PriorityLevel = "P2"
	PriorityLevelP3 PriorityLevel = "P3"
)

var levelRank = map[PriorityLevel]int{PriorityLevelP1: 1, PriorityLevelP2: 2, PriorityLevelP3: 3}

// Reachability says whether the project's code reaches a finding.
type Reachability string

// Reachability values. MigrationPriority reads any other value as ReachabilityUnknown.
const (
	ReachabilityReachable   Reachability = "reachable"
	ReachabilityUnreachable Reachability = "unreachable"
	ReachabilityUnknown     Reachability = "unknown"
)

// Valid reports whether r is one of the three values, so a consumer can log a
// value it maps wrongly instead of silently getting P3.
func (r Reachability) Valid() bool {
	switch r {
	case ReachabilityReachable, ReachabilityUnreachable, ReachabilityUnknown:
		return true
	}
	return false
}

// PriorityRule is the stable code of the rule that set a priority, for
// consumers that translate or match the reason.
type PriorityRule string

// Priority rules.
const (
	PriorityRuleReachableKeyExchange PriorityRule = "reachable_key_exchange"
	PriorityRuleReachableUseUnknown  PriorityRule = "reachable_use_unknown"
	PriorityRuleReachableSignature   PriorityRule = "reachable_signature"
	PriorityRuleUnreachable          PriorityRule = "unreachable"
	PriorityRuleReachabilityUnknown  PriorityRule = "reachability_unknown"
)

var priorityRules = map[PriorityRule]struct {
	level  PriorityLevel
	reason string
}{
	PriorityRuleReachableKeyExchange: {PriorityLevelP1, "reachable key exchange or encryption: recorded data can be decrypted later"},
	PriorityRuleReachableUseUnknown:  {PriorityLevelP1, "reachable, use unknown: ranked as key exchange"},
	PriorityRuleReachableSignature:   {PriorityLevelP2, "reachable signature"},
	PriorityRuleUnreachable:          {PriorityLevelP3, "not reached by the project's code"},
	PriorityRuleReachabilityUnknown:  {PriorityLevelP3, "reachability unknown"},
}

// Priority is the post-quantum migration priority of one quantum-vulnerable finding.
type Priority struct {
	Level  PriorityLevel `json:"level"`
	Rule   PriorityRule  `json:"rule"`
	Reason string        `json:"reason"`
	// DeadlineYear is the earliest year a source sets for the finding's family, 0 when none does.
	DeadlineYear int `json:"deadline_year,omitempty"`
	// Path is the finding's migration path, carried for Compare.
	Path Path `json:"path"`
}

// MigrationPriority returns the priority of a finding whose migration path is
// m, or false when the finding is not quantum-vulnerable. The path only orders
// findings; the level comes from reachability and use.
func MigrationPriority(f Finding, m Migration, r Reachability) (Priority, bool) {
	if f.Status != Vulnerable {
		return Priority{}, false
	}
	rule := priorityRuleOf(f, r)
	p := Priority{Level: priorityRules[rule].level, Rule: rule, Reason: priorityRules[rule].reason, Path: m.Path}
	if family, _, ok := Resolve(f.Family); ok {
		p.DeadlineYear, _ = family.EarliestDeadline()
	}
	return p, true
}

func priorityRuleOf(f Finding, r Reachability) PriorityRule {
	switch r {
	case ReachabilityReachable:
	case ReachabilityUnreachable:
		return PriorityRuleUnreachable
	case ReachabilityUnknown:
		return PriorityRuleReachabilityUnknown
	default:
		return PriorityRuleReachabilityUnknown
	}
	switch useOf(f) {
	case useSignature:
		return PriorityRuleReachableSignature
	case useKeyExchange:
		return PriorityRuleReachableKeyExchange
	case useUnknown:
	}
	return PriorityRuleReachableUseUnknown
}

type use int

const (
	useUnknown use = iota
	useSignature
	useKeyExchange
)

// useOf reads the primitive, then the operation for pke or any other primitive
// (RSA rules report signing as pke), then the family kind.
func useOf(f Finding) use {
	switch f.Primitive {
	case primitiveSignature:
		return useSignature
	case primitiveKeyAgree, primitiveKEM:
		return useKeyExchange
	}
	switch f.Operation {
	case "sign", "verify":
		return useSignature
	case "encrypt", "decrypt", "encapsulate", "decapsulate":
		return useKeyExchange
	}
	if family, _, ok := Resolve(f.Family); ok {
		switch family.Kind {
		case KindSignature:
			return useSignature
		case KindKeyAgreement:
			return useKeyExchange
		case KindDual:
		}
	}
	return useUnknown
}

// Compare orders two priorities for a migration plan: level first, then the
// closest deadline (none last), then the cheapest path. Unknown values sort
// last. It is an ordering for sorting, not equality: Rule and Reason are ignored.
func (p Priority) Compare(q Priority) int {
	return cmp.Or(
		cmp.Compare(rank(levelRank, p.Level), rank(levelRank, q.Level)),
		cmp.Compare(deadlineRank(p.DeadlineYear), deadlineRank(q.DeadlineYear)),
		cmp.Compare(rank(effort, p.Path), rank(effort, q.Path)),
	)
}

// rank is the value's position in ranks, or after every known value.
func rank[K comparable](ranks map[K]int, k K) int {
	if r, ok := ranks[k]; ok {
		return r
	}
	return len(ranks) + 1
}

func deadlineRank(year int) int {
	if year == 0 {
		return math.MaxInt
	}
	return year
}
