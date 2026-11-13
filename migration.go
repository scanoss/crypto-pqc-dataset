// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import (
	"slices"
	"strings"

	modsemver "golang.org/x/mod/semver"
)

// Finding is what the migration path reads from an existing crypto finding.
type Finding struct {
	Status    Status // pqc.status
	Family    string // pqc.family
	Primitive string // metadata algorithmPrimitive
	Operation string // metadata operation
	// Source is "direct" for the project's code, "dependency" (scan output) or
	// "indirect" (API responses) for code inside a dependency.
	Source            string
	DependencyModule  string
	DependencyPurl    string // with or without a version
	DependencyVersion string
	// LibraryPurl is the purl of the library the rule detected, when the
	// finding carries one.
	LibraryPurl string
}

// Migration is the migration path of one vulnerable finding.
type Migration struct {
	Path     Path   `json:"path"`
	Reason   string `json:"reason"`
	Inferred bool   `json:"inferred"`
	SizeRisk string `json:"size_risk,omitempty"`
}

// SizeRiskJWT marks a use inside a JOSE/JWT library, where bigger keys and
// signatures meet token size limits.
const SizeRiskJWT = "jwt"

// MigrationPath returns the migration path of a finding, or false when the
// finding is not quantum-vulnerable.
func MigrationPath(f Finding, libs *Libraries) (Migration, bool) {
	if f.Status != Vulnerable {
		return Migration{}, false
	}
	ref := mustReference()
	var m Migration
	if f.Source == "dependency" || f.Source == "indirect" {
		m = dependencyPath(f, libs)
	} else {
		m = projectPath(ref, f, libs)
	}
	m.SizeRisk = sizeRisk(ref, f)
	return m, true
}

// dependencyPath is the path of crypto inside a dependency: the user does not
// own that code, so only the dependency's PQC support matters.
func dependencyPath(f Finding, libs *Libraries) Migration {
	module := f.DependencyModule
	if module == "" {
		module = purlName(f.DependencyPurl)
	}
	if module == "" {
		module = "the dependency"
	}
	if strings.TrimSpace(f.DependencyPurl) == "" {
		// Support is looked up by purl: without one it is unknown, not absent.
		return Migration{Path: Blocked, Reason: "PQC support of " + module + " is unknown (no purl)"}
	}
	kind := supportKind(f)
	s, ok := libs.Support(f.DependencyPurl, kind)
	switch {
	case ok && s.Status == SupportAvailable && f.DependencyVersion == "":
		return Migration{Path: Upgrade, Reason: "ensure " + module + " >= " + s.Since}
	case ok && s.Status == SupportAvailable && versionAtLeast(f.DependencyVersion, s.Since):
		// Nothing to bump: the code must move to the algorithm it already ships.
		return Migration{Path: Upgrade, Reason: module + " " + f.DependencyVersion + " already supports " + algorithmOf(kind) + ": switch to it"}
	case ok && s.Status == SupportAvailable:
		return Migration{Path: Upgrade, Reason: "upgrade " + module + " to >= " + s.Since}
	case ok:
		return Migration{Path: Blocked, Reason: "no PQC in " + module + " (" + string(s.Status) + ")"}
	}
	return Migration{Path: Blocked, Reason: "no PQC in " + module + " (no entry)"}
}

// projectPath is the path of the project's own code: the primitive and
// operation decide, or the family when the operation is unknown. A library
// with no PQC at all has to be replaced first.
func projectPath(ref *reference, f Finding, libs *Libraries) Migration {
	var m Migration
	if rule, ok := matchPath(ref, f); ok {
		m.Path, m.Reason = rule.Path, rule.Reason
	} else {
		m.Path = Redesign
		if family, _, ok := Resolve(f.Family); ok && family.Kind == KindSignature {
			m.Path = Swap
		}
		m.Reason, m.Inferred = "operation unknown, inferred from "+f.Family, true
	}
	if f.LibraryPurl != "" {
		if s, ok := libs.Support(f.LibraryPurl, supportKind(f)); ok && s.Status == SupportNone {
			m.Path, m.Reason = Blocked, "no PQC in "+purlName(f.LibraryPurl)+"; replace the library"
		}
	}
	return m
}

// ComponentPath returns the worst path among a component's findings and the
// count per path.
func ComponentPath(paths []Path) (worst Path, counts map[Path]int) {
	counts = map[Path]int{}
	for _, p := range paths {
		if p == "" {
			continue
		}
		counts[p]++
		if effort[p] > effort[worst] {
			worst = p
		}
	}
	return worst, counts
}

func matchPath(ref *reference, f Finding) (pathRule, bool) {
	for _, r := range ref.Paths {
		if r.Primitive == f.Primitive && (len(r.Operations) == 0 || slices.Contains(r.Operations, f.Operation)) {
			return r, true
		}
	}
	return pathRule{}, false
}

// supportKind is the post-quantum primitive that replaces the finding's use.
func supportKind(f Finding) SupportKind {
	switch f.Primitive {
	case "signature":
		return SupportSignature
	case "key-agree", "pke", "kem":
		return SupportKEM
	}
	if family, _, ok := Resolve(f.Family); ok && family.Kind == KindSignature {
		return SupportSignature
	}
	return SupportKEM
}

func sizeRisk(ref *reference, f Finding) string {
	for _, purl := range []string{f.DependencyPurl, f.LibraryPurl} {
		base := purlBase(purl)
		if base == "" {
			continue
		}
		for _, l := range ref.JWTLibraries {
			if slices.ContainsFunc(l.Purls, func(p string) bool { return strings.EqualFold(p, base) }) {
				return SizeRiskJWT
			}
		}
	}
	return ""
}

// purlName is the purl without its type and version, e.g. github.com/go-jose/go-jose/v4.
func purlName(purl string) string {
	base := purlBase(purl)
	if _, rest, ok := strings.Cut(base, "/"); ok {
		return rest
	}
	return base
}

// algorithmOf names the post-quantum algorithm a support kind stands for.
func algorithmOf(kind SupportKind) string {
	if kind == SupportSignature {
		return "ML-DSA"
	}
	return "ML-KEM"
}

// versionAtLeast reports whether version is since or later, by semver. A
// leading v is optional; a version semver cannot read (a Maven .Final, four
// parts, a commit) reads as false, so the caller keeps the upgrade advice.
func versionAtLeast(version, since string) bool {
	v, s := canonicalVersion(version), canonicalVersion(since)
	return modsemver.IsValid(v) && modsemver.IsValid(s) && modsemver.Compare(v, s) >= 0
}

func canonicalVersion(v string) string {
	v = strings.TrimSpace(v)
	if v != "" && v[0] != 'v' {
		v = "v" + v
	}
	return v
}
