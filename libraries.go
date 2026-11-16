// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	modsemver "golang.org/x/mod/semver"

	"go.yaml.in/yaml/v3"
)

// SupportStatus is whether a library offers a post-quantum algorithm.
type SupportStatus string

// Library support statuses.
const (
	SupportAvailable     SupportStatus = "available"
	SupportPlanned       SupportStatus = "planned"
	SupportNone          SupportStatus = "none"
	SupportNotApplicable SupportStatus = "not_applicable"
)

// SupportKind is the post-quantum primitive a library may offer.
type SupportKind string

// Support kinds: ML-KEM for key establishment, ML-DSA for signatures.
const (
	SupportKEM       SupportKind = "kem"
	SupportSignature SupportKind = "signature"
)

// Support is a library's post-quantum support for one kind.
type Support struct {
	Status  SupportStatus `yaml:"status"`
	Since   string        `yaml:"since"`
	APIs    []string      `yaml:"apis"`
	Sources []string      `yaml:"sources"`
	Note    string        `yaml:"note"`
}

// TLSDefaultGroups is one row of a library's default TLS key-exchange groups:
// the groups a version from Since (inclusive) offers when the code configures
// none, spelled as the IANA TLS Supported Groups registry spells them
// (x25519, secp256r1, X25519MLKEM768). Rows are listed newest-first and the
// first row whose Since the version reaches answers, so a version older than
// every row has no answer: the entry only speaks for versions it can cite.
type TLSDefaultGroups struct {
	Since   string   `yaml:"since"`
	Groups  []string `yaml:"groups"`
	Sources []string `yaml:"sources"`
	Note    string   `yaml:"note"`
}

// Library is one libraries.yaml entry. A library published as several
// packages lists every purl.
type Library struct {
	Library          string             `yaml:"library"`
	Purls            []string           `yaml:"purls"`
	KEM              Support            `yaml:"kem"`
	Signature        Support            `yaml:"signature"`
	TLSDefaultGroups []TLSDefaultGroups `yaml:"tls_default_groups"`
	CheckedAt        string             `yaml:"checked_at"`
}

// Libraries is the PQC support of each library, looked up by purl.
type Libraries struct {
	entries []Library
	byPurl  map[string]*Library
}

//go:embed libraries.yaml
var librariesYAML []byte

var loadLibraries = sync.OnceValues(func() (*Libraries, error) { return ParseLibraries(librariesYAML) })

// DefaultLibraries returns the embedded libraries.yaml.
func DefaultLibraries() *Libraries {
	l, err := loadLibraries()
	if err != nil {
		panic(err) // the data is embedded; a parse failure is a build defect
	}
	return l
}

// ParseLibraries parses and validates a libraries.yaml document.
func ParseLibraries(data []byte) (*Libraries, error) {
	var entries []Library
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&entries); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("pqcdataset: libraries.yaml: %w", err)
	}
	l := &Libraries{entries: entries, byPurl: map[string]*Library{}}
	seen := map[string]bool{}
	for i := range entries {
		e := &entries[i]
		if err := e.validate(); err != nil {
			return nil, fmt.Errorf("pqcdataset: libraries.yaml: %s: %w", e.Library, err)
		}
		if seen[e.Library] {
			return nil, fmt.Errorf("pqcdataset: libraries.yaml: %s listed twice", e.Library)
		}
		seen[e.Library] = true
		for _, purl := range e.Purls {
			// The same package can back two libraries (a C and a C++ binding):
			// they must agree, or the lookup by purl would be ambiguous.
			key := strings.ToLower(purl)
			if prev, dup := l.byPurl[key]; dup && !sameSupport(prev, e) {
				return nil, fmt.Errorf("pqcdataset: libraries.yaml: %s and %s share %s with different support", prev.Library, e.Library, purl)
			}
			l.byPurl[key] = e
		}
	}
	return l, nil
}

// purlBase is the purl without its subpath, qualifiers and version, with a
// scope's @ spelled %40 as the data spells it. The version starts at the first
// @ that does not follow a slash: the @ of a scoped npm name
// (pkg:npm/@types/node) does, and a version may itself hold / or @.
func purlBase(purl string) string {
	base, _, _ := strings.Cut(purl, "#")
	base, _, _ = strings.Cut(base, "?")
	for i := 1; i < len(base); i++ {
		if base[i] == '@' && base[i-1] != '/' {
			base = base[:i]
			break
		}
	}
	return strings.ReplaceAll(base, "/@", "/%40")
}

func sameSupport(a, b *Library) bool {
	if a.KEM.Status != b.KEM.Status || a.KEM.Since != b.KEM.Since ||
		a.Signature.Status != b.Signature.Status || a.Signature.Since != b.Signature.Since ||
		len(a.TLSDefaultGroups) != len(b.TLSDefaultGroups) {
		return false
	}
	// Same reason as KEM/Signature: two libraries backed by one purl must
	// agree, or DefaultTLSGroups by purl silently answers for whichever
	// entry was parsed last.
	for i := range a.TLSDefaultGroups {
		x, y := a.TLSDefaultGroups[i], b.TLSDefaultGroups[i]
		if x.Since != y.Since || !slices.Equal(x.Groups, y.Groups) {
			return false
		}
	}
	return true
}

// DefaultTLSGroups returns the default TLS key-exchange groups a library
// version offers when the code configures none, looked up by purl or by the
// entry's library id (a standard library such as go/crypto has no purl). The
// second result is false when the library has no entry, carries no
// tls_default_groups rows, or the version predates every row — the data only
// speaks for versions it can cite.
func (l *Libraries) DefaultTLSGroups(purlOrID, version string) ([]string, bool) {
	e := l.byPurl[strings.ToLower(purlBase(purlOrID))]
	if e == nil {
		for i := range l.entries {
			if strings.EqualFold(l.entries[i].Library, purlOrID) {
				e = &l.entries[i]
				break
			}
		}
	}
	if e == nil {
		return nil, false
	}
	for _, row := range e.TLSDefaultGroups {
		if versionAtLeast(version, row.Since) {
			return append([]string(nil), row.Groups...), true
		}
	}
	return nil, false
}

// Entries returns a copy of every entry.
func (l *Libraries) Entries() []Library {
	return append([]Library(nil), l.entries...)
}

// Support returns a library's support for one kind, looked up by any of its
// purls, with or without a version and in any case: a Go module's namespace
// often arrives lowercased (github.com/protonmail/go-crypto). The second result
// is false when the library has no entry.
func (l *Libraries) Support(purl string, kind SupportKind) (Support, bool) {
	e, ok := l.byPurl[strings.ToLower(purlBase(purl))]
	if !ok {
		return Support{}, false
	}
	if kind == SupportSignature {
		return e.Signature, true
	}
	return e.KEM, true
}

func (e *Library) validate() error {
	if e.Library == "" {
		return fmt.Errorf("no library id")
	}
	for _, purl := range e.Purls {
		if !strings.HasPrefix(purl, "pkg:") || strings.Contains(purl, "@") {
			return fmt.Errorf("purl %q is not a purl without a version", purl)
		}
	}
	if e.CheckedAt != "" {
		checked, err := time.Parse(time.DateOnly, e.CheckedAt)
		if err != nil {
			return fmt.Errorf("checked_at %q is not YYYY-MM-DD", e.CheckedAt)
		}
		if checked.After(time.Now()) {
			return fmt.Errorf("checked_at %s is in the future", e.CheckedAt)
		}
	}
	for kind, s := range map[SupportKind]Support{SupportKEM: e.KEM, SupportSignature: e.Signature} {
		if err := s.validate(e.CheckedAt); err != nil {
			return fmt.Errorf("%s: %w", kind, err)
		}
	}
	for i, row := range e.TLSDefaultGroups {
		if !modsemver.IsValid(canonicalVersion(row.Since)) {
			return fmt.Errorf("tls_default_groups[%d]: since %q is not a version", i, row.Since)
		}
		if len(row.Groups) == 0 {
			return fmt.Errorf("tls_default_groups[%d]: no groups", i)
		}
		if len(row.Sources) == 0 {
			return fmt.Errorf("tls_default_groups[%d]: no sources", i)
		}
		for _, src := range row.Sources {
			if !strings.HasPrefix(src, "https://") && !strings.HasPrefix(src, "http://") {
				return fmt.Errorf("tls_default_groups[%d]: source %q is not a URL", i, src)
			}
		}
		// Newest-first and strictly so: lookup answers with the first row the
		// version reaches, and two rows with one Since would shadow each other.
		if i > 0 && versionAtLeast(row.Since, e.TLSDefaultGroups[i-1].Since) {
			return fmt.Errorf("tls_default_groups[%d]: since %q is not older than the row above (%q); list rows newest-first", i, row.Since, e.TLSDefaultGroups[i-1].Since)
		}
	}
	return nil
}

func (s Support) validate(checkedAt string) error {
	for _, src := range s.Sources {
		if !strings.HasPrefix(src, "https://") && !strings.HasPrefix(src, "http://") {
			return fmt.Errorf("source %q is not a URL", src)
		}
	}
	switch s.Status {
	case SupportAvailable:
		if s.Since == "" || len(s.APIs) == 0 || len(s.Sources) == 0 {
			return fmt.Errorf("available needs since, apis and sources")
		}
	case SupportPlanned:
		if len(s.Sources) == 0 || checkedAt == "" {
			return fmt.Errorf("planned needs sources and checked_at")
		}
	case SupportNone, SupportNotApplicable:
		return s.validateAbsent(checkedAt)
	default:
		return fmt.Errorf("invalid status %q", s.Status)
	}
	return nil
}

// validateAbsent checks a none or not_applicable support: no version, no API.
func (s Support) validateAbsent(checkedAt string) error {
	if s.Since != "" || len(s.APIs) > 0 {
		return fmt.Errorf("%s carries since or apis", s.Status)
	}
	if s.Status == SupportNone && checkedAt == "" {
		return fmt.Errorf("none needs checked_at")
	}
	return nil
}
