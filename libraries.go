// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

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

// Library is one libraries.yaml entry. A library published as several
// packages lists every purl.
type Library struct {
	Library   string   `yaml:"library"`
	Purls     []string `yaml:"purls"`
	KEM       Support  `yaml:"kem"`
	Signature Support  `yaml:"signature"`
	CheckedAt string   `yaml:"checked_at"`
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
			if prev, dup := l.byPurl[purl]; dup && !sameSupport(prev, e) {
				return nil, fmt.Errorf("pqcdataset: libraries.yaml: %s and %s share %s with different support", prev.Library, e.Library, purl)
			}
			l.byPurl[purl] = e
		}
	}
	return l, nil
}

func sameSupport(a, b *Library) bool {
	return a.KEM.Status == b.KEM.Status && a.KEM.Since == b.KEM.Since &&
		a.Signature.Status == b.Signature.Status && a.Signature.Since == b.Signature.Since
}

// Entries returns a copy of every entry.
func (l *Libraries) Entries() []Library {
	return append([]Library(nil), l.entries...)
}

// Support returns a library's support for one kind, looked up by any of its
// purls, with or without a version. The second result is false when the library has no entry.
func (l *Libraries) Support(purl string, kind SupportKind) (Support, bool) {
	base, _, _ := strings.Cut(purl, "@")
	e, ok := l.byPurl[base]
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
