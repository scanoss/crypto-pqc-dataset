// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import (
	"bufio"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// staleAfter is how long a planned or none entry stays valid before it is researched again.
const staleAfter = 90 * 24 * time.Hour

type snapshotRow struct {
	purls []string
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

func readSnapshot(t *testing.T) map[string]snapshotRow {
	t.Helper()
	rows := map[string]snapshotRow{}
	for _, line := range readLines(t, "testdata/crypto-rules-libraries.txt") {
		f := strings.Split(line, "\t")
		if len(f) != 2 {
			t.Fatalf("snapshot line %q: want id and purls", line)
		}
		row := snapshotRow{}
		if f[1] != "-" {
			row.purls = strings.Split(f[1], ",")
		}
		rows[f[0]] = row
	}
	return rows
}

func sorted(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// Every library of the rule set has an entry, or is listed as pending.
func TestLibrariesCoverage(t *testing.T) {
	snapshot := readSnapshot(t)
	pending := map[string]bool{}
	for _, id := range readLines(t, "testdata/libraries-pending.txt") {
		if _, ok := snapshot[id]; !ok {
			t.Errorf("pending %s is not in the snapshot", id)
		}
		pending[id] = true
	}
	entries := map[string]Library{}
	for _, e := range DefaultLibraries().Entries() {
		entries[e.Library] = e
	}
	for id, row := range snapshot {
		e, ok := entries[id]
		switch {
		case ok && pending[id]:
			t.Errorf("%s has an entry and is still pending", id)
		case !ok && !pending[id]:
			t.Errorf("%s has no entry", id)
		case !ok:
			continue
		}
		if !slices.Equal(sorted(e.Purls), row.purls) {
			t.Errorf("%s: purls %v, the snapshot says %v", id, e.Purls, row.purls)
		}
	}
	for id := range entries {
		if _, ok := snapshot[id]; !ok {
			t.Errorf("entry %s is not in the snapshot", id)
		}
	}
}

// A planned or none entry is researched again after three months.
func TestLibrariesNotStale(t *testing.T) {
	for _, e := range DefaultLibraries().Entries() {
		if e.KEM.Status != SupportPlanned && e.KEM.Status != SupportNone &&
			e.Signature.Status != SupportPlanned && e.Signature.Status != SupportNone {
			continue
		}
		checked, err := time.Parse(time.DateOnly, e.CheckedAt)
		if err != nil {
			t.Errorf("%s: checked_at %q", e.Library, e.CheckedAt)
			continue
		}
		if time.Since(checked) > staleAfter {
			t.Errorf("%s: checked %s, older than three months", e.Library, e.CheckedAt)
		}
	}
}

func TestLibrariesSchema(t *testing.T) {
	valid := `
- library: go/go-jose-v4
  purls: [pkg:golang/github.com/go-jose/go-jose/v4]
  kem: { status: none }
  signature: { status: planned, note: "JOSE ML-DSA is an IETF draft", sources: ["https://example.org/draft"] }
  checked_at: 2026-11-10
- library: java/bouncycastle
  purls: [pkg:maven/org.bouncycastle/bcprov-jdk18on, pkg:maven/org.bouncycastle/bctls-jdk18on]
  kem: { status: available, since: "1.79", apis: ["org.example.MLKEM"], sources: ["https://example.org/notes"] }
  signature: { status: not_applicable }
- library: c/blst
  purls: [pkg:github/supranational/blst]
  kem: { status: not_applicable }
  signature: { status: none }
  checked_at: 2026-11-10
- library: cpp/blst
  purls: [pkg:github/supranational/blst]
  kem: { status: not_applicable }
  signature: { status: none }
  checked_at: 2026-11-10
`
	l, err := ParseLibraries([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := l.Support("pkg:golang/github.com/go-jose/go-jose/v4@v4.1.7", SupportSignature); !ok || s.Status != SupportPlanned {
		t.Errorf("go-jose signature: %+v %v", s, ok)
	}
	if s, ok := l.Support("pkg:maven/org.bouncycastle/bctls-jdk18on@1.80", SupportKEM); !ok || s.Status != SupportAvailable {
		t.Errorf("a second purl of a library: %+v %v", s, ok)
	}
	if _, ok := l.Support("pkg:npm/unknown", SupportKEM); ok {
		t.Error("an unknown purl has support")
	}
	const ok = "kem: {status: not_applicable}, signature: {status: not_applicable}"
	for name, doc := range map[string]string{
		"available without since":   "- {library: a/b, kem: {status: available, apis: [x], sources: ['https://y']}, signature: {status: none}, checked_at: 2026-11-10}",
		"available without apis":    "- {library: a/b, kem: {status: available, since: '1', sources: ['https://y']}, signature: {status: none}, checked_at: 2026-11-10}",
		"available without source":  "- {library: a/b, kem: {status: available, since: '1', apis: [x]}, signature: {status: none}, checked_at: 2026-11-10}",
		"planned without source":    "- {library: a/b, kem: {status: planned}, signature: {status: none}, checked_at: 2026-11-10}",
		"none without checked_at":   "- {library: a/b, kem: {status: none}, signature: {status: none}}",
		"none with since":           "- {library: a/b, kem: {status: none, since: '1'}, signature: {status: none}, checked_at: 2026-11-10}",
		"source not a URL":          "- {library: a/b, kem: {status: planned, sources: [somewhere]}, signature: {status: none}, checked_at: 2026-11-10}",
		"checked in the future":     "- {library: a/b, kem: {status: none}, signature: {status: none}, checked_at: 2999-01-01}",
		"unknown status":            "- {library: a/b, kem: {status: maybe}, signature: {status: none}, checked_at: 2026-11-10}",
		"unknown key":               "- {library: a/b, purl: 'pkg:npm/x', " + ok + "}",
		"versioned purl":            "- {library: a/b, purls: ['pkg:npm/x@1'], " + ok + "}",
		"duplicate library":         "- {library: a/b, " + ok + "}\n- {library: a/b, " + ok + "}",
		"shared purl, other status": "- {library: c/x, purls: ['pkg:github/o/x'], " + ok + "}\n- {library: cpp/x, purls: ['pkg:github/o/x'], kem: {status: none}, signature: {status: none}, checked_at: 2026-11-10}",
	} {
		if _, err := ParseLibraries([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPurlBase(t *testing.T) {
	for purl, want := range map[string]string{
		"pkg:golang/github.com/go-jose/go-jose/v4@v4.1.4":                          "pkg:golang/github.com/go-jose/go-jose/v4",
		"pkg:golang/github.com/go-jose/go-jose/v4":                                 "pkg:golang/github.com/go-jose/go-jose/v4",
		"pkg:npm/@types/node@20.1.0":                                               "pkg:npm/%40types/node",
		"pkg:npm/@types/node":                                                      "pkg:npm/%40types/node",
		"pkg:npm/%40types/node@20.1.0":                                             "pkg:npm/%40types/node",
		"pkg:maven/org.example/pqc@1.0?repository_url=https://repo.example.com/m2": "pkg:maven/org.example/pqc",
		"pkg:maven/org.example/pqc@1.0?type=jar":                                   "pkg:maven/org.example/pqc",
		"pkg:golang/golang.org/x/crypto@v0.38.0#ssh/agent":                         "pkg:golang/golang.org/x/crypto",
		"pkg:golang/golang.org/x/crypto#ssh/agent":                                 "pkg:golang/golang.org/x/crypto",
		"pkg:npm/@types/node@20.1.0?vcs_url=git+https://github.com/a/b#lib":        "pkg:npm/%40types/node",
		"pkg:github/openssl/openssl@refs/tags/openssl-3.5.0":                       "pkg:github/openssl/openssl",
		"pkg:golang/golang.org/x/crypto@v1@v2":                                     "pkg:golang/golang.org/x/crypto",
		"":                                                                         "",
	} {
		if got := purlBase(purl); got != want {
			t.Errorf("purlBase(%q) = %q, want %q", purl, got, want)
		}
	}
}

// A scoped npm purl spelled with a literal @ finds its %40 entry.
func TestSupportScopedNpmPurl(t *testing.T) {
	l, err := ParseLibraries([]byte(`
- library: javascript/scoped
  purls: ["pkg:npm/%40acme/crypto"]
  kem: { status: none, sources: ["https://example.org"] }
  signature: { status: available, since: "1.2.0", apis: ["sign"], sources: ["https://example.org"] }
  checked_at: 2026-11-12
`))
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := l.Support("pkg:npm/@acme/crypto@1.0.0", SupportSignature); !ok || s.Since != "1.2.0" {
		t.Errorf("Support = %+v, %v; want the scoped entry", s, ok)
	}
}

// Qualifiers and a subpath, even with a slash inside, do not hide the entry.
func TestSupportPurlWithQualifiersAndSubpath(t *testing.T) {
	l := DefaultLibraries()
	for _, purl := range []string{
		"pkg:maven/org.bouncycastle/bcprov-jdk18on@1.79?repository_url=https://repo1.maven.org/maven2",
		"pkg:maven/org.bouncycastle/bcprov-jdk18on@1.79?type=jar",
		"pkg:golang/golang.org/x/crypto@v0.38.0#ssh/agent",
	} {
		if _, ok := l.Support(purl, SupportKEM); !ok {
			t.Errorf("Support(%q) found no entry", purl)
		}
	}
}

// Every purl that found its entry by cutting at the first @ still finds the same
// one: versions may hold / or @, and qualifiers or a subpath may follow.
func TestPurlBaseKeepsEveryEarlierMatch(t *testing.T) {
	l := DefaultLibraries()
	firstAt := func(purl string) string { base, _, _ := strings.Cut(purl, "@"); return base }
	versions := []string{"", "@1.0.0", "@v4.1.8", "@refs/tags/v1.0", "@release/v1", "@v1@v2", "@1.0/x", "@npm:%40c/d@1.0", "@2.0.0+build.1"}
	tails := []string{"", "?type=jar", "?repository_url=https://repo.example.com/m2", "#sub/dir", "?vcs_url=git@github.com:a/b#x"}
	checked := 0
	for _, e := range l.Entries() {
		for _, stored := range e.Purls {
			for _, v := range versions {
				for _, tail := range tails {
					purl := stored + v + tail
					before, foundBefore := l.byPurl[firstAt(purl)]
					if !foundBefore {
						continue
					}
					checked++
					if now := l.byPurl[purlBase(purl)]; now != before {
						t.Errorf("%s: found %v before, %v now", purl, before.Library, now)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no purl matched before; the test checks nothing")
	}
}

// Purls as producers spell them: a Go module's namespace arrives lowercased,
// so github.com/ProtonMail/go-crypto arrives as protonmail.
func TestSupportProducerSpelledPurls(t *testing.T) {
	l := DefaultLibraries()
	for _, tt := range []struct {
		purl string
		kind SupportKind
		want SupportStatus
	}{
		{"pkg:golang/github.com/protonmail/go-crypto@v1.8.0", SupportKEM, SupportAvailable},
		{"pkg:golang/github.com/protonmail/gopenpgp/v2@v2.7.5", SupportSignature, SupportNone},
		{"pkg:golang/github.com/azure/azure-sdk-for-go/sdk/security/keyvault/azkeys@v1.3.0", SupportSignature, SupportPlanned},
		{"pkg:golang/github.com/thalesignite/crypto11@v1.2.5", SupportKEM, SupportNone},
	} {
		s, ok := l.Support(tt.purl, tt.kind)
		if !ok || s.Status != tt.want {
			t.Errorf("Support(%q) = %q, %v; want %q", tt.purl, s.Status, ok, tt.want)
		}
	}
}

// Every stored purl is found whatever its case, with or without a version.
func TestSupportIgnoresCase(t *testing.T) {
	l := DefaultLibraries()
	for _, e := range l.Entries() {
		for _, purl := range e.Purls {
			for _, spelled := range []string{strings.ToLower(purl), strings.ToUpper(purl[:4]) + purl[4:], strings.ToLower(purl) + "@1.0.0"} {
				// A purl shared by two libraries (C and C++ bindings) finds either; they agree.
				if got, ok := l.byPurl[strings.ToLower(purlBase(spelled))]; !ok || !sameSupport(got, &e) {
					t.Errorf("%s spelled %s does not find %s's support", purl, spelled, e.Library)
				}
			}
		}
	}
}

// Two entries whose purls differ only in case must agree, or the lookup is ambiguous.
func TestParseLibrariesRejectsCaseClashes(t *testing.T) {
	_, err := ParseLibraries([]byte(`
- library: go/a
  purls: ["pkg:golang/github.com/Acme/lib"]
  kem: { status: none, sources: ["https://example.org"] }
  signature: { status: none, sources: ["https://example.org"] }
  checked_at: 2026-11-12
- library: go/b
  purls: ["pkg:golang/github.com/acme/lib"]
  kem: { status: available, since: "1.0.0", apis: ["x"], sources: ["https://example.org"] }
  signature: { status: none, sources: ["https://example.org"] }
  checked_at: 2026-11-12
`))
	if err == nil {
		t.Error("two libraries sharing a purl in different case parsed without error")
	}
}
