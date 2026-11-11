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

// Every crypto_rules library has an entry, or is listed as pending.
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
