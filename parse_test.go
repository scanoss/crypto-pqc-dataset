// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import (
	"strings"
	"testing"
)

// A mistake in dataset.yaml fails the load instead of shipping silently.
func TestParseRejectsInvalidData(t *testing.T) {
	const header = "version: 1.0.0\ndeadlines:\n  t: {source: S, deprecated_after: 2030, disallowed_after: 2035, citation: c}\nfamilies:\n"
	for name, families := range map[string]string{
		"misspelled key":    "  - {name: A, pqc_status: safe, aliasses: [B]}\n",
		"unknown status":    "  - {name: A, pqc_status: unasessed}\n",
		"unassessed stored": "  - {name: A, pqc_status: unassessed}\n",
		"missing status":    "  - {name: A}\n",
		"empty name":        "  - {name: '', pqc_status: safe}\n",
		"duplicate alias":   "  - {name: A, pqc_status: safe, aliases: [X]}\n  - {name: B, pqc_status: safe, aliases: [x]}\n",
		"unknown deadline":  "  - {name: A, pqc_status: vulnerable, deadlines: [nope]}\n",
		"same source twice": "  - {name: A, pqc_status: vulnerable, deadlines: [t, t]}\n",
		"punctuation name":  "  - {name: '--', pqc_status: safe}\n",
		"empty alias":       "  - {name: A, pqc_status: safe, aliases: ['']}\n",
	} {
		if _, err := parse([]byte(header + families)); err == nil {
			t.Errorf("%s: loaded without error", name)
		}
	}
	if _, err := parse([]byte(header + "  - {name: A, pqc_status: safe}\n")); err != nil {
		t.Errorf("valid data rejected: %v", err)
	}
	for name, deadline := range map[string]string{
		"no source":           "{deprecated_after: 2030, citation: c}",
		"no citation":         "{source: S, deprecated_after: 2030}",
		"no year":             "{source: S, citation: c}",
		"disallowed first":    "{source: S, deprecated_after: 2035, disallowed_after: 2030, citation: c}",
		"misspelled deadline": "{source: S, deprecate_after: 2030, citation: c}",
	} {
		data := "version: 1.0.0\ndeadlines:\n  d: " + deadline + "\nfamilies:\n  - {name: A, pqc_status: safe}\n"
		if _, err := parse([]byte(data)); err == nil {
			t.Errorf("deadline %s: loaded without error", name)
		}
	}
	for _, version := range []string{"x", "1.0", "v1.0.0", "1.0.0-rc1"} {
		if _, err := parse([]byte(strings.Replace(header, "1.0.0", version, 1) + "  - {name: A, pqc_status: safe}\n")); err == nil {
			t.Errorf("version %q: loaded without error", version)
		}
	}
	if _, err := parse([]byte(header + "  - {name: A, pqc_status: safe}\n---\nversion: 2.0.0\n")); err == nil {
		t.Error("second YAML document: loaded without error")
	}
	if _, err := parse([]byte(strings.Replace(header, "version: 1.0.0\n", "", 1) + "  - {name: A, pqc_status: safe}\n")); err == nil {
		t.Error("missing version: loaded without error")
	}
}
