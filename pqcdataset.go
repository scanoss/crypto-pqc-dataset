// Copyright (c) 2026 SCANOSS
// SPDX-License-Identifier: MIT

package pqcdataset

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

// Status is a family's post-quantum verdict.
type Status string

// PQC statuses. Unassessed means no curated family matched. Minor versions may
// add statuses, so a consumer must handle a value it does not know.
const (
	Safe          Status = "safe"
	Vulnerable    Status = "vulnerable"
	Hybrid        Status = "hybrid"
	NotApplicable Status = "not_applicable"
	Unassessed    Status = "unassessed"
)

// Sources of the deadlines in this dataset.
const (
	SourceNISTIR8547 = "NIST IR 8547"
	SourceCNSA2      = "CNSA 2.0"
)

// Deadline is one source's cited schedule for a family. A year is 0 when the
// source sets no such milestone: NIST IR 8547 deprecates and disallows, while
// CNSA 2.0 only sets the year to have migrated by.
type Deadline struct {
	Source          string `yaml:"source"`
	DeprecatedAfter int    `yaml:"deprecated_after"`
	DisallowedAfter int    `yaml:"disallowed_after"`
	MigrateBy       int    `yaml:"migrate_by"`
	Citation        string `yaml:"citation"`
}

// Family is one curated algorithm family. Every function returns its own copy,
// so changing a Family never changes the dataset.
type Family struct {
	// Name is the canonical family name, such as "RSA" or "ML-KEM".
	Name string
	// PQCStatus is never Unassessed: that is the answer for a spelling no
	// family matches.
	PQCStatus Status
	// TakesParameter reports whether a trailing number is a parameter, such as
	// the key size in "RSA-2048", rather than part of the name.
	TakesParameter bool
	// Aliases are the other spellings of the family; Name is not repeated.
	Aliases []string
	// Deadlines lists only the schedules an official source states for this
	// family; a family no source dates has none. A source may contribute more
	// than one.
	Deadlines []Deadline
	// Kind is set on vulnerable families only: what the family is used for.
	Kind Kind
}

// Kind is what a vulnerable family is used for. It decides the migration path
// when a finding does not say its operation.
type Kind string

// Family kinds.
const (
	KindSignature    Kind = "signature"
	KindKeyAgreement Kind = "key-agreement"
	KindDual         Kind = "dual"
)

// datasetFile and familyRow are the dataset.yaml format; a row names its
// deadlines by key, which Family resolves.
type datasetFile struct {
	Version       string              `yaml:"version"`
	SourceVintage string              `yaml:"source_vintage"`
	Deadlines     map[string]Deadline `yaml:"deadlines"`
	Families      []familyRow         `yaml:"families"`
}

type familyRow struct {
	Name           string   `yaml:"name"`
	PQCStatus      Status   `yaml:"pqc_status"`
	TakesParameter bool     `yaml:"takes_parameter"`
	Aliases        []string `yaml:"aliases"`
	Deadlines      []string `yaml:"deadlines"`
	Kind           Kind     `yaml:"kind"`
}

// semver is the X.Y.Z form the release tag and Version share.
var semver = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// storedStatuses are the statuses a row may declare; Unassessed is only ever
// the answer for a spelling no row matches.
var storedStatuses = map[Status]bool{Safe: true, Vulnerable: true, Hybrid: true, NotApplicable: true, Unassessed: false}

type dataset struct {
	Version  string
	Families []Family

	index map[string]*Family
	// maxParts is the most parts any spelling splits into, which bounds the
	// runs classifyCompound tries.
	maxParts int
}

//go:embed dataset.yaml
var raw []byte

var load = sync.OnceValues(func() (*dataset, error) { return parse(raw) })

func parse(b []byte) (*dataset, error) {
	var file datasetFile
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true) // a misspelled key is an error, not an ignored field
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("pqcdataset: parse dataset: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("pqcdataset: parse dataset: more than one YAML document")
	}
	if !semver.MatchString(file.Version) {
		return nil, fmt.Errorf("pqcdataset: parse dataset: version %q is not X.Y.Z", file.Version)
	}
	for key, deadline := range file.Deadlines {
		if err := validDeadline(key, deadline); err != nil {
			return nil, fmt.Errorf("pqcdataset: %w", err)
		}
	}
	d := &dataset{Version: file.Version, Families: make([]Family, len(file.Families)), index: make(map[string]*Family)}
	for i, row := range file.Families {
		f := &d.Families[i]
		var err error
		if *f, err = row.family(file); err != nil {
			return nil, fmt.Errorf("pqcdataset: family %d (%q): %w", i, row.Name, err)
		}
		for _, spelling := range append([]string{f.Name}, f.Aliases...) {
			token := normalize(spelling)
			if token == "" {
				return nil, fmt.Errorf("pqcdataset: family %s: spelling %q has no letters or digits", f.Name, spelling)
			}
			if prev, dup := d.index[token]; dup && prev != f {
				return nil, fmt.Errorf("pqcdataset: %q resolves to both %s and %s", spelling, prev.Name, f.Name)
			}
			d.index[token] = f
			d.maxParts = max(d.maxParts, len(splitName(spelling)))
		}
	}
	return d, nil
}

// family validates one row and resolves its deadline keys.
func (row familyRow) family(file datasetFile) (Family, error) {
	if row.Name == "" {
		return Family{}, fmt.Errorf("no name")
	}
	if !storedStatuses[row.PQCStatus] {
		return Family{}, fmt.Errorf("invalid pqc_status %q", row.PQCStatus)
	}
	switch {
	case row.PQCStatus == Vulnerable && row.Kind != KindSignature && row.Kind != KindKeyAgreement && row.Kind != KindDual:
		return Family{}, fmt.Errorf("vulnerable family without a valid kind (%q)", row.Kind)
	case row.PQCStatus != Vulnerable && row.Kind != "":
		return Family{}, fmt.Errorf("kind %q on a family that is not vulnerable", row.Kind)
	}
	f := Family{Name: row.Name, PQCStatus: row.PQCStatus, TakesParameter: row.TakesParameter, Aliases: row.Aliases, Kind: row.Kind}
	for _, key := range row.Deadlines {
		d, ok := file.Deadlines[key]
		if !ok {
			return Family{}, fmt.Errorf("unknown deadline %q", key)
		}
		if _, dup := f.Deadline(d.Source); dup {
			return Family{}, fmt.Errorf("two %s deadlines", d.Source)
		}
		f.Deadlines = append(f.Deadlines, d)
	}
	return f, nil
}

// validDeadline rejects a schedule a consumer could not use or cite.
func validDeadline(key string, d Deadline) error {
	switch {
	case d.Source == "" || d.Citation == "":
		return fmt.Errorf("deadline %q: source and citation are required", key)
	case d.DeprecatedAfter == 0 && d.DisallowedAfter == 0 && d.MigrateBy == 0:
		return fmt.Errorf("deadline %q: no year", key)
	case d.DeprecatedAfter < 0 || d.DisallowedAfter < 0 || d.MigrateBy < 0:
		return fmt.Errorf("deadline %q: negative year", key)
	case d.DeprecatedAfter != 0 && d.DisallowedAfter != 0 && d.DeprecatedAfter > d.DisallowedAfter:
		return fmt.Errorf("deadline %q: deprecated after it is disallowed", key)
	}
	return nil
}

func mustLoad() *dataset {
	d, err := load()
	if err != nil {
		panic(err) // the dataset is embedded; a parse failure is a build defect
	}
	return d
}

// Version is the dataset version that produced a classification.
func Version() string { return mustLoad().Version }

// Families returns every curated family, sorted by name in byte order.
func Families() []Family {
	families := mustLoad().Families
	out := make([]Family, len(families))
	for i := range families {
		out[i] = families[i].clone()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Resolve maps a producer spelling ("RSASSA-PSS", "rsa-2048", "Kyber") to its
// curated family, plus the trailing parameter when the spelling carried one.
// The name or an alias is tried first, then a numeric suffix is stripped only on
// families that take a parameter, so "RIPEMD-128" never becomes RIPEMD-160.
func Resolve(spelling string) (f Family, parameter int, ok bool) {
	d := mustLoad()
	token := normalize(spelling)
	if family, found := d.index[token]; found {
		return family.clone(), 0, true
	}
	// Longest number first, so "DH2048" is DH with 2048 even though "DH20" is
	// an alias; a stem that is no family, as "SM" in "SM4128", moves the cut right.
	start := len(token)
	for start > minStem && isDigit(token[start-1]) {
		start--
	}
	for cut := start; cut < len(token); cut++ {
		family, found := d.index[token[:cut]]
		if !found || !family.TakesParameter {
			continue
		}
		n, err := strconv.Atoi(token[cut:])
		if err != nil || n <= 0 {
			return Family{}, 0, false
		}
		return family.clone(), n, true
	}
	return Family{}, 0, false
}

// minStem keeps a stem of at least two characters, so "3DES" and "MD5" are
// never read as a parameterised "DES" or "MD".
const minStem = 2

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// clone copies everything a caller could change, so no caller can alter the
// shared dataset.
func (f *Family) clone() Family {
	c := *f
	c.Aliases = append([]string(nil), f.Aliases...)
	c.Deadlines = append([]Deadline(nil), f.Deadlines...)
	return c
}

// tlsGroupFamilies overrides the family of the IANA TLS supported-group
// spellings whose bare name resolves to the wrong use: a TLS group is by
// definition a key exchange, but "secp256r1" alone is also a signing curve
// and resolves to the dual-use EC family (whose migration path is never the
// cheap one), and the finite-field ffdhe groups resolve to nothing at all.
var tlsGroupFamilies = map[string]string{
	"secp256r1": "ECDH", "secp384r1": "ECDH", "secp521r1": "ECDH",
	"secp224r1": "ECDH",
	// OpenSSL accepts the SECG/legacy spellings of the same groups in
	// SSL_CTX_set1_groups_list, so a group extracted from code may arrive in
	// any of them; they must resolve exactly like their registry spelling.
	"prime256v1": "ECDH", "p-256": "ECDH", "p-384": "ECDH", "p-521": "ECDH",
	// The brainpool TLS 1.3 groups (RFC 8734, IANA 31-33).
	"brainpoolp256r1tls13": "ECDH", "brainpoolp384r1tls13": "ECDH",
	"brainpoolp512r1tls13": "ECDH",
	"ffdhe2048":            "DH", "ffdhe3072": "DH", "ffdhe4096": "DH",
	"ffdhe6144": "DH", "ffdhe8192": "DH",
	// OpenSSL's default list also names SM2 as a TLS group (RFC 8998) and the
	// SM2+ML-KEM hybrid, which has no family of its own and lands in the
	// generic Hybrid family. KNOWN LIMITATION: the SM2 family's kind is dual,
	// so curveSM2 keeps the dual-use migration priority — the very trap this
	// map removes for secp256r1 — because the dataset has no SM2
	// key-agreement family to redirect to; TestResolveTLSGroup pins it so a
	// future family makes the fix visible. The GOST groups (GC256A..GC512C,
	// RFC 9189) are deliberately NOT mapped: the dataset's GOST family is the
	// symmetric cipher one (not_applicable), which would be the wrong verdict
	// for a key agreement — and a stock OpenSSL never offers them anyway (the
	// default list is filtered by what the loaded providers support).
	"curvesm2": "SM2", "curvesm2mlkem768": "Hybrid",
}

// ResolveTLSGroup resolves an IANA TLS supported-group spelling — a
// tls_default_groups row's group, or a group a rule extracted from code — to
// its family, in its own context: a TLS group is a key exchange, so the
// ambiguous curve names resolve to ECDH (kind key-agreement) and the ffdhe
// groups to DH, instead of what the bare spelling would resolve to. Every
// other spelling (x25519, x448, the hybrids, pure ML-KEM) already resolves
// correctly and is delegated to Resolve; an unknown name is a miss, never a
// guess.
func ResolveTLSGroup(name string) (Family, bool) {
	if fam, ok := tlsGroupFamilies[strings.ToLower(strings.TrimSpace(name))]; ok {
		f, _, resolved := Resolve(fam)
		return f, resolved
	}
	f, _, resolved := Resolve(name)
	return f, resolved
}

// StatusOf returns the PQC status of a spelling, Unassessed when it does not
// resolve. Unlike Classify, it does not split compound names such as "SHA256-RSA".
func StatusOf(spelling string) Status {
	if f, _, ok := Resolve(spelling); ok {
		return f.PQCStatus
	}
	return Unassessed
}

// familySources is the order a finding's algorithm identity is read in:
// the algorithm's own keys first, then a certificate's signature algorithm.
var familySources = []string{
	"algorithmFamily", "materialAlgorithm", "algorithmName", "certificateAlgorithm", "signatureAlgorithm",
}

// Classify resolves a finding's family from its producer metadata, so every
// consumer reads the same fields in the same order: each key as a spelling
// first, then each as a compound name. A post-quantum family paired with a
// hybrid is the hybrid (see pairedHybrid). Minor versions may read more keys,
// and so classify findings an earlier version left unassessed; the order of
// the keys read today does not change.
func Classify(metadata map[string]string) (Family, bool) {
	f, ok := classifyIdentity(metadata)
	if ok && f.PQCStatus == Safe {
		if h, paired := pairedHybrid(metadata, f); paired {
			return h, true
		}
	}
	return f, ok
}

func classifyIdentity(metadata map[string]string) (Family, bool) {
	for _, key := range familySources {
		if v := metadata[key]; v != "" {
			if f, _, ok := Resolve(v); ok {
				return f, true
			}
		}
	}
	for _, key := range familySources {
		if f, ok := classifyCompound(metadata[key]); ok {
			return f, true
		}
	}
	return Family{}, false
}

// pairedHybrid reports the hybrid a post-quantum family is half of. Detection
// rules give a hybrid KEM the post-quantum family, since CycloneDX has no hybrid
// family, and put the pair in the name ("X25519MLKEM768") or the classical half
// in classicalAlgorithm; the name is the more specific identity.
func pairedHybrid(metadata map[string]string, postQuantum Family) (Family, bool) {
	for _, key := range familySources {
		v := metadata[key]
		if v == "" {
			continue
		}
		if f, _, ok := Resolve(v); ok && f.PQCStatus == Hybrid {
			return f, true
		}
		if f, ok := classifyCompound(v); ok && f.PQCStatus == Hybrid {
			return f, true
		}
	}
	if classical, _, ok := Resolve(metadata["classicalAlgorithm"]); ok && classical.PQCStatus == Vulnerable {
		return combine([]Family{postQuantum, classical}, false)
	}
	return Family{}, false
}

// nameSeparators split a compound name such as "SHA256-RSA", "SHA256withRSA"
// or "DHKEM(P-256, HKDF-SHA256)" into its algorithms.
var nameSeparators = regexp.MustCompile(`(?i)[-_/\s(),.:+@]+|with`)

// ignorableParts are cipher modes and paddings: words in a compound name that
// name no algorithm, so they never make it unknown.
var ignorableParts = map[string]bool{
	"ECB": true, "CBC": true, "CFB": true, "CFB8": true, "OFB": true, "CTR": true, "GCM": true,
	"CCM": true, "XTS": true, "SIV": true, "OCB": true, "EAX": true, "KW": true, "KWP": true,
	"NOPADDING": true, "PKCS1PADDING": true, "PKCS5PADDING": true, "PKCS7PADDING": true,
	"ISO10126PADDING": true, "OAEPPADDING": true, "PADDING": true,
}

func splitName(name string) []string {
	var parts []string
	for _, p := range nameSeparators.Split(name, -1) {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// classifyCompound resolves each algorithm in a compound name, longest run of
// parts first so "ML-KEM-768" stays one algorithm, and judges the name by its
// riskiest part: the hash in "SHA256-RSA" must not hide the RSA.
func classifyCompound(name string) (Family, bool) {
	parts := splitName(name)
	if len(parts) < 2 {
		return Family{}, false
	}
	maxParts := mustLoad().maxParts
	var found []Family
	unknown := false
	// afterUnparameterised is true right after an algorithm that takes no parameter.
	afterUnparameterised := false
	for i := 0; i < len(parts); {
		j := min(len(parts), i+maxParts)
		for ; j > i; j-- {
			if f, _, ok := Resolve(strings.Join(parts[i:j], "-")); ok {
				found = append(found, f)
				afterUnparameterised = !f.TakesParameter
				break
			}
		}
		if j > i {
			i = j
			continue
		}
		// A number belongs to the algorithm before it; one that takes no
		// parameter makes it another algorithm ("RIPEMD-128").
		part := normalize(parts[i])
		switch {
		case ignorableParts[part]:
		case isNumber(part):
			unknown = unknown || afterUnparameterised
		default:
			unknown = true
		}
		if !isNumber(part) {
			afterUnparameterised = false
		}
		i++
	}
	return combine(found, unknown)
}

func isNumber(s string) bool {
	for i := range len(s) {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s != ""
}

// combine judges several algorithms used together: a classical public-key
// algorithm beside a post-quantum one is a hybrid, otherwise the riskiest wins.
// When a part is unknown and every known part is not applicable, the unknown
// part may be the public-key algorithm, so the name stays unassessed.
func combine(found []Family, unknown bool) (Family, bool) {
	first := func(status Status) (Family, bool) {
		for _, f := range found {
			if f.PQCStatus == status {
				return f, true
			}
		}
		return Family{}, false
	}
	_, hasVulnerable := first(Vulnerable)
	if _, hasSafe := first(Safe); hasSafe && hasVulnerable {
		f, _, ok := Resolve(hybridFamily)
		return f, ok
	}
	for _, status := range []Status{Vulnerable, Hybrid, Safe} {
		if f, ok := first(status); ok {
			return f, true
		}
	}
	if f, ok := first(NotApplicable); ok && !unknown {
		return f, true
	}
	return Family{}, false
}

// hybridFamily is the row for a classical and a post-quantum algorithm
// combined when no row names that pair.
const hybridFamily = "Hybrid"

// NamesAlgorithm reports whether the metadata carries any algorithm identity.
func NamesAlgorithm(metadata map[string]string) bool {
	for _, key := range familySources {
		if metadata[key] != "" {
			return true
		}
	}
	return false
}

// Deadline returns the family's deadline from one source, such as SourceCNSA2;
// the first one when the source contributes more than one.
func (f Family) Deadline(source string) (Deadline, bool) {
	for _, d := range f.Deadlines {
		if d.Source == source {
			return d, true
		}
	}
	return Deadline{}, false
}

// EarliestDeadline returns the earliest year any source sets for the family,
// whatever the milestone: the worst case to plan a migration against.
func (f Family) EarliestDeadline() (year int, ok bool) {
	for _, d := range f.Deadlines {
		for _, y := range []int{d.DeprecatedAfter, d.DisallowedAfter, d.MigrateBy} {
			if y != 0 && (!ok || y < year) {
				year, ok = y, true
			}
		}
	}
	return year, ok
}

// normalize keeps upper-cased letters and digits only, so case and punctuation never matter.
func normalize(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}
