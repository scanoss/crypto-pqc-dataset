# crypto-pqc-dataset

A curated, versioned dataset that says which cryptographic algorithm families a quantum computer
breaks, and by when published guidance says they must be replaced. It ships as a Go package with the
data embedded, so classification works offline and every tool that uses the same version gives the
same answer.

For each algorithm family it records:

- **PQC status:** one of the values below.
- **Aliases:** every CycloneDX 1.7 `algorithmFamily` value except HPKE, plus common algorithm names
  that have no CycloneDX family of their own (`RSA`, `EC`, `X25519`, ...).
- **Deadlines:** NIST IR 8547's deprecation and disallowance years for the families it lists, and a
  CNSA 2.0 year for the classical signature and key-exchange families, each with its citation. A
  vulnerable family no source dates has no deadline.

| Status | Meaning | Examples |
|---|---|---|
| `vulnerable` | A cryptographically relevant quantum computer breaks it (Shor's algorithm), at any key size. | RSA, ECDSA, ECDH, DH |
| `safe` | A post-quantum algorithm. | ML-KEM, ML-DSA, SLH-DSA |
| `hybrid` | A classical and a post-quantum algorithm combined. | X25519MLKEM768, X-Wing |
| `not_applicable` | Symmetric ciphers, hashes, MACs and KDFs: Grover's algorithm weakens them but breaks nothing outright. | AES, SHA-2, HMAC |
| `unassessed` | Returned for an algorithm the dataset does not recognize. Never stored in the data. | |

Severity, policy and remediation are out of scope: the dataset states facts, and each consumer
decides what they mean for its users.

## Install

```sh
go get github.com/scanoss/crypto-pqc-dataset
```

Requires Go 1.26 or later.

## Usage

```go
import pqcdataset "github.com/scanoss/crypto-pqc-dataset"

// Classify a finding from its metadata.
family, ok := pqcdataset.Classify(map[string]string{"algorithmFamily": "RSAES-OAEP"})
if ok {
	fmt.Println(family.Name, family.PQCStatus) // RSA vulnerable
	for _, d := range family.Deadlines {
		fmt.Println(d.Source, d.DeprecatedAfter, d.DisallowedAfter, d.MigrateBy)
		// CNSA 2.0 0 0 2030
		// NIST IR 8547 2030 2035 0
	}
	year, _ := family.EarliestDeadline() // 2030, the worst case
	fmt.Println(year)
}

// Classify a single spelling.
fmt.Println(pqcdataset.StatusOf("ML-KEM-768")) // safe

// Record which dataset produced the verdict.
fmt.Println(pqcdataset.Version())
```

| Function | Purpose |
|---|---|
| `Classify(metadata)` | Classifies a finding from its metadata keys (see below). |
| `Resolve(spelling)` | Maps one spelling to its family, plus a trailing parameter such as a key size. |
| `StatusOf(spelling)` | The PQC status of one spelling, `unassessed` when it does not resolve. Unlike `Classify`, it does not split compound names. |
| `NamesAlgorithm(metadata)` | Reports whether the metadata carries any algorithm identity. |
| `Families()` | Every curated family, sorted by name. |
| `Version()` | The dataset version, to store next to each verdict. |
| `Family.Deadline(source)` | The family's deadline from one source (`SourceNISTIR8547`, `SourceCNSA2`). |
| `Family.EarliestDeadline()` | The earliest year any source sets for the family: the worst case. |

The package reference is on [pkg.go.dev](https://pkg.go.dev/github.com/scanoss/crypto-pqc-dataset).

## How classification works

`Classify` reads the metadata keys CycloneDX-style crypto findings use, in this order, and returns
the first family that resolves:

1. `algorithmFamily`
2. `materialAlgorithm` (the algorithm of a key or other crypto material)
3. `algorithmName`
4. `certificateAlgorithm` and `signatureAlgorithm` (a certificate's signature algorithm)
5. the same keys, in the same order, as compound names, see below

A post-quantum family paired with a hybrid is the hybrid. A hybrid KEM such as `X25519MLKEM768` is
usually reported with `algorithmFamily: ML-KEM`, since CycloneDX has no hybrid family, and the pair
in `algorithmName` or the classical half in `classicalAlgorithm`; either one makes it `hybrid`.

Minor versions may read more keys, and so classify findings an earlier version left unassessed; the
order of the keys read today does not change. They may also add statuses, so handle a status you do
not know.

`algorithmName` matters because CycloneDX 1.7 has no generic RSA, EC, DH or X25519 family, so a
finding for one of those can only name it.

Spellings are compared on upper-cased letters and digits only, so `RSASSA-PSS`, `rsassa_pss` and
`RSASSAPSS` are the same. A trailing number is read as a parameter (`RSA-2048`, `ML-KEM-768`) only
for families marked `takes_parameter`, so `RIPEMD-128` never resolves to RIPEMD-160.

A compound name, such as a signature that names its hash or a hybrid that names both halves, is split
on `-`, `_`, `/`, spaces and `with`, and each algorithm in it is resolved. The name is judged by its
riskiest part, so the hash never hides the public-key algorithm:

| Name | Result | Why |
|---|---|---|
| `SHA256-RSA`, `SHA256withRSA` | RSA, `vulnerable` | The hash is `not_applicable`; RSA decides. |
| `RSA-PKCS1v15-SHA256` | RSA, `vulnerable` | Same, in the other order. |
| `Kyber768-X25519` | Hybrid, `hybrid` | A post-quantum and a classical public-key algorithm together. |
| `X25519-ML-KEM-768` | X25519MLKEM768, `hybrid` | A curated hybrid keeps its own row. |
| `AES-256-GCM` | AES, `not_applicable` | Only symmetric parts. |

`Hybrid` is the row for a classical and a post-quantum pair that no curated row names.

A finding stays `unassessed` when its algorithm is only known at runtime (a name read from
configuration, a key in a hardware module) or the dataset does not curate it yet. HPKE is
`unassessed` on purpose: its status depends on the KEM it uses.

## Data

The data lives in [`dataset.yaml`](dataset.yaml) and is embedded at build time.

| Key | Meaning |
|---|---|
| `version` | The dataset version; it matches the release tag without the `v`. |
| `source_vintage` | The edition of the cited standards the rows were reviewed against. |
| `deadlines` | Named, cited schedules: `source`, any of `deprecated_after`, `disallowed_after` and `migrate_by` (absent when the source sets none), and `citation`. |
| `families[].name` | The canonical family name. |
| `families[].pqc_status` | `vulnerable`, `safe`, `hybrid` or `not_applicable`. |
| `families[].aliases` | Other spellings of the family. |
| `families[].takes_parameter` | Whether a trailing number is a parameter, such as a key size. |
| `families[].deadlines` | Keys of `deadlines` entries, at most one per source; a family gets only the schedules its source states for it. |
| `families[].kind` | Vulnerable families only: `signature`, `key-agreement` or `dual`, what the family is used for. The migration path falls back to it when a finding does not say its operation. |

A spelling may belong to one family only; loading fails otherwise. Tests require every CycloneDX 1.7
`algorithmFamily` value except HPKE to resolve, so any other family a CycloneDX producer can emit is
classified. That vocabulary, in `testdata/cyclonedx-1.7-algorithm-families.txt`, is the
`algorithmFamily` enumeration of the CycloneDX 1.7 specification.

The migration path reads [`migration.yaml`](migration.yaml): the path for a known primitive and
operation, cited key and signature sizes, and the `crypto_rules` libraries that implement JOSE/JWT.
Every row cites its source.

### Sources

- [CNSA 2.0](https://www.nsa.gov/Press-Room/Digital-Media-Center/Document-Gallery/igphoto/2003728741/)
  (NSA, PP-22-1338, September 2022): migrate by 2030 for the classical signature and
  key-exchange families. CNSA 2.0 applies to US National Security Systems and sets its dates by type of system
  (2030 for software and firmware signing and networking equipment, 2033 for most others, 2035 for
  the whole transition); a dataset that only sees the algorithm keeps the earliest.
- [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final), *Transition to Post-Quantum
  Cryptography Standards* (October 2026): Table 2 (digital signatures) and Table 4 (key
  establishment), deprecated after 2030 and disallowed after 2035.

## Contributing

Contributions are welcome, especially data: a family, a spelling or a cited deadline. See
[CONTRIBUTING.md](CONTRIBUTING.md) for how to change the data, the tests each change needs and the
pull request process.

## Versioning

Releases follow [Semantic Versioning](https://semver.org/). A new verdict can change what consumers
report, so:

- **Major:** a breaking change to the Go API or to the format of `dataset.yaml`. As Go requires, a
  major version after v1 changes the module path, e.g. `github.com/scanoss/crypto-pqc-dataset/v2`.
- **Minor:** any change that can change a verdict: new families, aliases, statuses or deadlines.
- **Patch:** citation and documentation fixes that change no verdict.

The dataset version in `dataset.yaml`, returned by `Version()`, is always the module version.

## Releasing

1. In a PR, change `dataset.yaml`, bump its `version`, and in `CHANGELOG.md` move the `[Unreleased]`
   entries under a new `## [X.Y.Z] - YYYY-MM-DD` heading. Update the links at the bottom:
   `[Unreleased]` compares `vX.Y.Z...HEAD`, and a new `[X.Y.Z]` line points to the release tag.
2. After merge, tag `vX.Y.Z` on `main`. The release workflow checks that the tag, the dataset version
   and the changelog agree, runs the tests and publishes a GitHub Release.

## License

[MIT](LICENSE).
