# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The dataset version is the module tag (`vX.Y.Z`) and is exposed by `Version()`.

## [Unreleased]

## [1.4.0] - 2026-11-16

### Added

- `tls_default_groups` in `libraries.yaml`: per-version default TLS key-exchange
  groups (IANA spellings, newest-first, every row cited), with
  `DefaultTLSGroups(purlOrID, version)` answering the newest row the version
  reaches — by purl or by library id — and nothing below the oldest row. First
  data: go/crypto, rust/rustls, c/openssl, c/aws-lc, java/bouncycastle and
  javascript/node-tls (whose defaults are the bundled OpenSSL's — verified in
  Node's own deps, LTS backports of OpenSSL 3.5 noted), each row verified
  against a tagged upstream source. python/ssl carries no rows (its
  defaults are the linked OpenSSL's) and java/jca none either (keyed by a JDK
  version no scan captures).
- `ResolveTLSGroup`: resolves an IANA TLS supported-group spelling in its
  key-exchange context, so `secp256r1` (and the `prime256v1`/`P-256` spellings
  OpenSSL also accepts) answers ECDH/key-agreement instead of the dual-use EC
  family, and the `ffdhe*` groups answer DH instead of nothing. The GOST TLS
  groups stay unresolved on purpose; `curveSM2` keeps the dual kind as a
  documented limitation until the dataset grows an SM2 key-agreement family.

## [1.3.0] - 2026-11-13

### Added

- `MigrationPriority` ranks a quantum-vulnerable finding `P1`, `P2` or `P3` by reachability and use, with a
  rule code, reason and deadline; `Priority.Compare` orders a migration plan.

## [1.2.2] - 2026-11-12

### Fixed

- A dependency purl in another case than `libraries.yaml`'s now finds its entry. A Go purl with a
  lowercased namespace (`github.com/protonmail/go-crypto`) was reported `blocked` although the library
  supports ML-KEM and ML-DSA.
- A dependency with no purl now reads "PQC support of X is unknown (no purl)" instead of claiming no PQC.

## [1.2.1] - 2026-11-12

### Fixed

- A dependency already at or past the version that ships ML-KEM / ML-DSA is no longer told to upgrade
  to it: the `upgrade` reason now says the version already supports the algorithm and to switch to it.
- A scoped npm purl spelled with a literal `@` (`pkg:npm/@scope/name`), or a purl with qualifiers or a
  subpath but no version, now finds its `libraries.yaml` entry.

## [1.2.0] - 2026-11-12

### Added

- Vulnerable families carry a `kind` (`signature`, `key-agreement` or `dual`), and `migration.yaml`
  holds the cited path rules, key and signature sizes, and JOSE/JWT libraries the migration path reads.
- `libraries.yaml` records ML-KEM and ML-DSA support for every library in the inventory
  (`testdata/crypto-rules-libraries.txt`); a test fails when a library has no entry, so a new one
  needs its entry before a release.
- `MigrationPath` and `ComponentPath` give a vulnerable finding and a component their migration path
  (`upgrade`, `swap`, `redesign` or `blocked`), with `inferred` and `size_risk`.

## [1.1.0] - 2026-11-10

### Fixed

- A hybrid KEM reported with the `ML-KEM` family and the pair in `algorithmName` (or the classical
  half in `classicalAlgorithm`) is now `hybrid`; it was `safe`, so no hybrid finding was ever
  classified as one.

## [1.0.0] - 2026-11-06

### Added

- PQC status per algorithm family (`vulnerable`, `safe`, `hybrid`, `not_applicable`), with
  aliases for the spellings standards, protocols and libraries use.
- Every CycloneDX 1.7 `algorithmFamily` value except HPKE resolves; HPKE stays unassessed because
  its status depends on the KEM.
- Compound names such as `SHA256-RSA` or `Kyber768-X25519` are judged by their riskiest algorithm,
  and a classical and a post-quantum algorithm together are `hybrid`.
- Cited deadlines per source: NIST IR 8547 (October 2026) deprecation and disallowance years for the
  families it lists, and the CNSA 2.0 migrate-by year for the classical signature and key-exchange
  families.
- `Classify` also reads a certificate's `certificateAlgorithm` and `signatureAlgorithm`.

[Unreleased]: https://github.com/scanoss/crypto-pqc-dataset/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/scanoss/crypto-pqc-dataset/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/scanoss/crypto-pqc-dataset/compare/v1.2.2...v1.3.0
[1.2.2]: https://github.com/scanoss/crypto-pqc-dataset/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/scanoss/crypto-pqc-dataset/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/scanoss/crypto-pqc-dataset/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/scanoss/crypto-pqc-dataset/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/scanoss/crypto-pqc-dataset/releases/tag/v1.0.0
