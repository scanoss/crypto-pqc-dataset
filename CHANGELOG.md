# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The dataset version is the module tag (`vX.Y.Z`) and is exposed by `Version()`.

## [Unreleased]

### Fixed

- A scoped npm purl spelled with a literal `@` (`pkg:npm/@scope/name`) now finds its `libraries.yaml` entry.

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

[Unreleased]: https://github.com/scanoss/crypto-pqc-dataset/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/scanoss/crypto-pqc-dataset/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/scanoss/crypto-pqc-dataset/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/scanoss/crypto-pqc-dataset/releases/tag/v1.0.0
