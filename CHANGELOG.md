# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The dataset version is the module tag (`vX.Y.Z`) and is exposed by `Version()`.

## [Unreleased]

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

[Unreleased]: https://github.com/scanoss/crypto-pqc-dataset/commits/main
