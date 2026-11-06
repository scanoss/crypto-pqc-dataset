# Contributing to crypto-pqc-dataset

Thank you for your interest in contributing. This project is a curated dataset, so most
contributions are data: a new algorithm family, a spelling that should resolve, or a status or
deadline that needs correcting. Code changes are welcome too.

## Code of Conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md). By taking part you agree to uphold it.

## Reporting a problem

Open an [issue](https://github.com/scanoss/crypto-pqc-dataset/issues) and include:

- the dataset version (`pqcdataset.Version()`, or the module version in your `go.mod`);
- the spelling or metadata you classified, what you got, and what you expected;
- for a wrong status or deadline, a link to the public document that supports the correction.

## Getting started

You need Go 1.26 or later and [golangci-lint](https://golangci-lint.run/) v2.

```sh
git clone https://github.com/<your-user>/crypto-pqc-dataset.git
cd crypto-pqc-dataset
go test -race ./...
golangci-lint run
```

## Changing the data

The data lives in [`dataset.yaml`](dataset.yaml); the README describes every key.

- **A new alias.** Add the spelling to the family's `aliases`. Spellings are compared on upper-case
  letters and digits only, so `RSA-PSS` and `rsapss` are the same alias; loading fails if a spelling
  belongs to two families.
- **A new family.** Add a row with `name` and `pqc_status`. Set `takes_parameter: true` only when a
  trailing number is a parameter, such as a key size (`AES-256`), never when it is part of the name.
- **A status or a deadline.** Every one must rest on a public document. Put the citation in
  `deadlines`, and give a family only the schedules its source states for it.

Unassessed is not a status a row can declare: a family that is not known stays out of the data.

## Changing the code

- Follow [Effective Go](https://go.dev/doc/effective_go) and keep `gofmt` and `golangci-lint` clean.
- Document every exported identifier.
- Keep the public API stable: anything exported is part of the module's compatibility promise.

## Tests

Every change comes with a test. For data, add the spelling and the expected family or status to the
table tests in the `*_test.go` files. For a bug, add a test that fails before the fix.

## Pull requests

1. Branch from `main` and keep the change focused on one thing.
2. Add an entry under `[Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md), in the
   [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.
3. Make sure `go test -race ./...` and `golangci-lint run` pass; CI runs both.
4. Open the pull request against `main`, describing what changed and why, with the sources for any
   data change.

A maintainer reviews every pull request. Releases are cut by maintainers, as the README describes.

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).
