# Contributing

Issues and pull requests are welcome. Security issues: see [SECURITY.md](SECURITY.md), not a public issue.

## Developing

Go, as `go.mod` says. Before a pull request:

```bash
go generate ./...   # the Gravity API client
go vet ./...
go test -race ./...
```

CI runs those, a 32-bit build, `staticcheck` and `govulncheck`.

To work on [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc) at the same time, a `go.work` with both, outside the repository, as `GOWORK=../go.work`.

## The documentation

The [configuration reference](docs/reference/configuration.md) and the [providers reference](docs/reference/providers.md) are generated from the schemas: [`config/schema.json`](config/schema.json), and each provider's in [`ddns/schemas/`](ddns/schemas/). After changing a schema:

```bash
go test ./internal/docgen -update
```

A test fails when the pages are behind, when a key has no description, or when an example of the documentation doesn't validate.

## Adding a DNS provider

1. Copy a provider of [`ddns/`](ddns/), as `cloudflare.go`, and its test.
2. Register it under its name in `init`, and describe its settings in `ddns/schemas/<name>.json`, every setting with a `description`: `decodeSettings` checks them against it, and the reference is made of it.
3. `Update` makes the records of a name exactly the addresses given: it adds those missing, and removes the others, of both A and AAAA.
4. Test it against a fake of the provider's API, as the others do, through prefix changes, and an update that fails halfway.
5. Add it to the test of `ddns/schema_test.go`, and regenerate the reference.
