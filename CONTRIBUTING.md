# Contributing

Issues and pull requests are welcome. Security issues: see [SECURITY.md](SECURITY.md), not a public issue.

## Developing

Go, as `go.mod` says. Before a pull request:

```bash
go vet ./...
go test -race ./...
```

CI runs those, a 32-bit build, a build for every platform of the release, `staticcheck`, `golangci-lint` as [`.golangci.yaml`](.golangci.yaml) sets it, on each system of the release, `govulncheck`, and the live tests below.

The tests of the Home Assistant device that connect with Home Assistant's own library, [aioesphomeapi](https://github.com/esphome/aioesphomeapi), skip without it: `ESPHOME_PYTHON` names a Python that has it, at the version [CI](.github/workflows/ci.yaml) installs, and `ESPHOME_MDNS_INTERFACES` two interfaces for the test of discovery to announce on, as CI's dummy ones. With `ESPHOME_COMPAT_REQUIRED` set, as in CI, they fail instead.

The live tests are what only a real socket or a real link tells, and a fake wouldn't: which family an entry of `listen` listens on, on Linux, where Go's `0.0.0.0` is IPv6 too; that Home Assistant's libraries, at the other end of a link between two network namespaces, find the device by mDNS at the port it listens on, and connect to it; and that the device drops a Home Assistant that vanishes from the link, one that stops reading, and clients that connect and say nothing, at its limit of connections. And several instances at once, of the command as it is built, `IPV6DDNS_COMMAND`, on the machines of a link made of network namespaces, with a DNS server of the test's for each and Home Assistant's libraries on another machine: two on one machine, each with its ports, its records and its device, through one stopping and starting again, and a third that finds a port taken; a second that would be the first's device over again, with its state file, its name or its identity, and a reflector of mDNS that answers for the first, which is no second; and two on two machines, where what each sends and asks is counted on the wire, alone and with the other, one asks for an address nobody has within the other's hearing, and a name both keep is written once, but when both update it at the same moment, which the test's server arranges: the one refused tries again. And the resolver, asked with dig by clients on the link, as the command runs it: a peer's name through its discovery, a change of address and its leaving, records and CNAMEs, a fake upstream server that is slow, down or truncates, a client outside `allow`, two resolvers with two answers for one name, a second machine of the same configuration, and a second instance on the first's addresses. And the protocols of the discovery, of three instances with three configurations: one that is disabled sends nothing on the wire and one enabled does, and the name a real mDNS responder, avahi-daemon, tells of a host is in the status of the instance that keeps names, and of no other. And the names of a task's templates, for hosts that a real avahi-daemon names: answered by a resolver, with their reverse, and kept at a provider, a name written and a zone's record staying what they are, through a host that leaves and comes back. And the command at work for a while, `TestLiveSoak`: hosts that come and go, their names, and clients asking the resolver, with its goroutines, open files and memory, which `/status.json` tells, staying level; a minute among the others, and `IPV6DDNS_SOAK=15m` every night, in a workflow of its own. And the command started off its link, and killed in the middle of an update and started again, `TestLiveRestart`: the records end as the peer has them, nothing written twice; and two hosts called the same, one by mDNS and one in its DHCP requests, with a real udhcpc, `TestLiveSharedHostname`. They are the `TestLive` ones, built with the `integration` tag, and need Linux, root, iproute2, dig (bind9-dnsutils) and that Python:

```bash
go build -o /tmp/ipv6ddns ./cmd/ipv6ddns
go test -tags integration -exec "sudo env ESPHOME_PYTHON=$(which python3) IPV6DDNS_COMMAND=/tmp/ipv6ddns" -run '^TestLive' . ./cmd/ipv6ddns ./pkg/listen ./pkg/esphome
```

From another system, with Docker, `tools/live-test.sh` runs them, after all the others under the race detector with nothing skipped, in a privileged container that is thrown away; `IPV6DISC=../ipv6disc tools/live-test.sh`, with an ipv6disc that isn't released. A change whose effect only a real socket shows comes with a live test, seen to fail without the change.

The DNS providers have live tests of their own, against the real server where it runs in a container: a fake of an API is written by the hand that wrote its provider, and agrees with it. `tools/live-providers.sh` starts Technitium DNS Server, Gravity, OpenWrt and Mikrotik RouterOS, a CHR under QEMU, gives each a zone, a credential and records to leave alone, and runs the `TestLive` tests of `ddns/`, built with the `live` tag: every change goes through `Update`, under each spelling of the name, and is looked up with a DNS query to the server. It needs Docker, Go, curl and OpenSSH, and takes under a minute. CI runs it. The servers are of the versions pinned in the script, so that a run that fails tells of the code, not of what was released that day: a newer version of one is a change of the script. What a real server does and its fake doesn't is a bug of both.

The providers that are a service run with it when the environment gives them an account, as the settings of the provider in JSON, and a name of the zone that has no records of its own, the only one they touch; they skip without:

```bash
IPV6DDNS_LIVE_CLOUDFLARE='{"api_token": "...", "zone": "example.com", "ttl": "5m", "proxied": false}' IPV6DDNS_LIVE_CLOUDFLARE_NAME=ipv6ddns-live \
IPV6DDNS_LIVE_ROUTE53='{"access_key_id": "...", "secret_access_key": "...", "region": "us-east-1", "hosted_zone_id": "Z...", "ttl": "5m"}' IPV6DDNS_LIVE_ROUTE53_NAME=ipv6ddns-live \
IPV6DDNS_LIVE_DUCKDNS='{"api_token": "..."}' IPV6DDNS_LIVE_DUCKDNS_NAME=a-name-of-the-account \
tools/live-providers.sh
```

pfSense, OPNsense and Windows DNS have their fake only: each is a whole system to install, with no image to start and throw away.

The Gravity API client, `ddns/gravity/client.gen.go`, is generated and committed, so that `go install` and an import of the module build. `go generate ./...` makes it again, from the schema pinned in [`ddns/gravity/main.go`](ddns/gravity/main.go): only needed after changing that pin, or the generator's version. CI fails when the file is not what they generate.

To work on [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc) at the same time, a `go.work` with both, outside the repository, as `GOWORK=../go.work`.

## The documentation

The [configuration reference](docs/reference/configuration.md) and the [providers reference](docs/reference/providers.md) are generated from the schemas: [`config/schema.json`](config/schema.json), and each provider's in [`ddns/schemas/`](ddns/schemas/). After changing a schema:

```bash
go test ./internal/docgen -update
```

A test fails when the pages are behind, when a key has no description, or when an example of the documentation doesn't validate.

The [guides](docs/guides/README.md) are linked from posts elsewhere, which nobody updates: a guide's file name and its headings, whose anchors the links have, stay as they are once published. A new guide is a new file, of one setup, named by what it sets up; it goes in the index, and in the [add-on's](docs/guides/home-assistant/README.md) too, with a page of the add-on's side only where the add-on changes something. Its configuration is whole, as a reader copies it, and is tested as every example is.

The pages, the schemas' descriptions and the program's messages are written in plain words, for someone setting it up, not for someone who knows the code. The point comes first, in short sentences. An error starts with where the problem is, as `resolvers.lan.upstream:`, then says what's wrong and what to write instead, with an example: `resolvers.lan.upstream is missing: give one or more servers to ask ..., as 192.168.1.1`. Many messages are quoted in the pages and the tests, so search for the old text when you change one.

## Adding a DNS provider

1. Copy a provider of [`ddns/`](ddns/), as `cloudflare.go`, and its test.
2. Register it under its name in `init`, and describe its settings in `ddns/schemas/<name>.json`, every setting with a `description`: `decodeSettings` checks them against it, and the reference is made of it.
3. `Update` makes the records of a name exactly the addresses given: it adds those missing, and removes the others, of both A and AAAA. It runs when the addresses change and again after an error, never periodically: it returns `nil` only once the change is applied and served, also when the update before it failed halfway, and every wait for the provider has a timeout.
4. Test it against a fake of the provider's API, as the others do, through prefix changes, and an update that fails halfway. Where the real server runs in a container, add it to `tools/live-providers.sh` and `ddns/live_test.go`.
5. Add it to the test of `ddns/schema_test.go`, and regenerate the reference.

## Releases

A tag makes a release: goreleaser builds it and publishes it on GitHub, with its images. Work goes to `dev`, where CI runs on every push, and reaches `main` when it is released.

- **A prerelease** is a tag of `dev` with a prerelease part: `v0.23.0-rc.1`, `-rc.2`, `-beta.1`. GitHub marks it a prerelease, not the latest release, and its images have its own tags only: `latest`, `vX` and `vX.Y` stay on the last release, so nobody gets it who didn't ask for it. An ipv6ddns prerelease can take an ipv6disc prerelease in `go.mod`, which Go takes as any version: `go get github.com/miguelangel-nubla/ipv6disc@v0.19.0-rc.1`. The add-on repository is told of releases only, so Home Assistant users get none of them.
- **A release** is `dev` merged into `main`, and tagged there: `v0.23.0`.

A tag whose commit says `[skip ci]` starts no release: GitHub skips every workflow of that push, the tag's too. Tag a commit that doesn't, or run the release on the tag by hand: *Actions*, *goreleaser*, *Run workflow*, with the tag under *Use workflow from*.
