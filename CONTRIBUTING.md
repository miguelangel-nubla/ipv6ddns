# Contributing

Issues and pull requests are welcome. For a security issue, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Developing

You need Go, at the version `go.mod` names. Before opening a pull request, run:

```bash
go vet ./...
go test -race ./...
```

CI runs both. It also runs:

- a 32-bit build, and a build for every platform of the release;
- `staticcheck`, and `golangci-lint` with the settings in [`.golangci.yaml`](.golangci.yaml), on each operating system of the release;
- `govulncheck`;
- the live tests described below.

To work on [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc) at the same time, keep a `go.work` with both modules outside the repository, and point to it with `GOWORK=../go.work`.

### Tests that need Home Assistant's library

Some tests of the Home Assistant device connect to it with Home Assistant's own library, [aioesphomeapi](https://github.com/esphome/aioesphomeapi). They skip when the library isn't available. To run them, set:

- `ESPHOME_PYTHON`: a Python that has aioesphomeapi, at the version [CI](.github/workflows/ci.yaml) installs.
- `ESPHOME_MDNS_INTERFACES`: two interfaces for the discovery test to announce on. CI uses dummy interfaces.
- `ESPHOME_COMPAT_REQUIRED`: when set, as it is in CI, these tests fail instead of skipping.

### Live tests

The live tests check what only a real socket or a real link can show, and a fake can't. They are the tests named `TestLive…`, built with the `integration` tag. Each instance they start is the built command, given as `IPV6DDNS_COMMAND`, on a link made of network namespaces.

They need Linux, root, iproute2, dig (bind9-dnsutils), and the Python above:

```bash
go build -o /tmp/ipv6ddns ./cmd/ipv6ddns
go test -tags integration -exec "sudo env ESPHOME_PYTHON=$(which python3) IPV6DDNS_COMMAND=/tmp/ipv6ddns" -run '^TestLive' . ./cmd/ipv6ddns ./pkg/listen ./pkg/esphome
```

On another system, `tools/live-test.sh` runs them with Docker, in a privileged container that is thrown away afterwards. It first runs all the other tests under the race detector, with none skipped. To test against an ipv6disc that isn't released yet, run `IPV6DISC=../ipv6disc tools/live-test.sh`.

A change whose effect only a real socket shows must come with a live test, and you must have seen that test fail without the change.

What the live tests cover:

- **Listening.** Which address family each `listen` entry listens on. This matters on Linux, where Go's `0.0.0.0` listens on IPv6 too.
- **The Home Assistant device.** Home Assistant's libraries sit at the other end of a link between two network namespaces. They find the device by mDNS, at the port it listens on, and connect to it. The device drops a Home Assistant that vanishes from the link, and one that stops reading. It also drops clients that connect and say nothing, which would otherwise hold every place up to its connection limit.
- **Several instances at once.** Each machine has a DNS server of the test's, and Home Assistant's libraries run on another machine.
  - Two instances on one machine, each with its own ports, records and device. One of them stops and starts again, and a third instance finds a port taken.
  - A second instance that would duplicate the first's device, by using its state file, its name or its identity. An mDNS reflector that answers for the first instance doesn't count as a second one.
  - Two instances on two machines. The test counts what each sends and asks on the wire, alone and with the other running. One of them asks for an address nobody has, within the other's hearing. A name both keep is written once. When both update it at the same moment, which the test's server arranges, the one that is refused tries again.
- **The resolver**, run by the command and queried with dig by clients on the link:
  - a peer's name learned through discovery, then a change of its address, then the peer leaving;
  - records and CNAMEs;
  - a fake upstream server that is slow, down, or truncates its answers;
  - a client outside `allow`;
  - two resolvers with different answers for one name;
  - a second machine with the same configuration, and a second instance on the first's addresses.
- **The discovery protocols**, with three instances that have three configurations. An instance with a protocol disabled sends nothing for it on the wire, and one with it enabled does. A real mDNS responder, avahi-daemon, announces a host's name, and that name appears in the status of the instance that keeps names, and in no other.
- **Template names**, for hosts that a real avahi-daemon names. A resolver answers them, with their reverse names, and a provider keeps them. A name written in the configuration and a zone's record stay as they are while a host leaves and comes back.
- **A long run**, `TestLiveSoak`. Hosts come and go with their names, and clients query the resolver. The command's goroutines, open files and memory, which `/status.json` reports, must stay level. It runs for a minute with the other tests, and with `IPV6DDNS_SOAK=15m` every night, in a workflow of its own.
- **Restarts**, `TestLiveRestart`. The command is started while its machine is off the link. It is also killed in the middle of an update and started again. The records end up matching what the peer has, with nothing written twice.
- **A shared host name**, `TestLiveSharedHostname`. Two hosts have the same name: one announces it by mDNS, and the other sends it in its DHCP requests, with a real udhcpc.

### The packages

[`packaging/`](packaging/) has what the packages add to the binary: the service, which is a systemd unit in the `.deb`, the `.rpm` and Arch's package and an OpenRC script in Alpine's `.apk`, the starting configuration, the scripts that run at an install, an upgrade or a removal, and the manual page. The `nfpms` block of [`.goreleaser.yaml`](.goreleaser.yaml) puts them together.

`tools/package-test.sh` builds the packages as a release does, and tests them with Docker, in Debian, Fedora, Arch and Alpine containers that boot their own init. Arch has an image for amd64 only, and its systemd doesn't start emulated: on another architecture, as an Apple silicon Mac, its package is only installed, upgraded and removed, and CI, on amd64, tests its service. In each one it:

- installs the package, and checks that nothing was started;
- starts the service, and checks that it discovers a host on a link with it: its addresses by NDP and by ping, and its names by mDNS and by DHCP. This is what shows that the limits the service runs under leave discovery its sockets;
- upgrades the package, and checks that the configuration was kept and the service restarted;
- removes it, and checks that the service stopped and the configuration stayed.

It also runs the 32-bit ARM `.deb` and `.apk` on an emulated ARMv6 processor, as a Raspberry Pi Zero has. There is one 32-bit ARM `.deb`, built for ARMv6: Debian calls ARMv6 and ARMv7 both `armhf`, so a second one, for ARMv7, would install on a Pi Zero and not run there.

The build covers every system of a release and takes minutes: `PACKAGES_BUILT=1 tools/package-test.sh` tests the packages already in `dist/`.

A change to the service's limits must pass this test, and a new limit that discovery could meet must be seen to fail it when set too tight.

### The flake

[`flake.nix`](flake.nix) has the package for Nix, [`nix/package.nix`](nix/package.nix), and the NixOS module, [`nix/module.nix`](nix/module.nix). The module runs the service by the packages' own unit, [`packaging/ipv6ddns.service`](packaging/ipv6ddns.service), which the Nix package brings with it: the limits of the service are written there alone.

`tools/nix-test.sh` checks it with Docker, as CI does: the package builds, and a NixOS virtual machine runs the module's service, which must discover a second machine on its network.

The package pins a hash of the Go modules, which is behind after any change to `go.sum`, such as a new version of ipv6disc. On `dev`, CI writes it by itself: its `nix` job commits the new hash and starts CI on that commit, so wait for that run before a release. In a pull request it can't, and fails until you run this and commit the result:

```bash
tools/nix-test.sh --update
```

### The Homebrew formula

The formula is in its own repository, [`miguelangel-nubla/homebrew-tap`](https://github.com/miguelangel-nubla/homebrew-tap). It builds from the source of a tag, with Go, so a release only changes its source and its checksum. The tap does that by itself: every day, a workflow there makes the formula of the latest release, installs and tests it on macOS, and keeps it. A release here has nothing to do for it, and a prerelease is not followed.

To test a change to the formula, use a container, `docker run --rm -it homebrew/brew`, rather than your own Homebrew.

### Live tests of the DNS providers

A provider's fake API is written by the same person who wrote the provider, so the two always agree. The providers therefore also have live tests against the real server, wherever that server runs in a container.

`tools/live-providers.sh` starts Technitium DNS Server, Gravity, AdGuard Home, Pi-hole, BIND, OpenWrt, a self-hosted UniFi Network Application and MikroTik RouterOS (a CHR under QEMU). It gives each one a zone, a credential, and some records that must be left alone. Then it runs the `TestLive` tests of `ddns/`, built with the `live` tag. Every change goes through `Update`, under each spelling of the name, and is checked with a DNS query to the server.

UniFi is the exception: without a gateway, nothing serves its records, so its test reads them back through its API. A test of the whole program, `TestLiveUniFiProgram`, has UniFi as both its discovery and its names.

The resolver's dynamic updates are tested with real ACME clients, in `TestLiveUpdatesACMEClients`. certbot, lego and acme.sh, of the versions the script pins, each get a certificate of Pebble through ipv6ddns, with a key of their own. ipv6ddns writes their challenges to BIND with the `rfc2136` provider, where Pebble checks them. The clients run in BIND's network, where Pebble is, and reach the test's resolver on this machine. Their certificates must have their names, and no challenge may be left at BIND. In `TestLiveUpdatesNsupdate`, a real `nsupdate`, in BIND's container, sends a host's own addresses with a key: they must reach BIND through a push source and its task, and leave with the last update. In `TestLiveUpdatesKea`, Kea's DHCP-DDNS, of the version the script pins, is sent the requests kea-dhcp4 sends it after a lease, and updates ipv6ddns with its conflict resolution: a name must reach BIND by its host's address, another client asking for it must be refused, and a lease that ends must take it away.

The same UniFi tests run against UniFi OS, which no container has:

- `tools/unifi-os-server.sh <file>` installs UniFi OS Server, of the version it pins, on a Linux machine with Podman. It sets it up offline with a local admin, makes an API key, and writes `IPV6DDNS_LIVE_UNIFI_OS` and `IPV6DDNS_LIVE_UNIFI_OS_USER` to the file, to source before `go test -tags live -run '^TestLiveUniFi' ./ddns .`.
- `tools/unifi-os-vm.sh up` does it in a Debian VM under QEMU, for macOS: the file is then `~/.cache/ipv6ddns-unifi-os-vm/env`.
- CI runs them on `main`, weekly and by hand: the installer is large, and the server takes minutes to start.
- UniFi OS limits how often a user logs in. The tests log in often, so the admin's may wait a minute for a refused login to pass.

Neither UniFi OS Server nor the self-hosted application has a gateway, so they serve none of the records. Against a real console with a gateway, the same tests check what it answers too:

1. Make an API key and get the certificate's fingerprint, as [UniFi: logging in](docs/unifi.md#logging-in) says.
2. Set `IPV6DDNS_LIVE_UNIFI_OS` to the provider's settings, `{"address":"https://192.168.1.1","api_key":"...","tls_fingerprint":"...","zone":"lan.example.com"}`, with a zone whose names `live`, `other` and `live-program` you don't use: the tests add and remove records of those alone.
3. Set `IPV6DDNS_LIVE_UNIFI_OS_DNS` to the gateway's DNS server, `192.168.1.1:53`.
4. Run `go test -tags live -count=1 -v -run '^TestLiveUniFi' ./ddns .`. Each step asks the gateway for the name and expects the records UniFi lists, and the log shows the TTL it answers with.

ipv6disc's plugin test, run against the same console, logs the clients it lists with their IPv6 fields: see its CONTRIBUTING.

- It needs Docker, Go, curl, OpenSSL and OpenSSH, and takes a few minutes, most of them the UniFi Network Application's start. CI runs it.
- The servers are pinned to the versions in the script, so a failing run points at the code and not at whatever was released that day. Moving to a newer version of a server is a change to the script.
- When a real server and its fake behave differently, that is a bug in both the fake and the provider.

The providers that are an online service are tested too, when the environment gives them an account. Each takes the provider's settings as JSON, and a name in the zone that has no records of its own, which is the only name the test touches. Without these variables, the tests skip:

```bash
IPV6DDNS_LIVE_CLOUDFLARE='{"api_token": "...", "zone": "example.com", "ttl": "5m", "proxied": false}' IPV6DDNS_LIVE_CLOUDFLARE_NAME=ipv6ddns-live \
IPV6DDNS_LIVE_ROUTE53='{"access_key_id": "...", "secret_access_key": "...", "region": "us-east-1", "hosted_zone_id": "Z...", "ttl": "5m"}' IPV6DDNS_LIVE_ROUTE53_NAME=ipv6ddns-live \
IPV6DDNS_LIVE_DUCKDNS='{"api_token": "..."}' IPV6DDNS_LIVE_DUCKDNS_NAME=a-name-of-the-account \
IPV6DDNS_LIVE_DESEC='{"token": "...", "zone": "example.com"}' IPV6DDNS_LIVE_DESEC_NAME=ipv6ddns-live \
IPV6DDNS_LIVE_HETZNER='{"api_token": "...", "zone": "example.com"}' IPV6DDNS_LIVE_HETZNER_NAME=ipv6ddns-live \
IPV6DDNS_LIVE_PORKBUN='{"api_key": "pk1_...", "secret_api_key": "sk1_...", "zone": "example.com"}' IPV6DDNS_LIVE_PORKBUN_NAME=ipv6ddns-live \
IPV6DDNS_LIVE_DIGITALOCEAN='{"api_token": "...", "zone": "example.com"}' IPV6DDNS_LIVE_DIGITALOCEAN_NAME=ipv6ddns-live \
IPV6DDNS_LIVE_GANDI='{"token": "...", "zone": "example.com"}' IPV6DDNS_LIVE_GANDI_NAME=ipv6ddns-live \
IPV6DDNS_LIVE_OVH='{"application_key": "...", "application_secret": "...", "consumer_key": "...", "zone": "example.com"}' IPV6DDNS_LIVE_OVH_NAME=ipv6ddns-live \
tools/live-providers.sh
```

pfSense, OPNsense and Windows DNS only have their fakes. Each is a whole system to install, with no image to start and throw away.

### Generated code

The Gravity API client, `ddns/gravity/client.gen.go`, is generated and committed, so that `go install` and imports of the module build without a generation step. `go generate ./...` regenerates it from the schema pinned in [`ddns/gravity/main.go`](ddns/gravity/main.go). You only need that after changing the pin or the generator's version. CI fails when the committed file differs from what they generate.

## The documentation

### Generated pages

The [configuration reference](docs/reference/configuration.md) and the [providers reference](docs/reference/providers.md) are generated from the schemas: [`config/schema.json`](config/schema.json), and each provider's schema in [`ddns/schemas/`](ddns/schemas/). After changing a schema, regenerate them:

```bash
go test ./internal/docgen -update
```

A test fails when the pages are out of date, when a key has no description, or when an example in the documentation doesn't validate.

The manual page, [`packaging/ipv6ddns.1`](packaging/ipv6ddns.1), is generated from the flags. After changing a flag, regenerate it:

```bash
go test ./cmd/ipv6ddns -update
```

The same command redraws the pictures of the report, the `.svg` files in `docs/images/`, each from the `.txt` file beside it. Change the text, never the pictures. A test holds the pictures' colors to those the program gives each kind of line.

The picture of how ipv6ddns works, `architecture-light.svg`, is a drawing: edit it, and the same command draws `architecture-dark.svg` from it, in the dark colors. Check that every text still fits its box, in a browser.

### Guides

The [guides](docs/guides/README.md) are linked from posts elsewhere, which nobody updates. So once a guide is published, its file name and its headings stay as they are, because those links use the headings' anchors.

- A new guide is a new file. It covers one setup, and is named after what it sets up.
- Add it to the guides' index, and to the [app's index](docs/guides/home-assistant/README.md) too. Write a page for the app's side only where the app changes something.
- Give its configuration whole, ready to copy. It is tested like every other example.

### Writing style

The pages, the schemas' descriptions and the program's messages are written in plain words, for someone setting ipv6ddns up, not for someone who knows the code. Put the point first, in short sentences.

An error message starts with where the problem is, such as `resolvers.lan.upstream:`. Then it says what's wrong and what to write instead, with an example: `resolvers.lan.upstream is missing: give one or more servers to ask ..., as 192.168.1.1`.

Many messages are quoted in the pages and the tests, so search for the old text when you change one.

## Adding a DNS provider

1. **Copy an existing provider** from [`ddns/`](ddns/), such as `cloudflare.go`, together with its test.
2. **Register it** under its name in `init`.
3. **Describe its settings** in `ddns/schemas/<name>.json`, each with a `description`. `decodeSettings` checks the settings against that schema, and the reference is generated from it.
4. **Write `Update`.** It makes a name's records exactly the addresses given: it adds the missing ones and removes the others, for both A and AAAA.
   - It runs when the addresses change, and again after an error. It never runs periodically.
   - It returns `nil` only once the change is applied and served. That holds even when the previous update failed halfway.
   - Every wait for the provider has a timeout.
5. **Write TXT records too, whenever its API can.** Implement `ddns.TXTWriter`: `SetTXT`, which makes a name's TXT records exactly the values given, and returns once they are served; and `FullName`, a name in full, as `Domain` but asking the provider when it must. That makes its credential one that writes the DNS challenge, for ipv6ddns's own certificates and for the [challenges of other machines](docs/guides/certificates-for-other-machines.md). Register it with `RegisterTXT`, beside `RegisterProvider`: the errors and the [providers reference](docs/reference/providers.md) list it then, and a test checks that each registered is a `TXTWriter`, and each `TXTWriter` registered. When you change a provider whose API has TXT records, and it has no `SetTXT` yet, add it.
6. **Test it against a fake of the provider's API**, as the other providers do. Cover prefix changes, and an update that fails halfway. Where the real server runs in a container, add it to `tools/live-providers.sh` and `ddns/live_test.go`.
7. **Add its type to `providerTypes` in `ddns/schema_test.go`**, whose tests check its schema and its TXT records, and regenerate the reference.

## A job without a runner

GitHub is at times short of macOS runners. A job it has none for waits, is cancelled with nothing run, and its CI run ends as failed, though nothing was tested. The [rerun](.github/workflows/rerun.yaml) workflow runs such jobs again by itself, up to three times, and only when that is all that went wrong: a job that ran and failed is left for you to look at. `DRY_RUN=1 tools/ci-rerun.sh <owner/repository> <run id>` tells what it would do with a run.

It runs as `main` has it, so a change to it takes effect once it is merged there.

## Releases

A tag makes a release: goreleaser builds it and publishes it on GitHub, with its images. Work goes to `dev`, where CI runs on every push. It reaches `main` when it is released.

- **A prerelease** is a tag on `dev` with a prerelease part: `v0.23.0-rc.1`, `-rc.2`, `-beta.1`.
  - GitHub marks it as a prerelease, not as the latest release.
  - Its images only get its own tags. `latest`, `vX` and `vX.Y` stay on the last release, so nobody gets a prerelease without asking for it.
  - It can depend on an ipv6disc prerelease in `go.mod`, which Go treats like any other version: `go get github.com/miguelangel-nubla/ipv6disc@v0.19.0-rc.1`.
  - The app repository is only notified of releases, so Home Assistant users never get a prerelease.
- **A release** is `dev` merged into `main`, and tagged there: `v0.23.0`.

A tag whose commit message contains `[skip ci]` starts no release. GitHub skips every workflow of that push, including the tag's. Either tag a commit without it, or run the release on the tag by hand: *Actions*, *goreleaser*, *Run workflow*, with the tag under *Use workflow from*.
