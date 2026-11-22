# Installation and running

## Getting it

- **A release**: download the binary for your system from the [latest release](https://github.com/miguelangel-nubla/ipv6ddns/releases/latest).
- **Docker**: `ghcr.io/miguelangel-nubla/ipv6ddns`, for linux/386, amd64, arm/v6, arm/v7 and arm64. `:latest` and `:v0` follow the latest release, `:v0.18` follows that minor version's patches, and `:v0.18.0` stays on that exact version.
- **From source**, with [Go](https://go.dev/doc/install): `go install github.com/miguelangel-nubla/ipv6ddns/cmd/ipv6ddns@latest`.
- **On a Mikrotik router**, as a container: see [Mikrotik](mikrotik.md#running-as-a-container-on-routeros).
- **In Home Assistant**, as an add-on: see [its documentation](../homeassistant/addon/DOCS.md).

## What discovery needs

Local discovery listens to the network and sends probes, which needs raw sockets:

- **As a binary:** run it as root, or give it the `CAP_NET_RAW` capability. `sudo setcap cap_net_raw+ep $(command -v ipv6ddns)` lets another user run it.
- **In Docker:**
  - **Use the host's network**, `network_mode: host` or `--network host`. On a network of its own, the container sees none of the hosts. Docker's `"ipv6": true` in `daemon.json` only concerns the networks Docker creates, not the host's, so you don't need it.
  - **Keep `NET_RAW`.** Docker grants it by default, but other runtimes, or a Kubernetes `securityContext`, can drop it. Without it, discovery logs `operation not permitted`.

Without either, [plugins](discovery.md#plugins), which read your routers' neighbor tables, still find hosts. The container then needs no privileges and no host network.

On a machine running other containers, leave their bridges out of discovery: see [interfaces](discovery.md#interfaces).

## With Docker Compose

```yaml
services:
  ipv6ddns:
    image: ghcr.io/miguelangel-nubla/ipv6ddns:v0
    network_mode: host
    restart: unless-stopped
    command:
      - "-config_file"
      - "/config.yaml"
    volumes:
      - ./config.yaml:/config.yaml:ro
    environment:
      CLOUDFLARE_TOKEN: ${CLOUDFLARE_TOKEN}
    healthcheck:
      test:
        - "CMD"
        - "curl"
        - "-fsS"
        - "http://127.0.0.1:8053/healthz"
```

The health check needs the web server reachable at `127.0.0.1:8053`, so set `webserver.listen` to `8053`, `:8053` or `127.0.0.1:8053`. The image includes `bash`, `curl`, `jq`, `dig` and `ip`, for the scripts of [command sources](sources.md).

To make it a [Home Assistant](home-assistant-integration.md) device, give it the device's key yourself. Make the key once with `openssl rand -base64 32`, and put it in the container's environment, as `HOMEASSISTANT_KEY: ${HOMEASSISTANT_KEY}` beside the token.

```yaml
homeassistant:
  listen: 192.168.1.0/24    # the network Home Assistant is on
  key: ${HOMEASSISTANT_KEY}
```

Nothing is written to disk then: the configuration stays mounted read-only, and the container needs no data volume. With `key_provisioning: true` instead, the key Home Assistant gives is kept in a file beside the configuration. That file disappears with the container unless its folder is a writable volume: see [the key](home-assistant-integration.md#the-key).

## Flags

| Flag | |
|---|---|
| `-config_file` | The configuration file, YAML or JSON. Default: `config.yaml` |
| `-live` | Show the report in the terminal, updating live, instead of the log. Only what stops the start is logged, so the configuration's warnings and the plugins' errors don't show. It needs a terminal; `q`, Esc, Ctrl-C or a signal ends it |
| `-version` | Print the version |

Everything else is in the [configuration file](reference/configuration.md): the log level, `log_level`; where the web report is served, `webserver.listen`; and how long addresses last, `discovery.lifetime`. An unknown flag is an error, which lists the flags there are, as `-h` does.

Turn a boolean flag off with `-live=false`, not `-live false`: a word that is neither a flag nor a flag's value is an error.

## The web report

`webserver.listen` takes a list of where to listen, in any combination, or a single comma-separated string:

```yaml
webserver:
  listen:
    - 127.0.0.1:8053
    - 10.2.3.0/24
```

| Entry | Listens on |
|---|---|
| `8053`, `:8053` | that port, on all addresses, IPv4 and IPv6 |
| `0.0.0.0:8053`, `[::]:8053` | that port, on all IPv4 addresses, or on all IPv6 ones |
| `192.0.2.1:8053`, `[2001:db8::1]:8053` | that address and port |
| `192.0.2.1`, `2001:db8::1`, `[2001:db8::1]` | that address, port 8053 |
| `10.2.3.0/24`, `fd00::/64` | each address of the machine in that network, at start, port 8053 |
| `myhost:8053`, `myhost` | every address the name resolves to, at start |

Networks and host names are resolved once, at start:

- An address the machine gets later, as from DHCP or a new prefix, isn't listened on until a restart.
- A network with none of the machine's addresses, or a name that doesn't resolve, stops the start.
- A network doesn't include link-local addresses, which need their interface: list those as `fe80::1%eth0`.

[`homeassistant.listen`](home-assistant-integration.md#where-it-listens) takes the same entries, with its own default port, 6053.

The report has no authentication. Behind a reverse proxy, list only an address the proxy reaches. It hides the credentials, the plugins' settings, the commands' arguments, the `urls` of http sources except their host, and the error messages of updates and sources.

| Path | Serves |
|---|---|
| `/` | The report, as text: the names and their records, the discovered hosts with their [names](discovery.md#names), the protocols that run, and the configuration |
| `/healthz` | `ok` while the process runs and its [resolvers](resolver.md) answer; 503, with the reason, when one doesn't. For health checks |
| `/status.json` | The same state as JSON: the names and their records, the discovered hosts with their `names`, the `protocols` that run, and the sources' runs |
| `/metrics` | Prometheus metrics: each name's addresses, its updates by result, its last success. And the program's own, `go_goroutines`, `go_memstats_heap_inuse_bytes` and, on Linux, `process_open_fds`, which should stay level over days |

## Several instances

You can run any number of instances at once, each with its own configuration file, on one machine or on several machines of a network. Each has its own tasks, filters, credentials, sources, lifetimes and discovery, and discovers, updates and serves just what it would on its own.

### On one machine

Anything both would claim has to differ:

| | Each instance needs | Otherwise |
|---|---|---|
| [`webserver.listen`](#the-web-report) | Its own port, or address | The one started second doesn't start: `address already in use`, with the address |
| [`homeassistant`](home-assistant-integration.md#several-devices) `port`, or `listen` | Its own port, when both have the block: 6053 by default | The same |
| `homeassistant.key_provisioning_state_file`, with `key_provisioning: true` | Its own file. The default is `homeassistant.state` beside the configuration, so two configurations in one folder must each name theirs. Not needed with a `key` | The one started second doesn't start, and says which file |
| `homeassistant.name` | Its own name: `ipv6ddns` by default | The one started second runs, but isn't announced to Home Assistant, and logs why |
| `-live` | Its own terminal | |

Nothing else is shared: no lock, no file, no discovery port. An instance that fails to start for one of these reasons has updated and announced nothing. Stopping one leaves the others as they were: its ports are free at once, and only its own device is withdrawn from Home Assistant.

They do share what belongs to the system:

- **The IPv4 neighbor table.** Whatever one instance's sweep resolved, another that listens for IPv4 reads too. One without IPv4 reads none of it.
- **The answers to multicast pings,** which arrive at the machine. Each instance asks for the MAC of a host that answered any of them, so hosts are solicited once more per instance, and no more.

### On several machines of one network

Each instance hears the others' probes. To each one, another instance's machine is just a host, with its real addresses at its MAC; a [`self`](filtering.md#filterself) filter only takes the instance's own machine.

- What one asks for, the EUI-64 and IPv4 addresses its own filters want, tells the others nothing they then publish.
- Nothing heard from another instance makes one probe, so each sends on the network only what it would alone.
- A host that leaves goes from each instance after that instance's own lifetime.

With a `homeassistant` block, each needs its own [name](home-assistant-integration.md#several-devices).

### One name kept by two instances

Two instances can keep the same name at the same provider, as a second machine standing in for the first when it's down, as long as both give it the same addresses: the same filters, for the same hosts, on a network both discover.

An update makes a name's records exactly what its instance has, and only runs when that changes, never just to check. So two instances that find the same addresses end up with the same records, each writing only what's missing, and then leave them alone.

- **An instance that starts** writes what it has found so far, and removes what it hasn't found yet, until it does, just as a single instance does when it restarts. That takes seconds for an address its host uses, and longer for one it keeps quiet: see [after a start](discovery.md#after-a-start).
- **A host that leaves** disappears from the name when the first instance lets it go, after the shorter lifetime.
- **Two updates at the same moment** can collide at the provider. The refused one logs it, tries again after its `retry`, and finds the records already there.

This doesn't work for instances that would give the name different addresses: a `self` filter, which is each machine's own; different filters or [sources](sources.md); or hosts only one of them reaches. Nothing merges their addresses. The records are whatever was written last, and change hands whenever either instance's addresses change. For one name with the addresses of two machines, let one instance take both, each with its own `mac` filter.

## Stopping

On SIGINT or SIGTERM, ipv6ddns stops discovering and scheduling updates, and gives the updates in progress up to 30 seconds to finish. With `-live`, a key that quits the view does the same. A second signal while it waits stops it at once.
