# Installation and running

## Getting it

- **A release**: download the binary for your system from the [latest release](https://github.com/miguelangel-nubla/ipv6ddns/releases/latest).
- **Docker**: `ghcr.io/miguelangel-nubla/ipv6ddns`, for linux/386, amd64, arm/v6, arm/v7 and arm64. `:latest` and `:v0` follow the latest release, `:v0.18` its patches, `:v0.18.0` stays on one.
- **From source**, with [Go](https://go.dev/doc/install): `go install github.com/miguelangel-nubla/ipv6ddns/cmd/ipv6ddns@latest`.
- **On a Mikrotik router**, as a container: see [Mikrotik](mikrotik.md#running-as-a-container-on-routeros).
- **In Home Assistant**, as an add-on: see [its documentation](../homeassistant/addon/DOCS.md).

## What discovery needs

Local discovery listens to the network and sends probes, which needs raw sockets:

- **Root**, or the `CAP_NET_RAW` capability, for the binary: `sudo setcap cap_net_raw+ep $(command -v ipv6ddns)` lets another user run it.
- **In Docker**:
  - **The host's network**, `network_mode: host` or `--network host`: in a network of its own, the container sees none of the hosts. Docker's `"ipv6": true` in `daemon.json` is about the networks Docker makes, not the host's, and isn't needed.
  - **`NET_RAW`**, which Docker grants by default but other runtimes, or a Kubernetes `securityContext`, can drop. Without it, discovery logs `operation not permitted`.

With neither, the [plugins](discovery.md#plugins), which read the neighbor tables of routers, still find hosts: the container then needs no privilege and no host network.

On a host running other containers, leave their bridges out of the discovery: see [interfaces](discovery.md#interfaces).

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

The health check needs the web server reachable at `127.0.0.1:8053`: `webserver.listen` `8053`, `:8053` or `127.0.0.1:8053`. The image has `bash`, `curl`, `jq`, `dig` and `ip` for the scripts of [command sources](sources.md).

As a device of [Home Assistant](home-assistant-integration.md), give it the device's key yourself: made once with `openssl rand -base64 32`, in the container's environment, as `HOMEASSISTANT_KEY: ${HOMEASSISTANT_KEY}` beside the token.

```yaml
homeassistant:
  listen: 192.168.1.0/24    # the network Home Assistant is on
  key: ${HOMEASSISTANT_KEY}
```

Nothing is written then: the configuration stays mounted read-only, and the container needs no volume for data. With `key_provisioning: true` instead, the key Home Assistant gives is kept in a file beside the configuration, which is gone with the container unless that folder is a volume it can write: see [the key](home-assistant-integration.md#the-key).

## Flags

| Flag | |
|---|---|
| `-config_file` | The configuration file, YAML or JSON. Default: `config.yaml` |
| `-live` | Show the report in the terminal, updating, instead of the log: nothing is logged but what stops the start, so the configuration's warnings and the errors of the plugins don't show. It needs a terminal, and `q`, Esc, Ctrl-C or a signal ends it |
| `-version` | Print the version |

Everything else is in the [configuration file](reference/configuration.md): the level of the log, `log_level`, where the web report is served, `webserver.listen`, and the lifetime of the addresses, `discovery.lifetime`. A flag there is none of is an error, which shows the flags there are, as `-h` does.

A boolean flag is turned off as `-live=false`, not `-live false`: a word that is no flag, nor a flag's value, is an error.

## The web report

`webserver.listen` takes a list of what to listen on, in any combination, or one string of them, comma separated:

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

Networks and host names are read once, at start: an address the machine gets later, as from DHCP or a new prefix, isn't listened on until a restart, and a network with no address of the machine, or a name that doesn't resolve, stops the start. A network doesn't take link-local addresses, which need their interface: list those as `fe80::1%eth0`.

[`homeassistant.listen`](home-assistant-integration.md#where-it-listens) takes the same entries, with its port, 6053, for those without one.

The report has no authentication: behind a reverse proxy, list only an address the proxy reaches. It hides the credentials, the plugins' params, the commands' arguments, the `urls` of http sources but their host, and the errors of the updates and of the sources.

| Path | Serves |
|---|---|
| `/` | The report, as text: the names and their records, the discovered hosts, each with its [names](discovery.md#names) when they are kept, the protocols that run, and the configuration |
| `/healthz` | `ok`, while the process runs, and its [resolvers](resolver.md) answer: 503 with the reason when one doesn't. For health checks |
| `/status.json` | The state, as JSON: the names and their records, the discovered hosts, each with its `names` when they are kept, the `protocols` that run, and the sources' runs |
| `/metrics` | Prometheus metrics: the addresses of each name, the updates by result, the last success; and the program's own, `go_goroutines`, `go_memstats_heap_inuse_bytes` and, on Linux, `process_open_fds`, which stay level over days in a program that lets go of what it is done with |

## Several instances

Any number of instances run at once, each with its own configuration file: on one machine, or on several machines of one network. Its tasks, filters, credentials, sources, lifetimes and discovery are each instance's own, and each discovers, updates and serves what it would alone.

### On one machine

What two configurations would both take has to differ:

| | Each instance needs | Otherwise |
|---|---|---|
| [`webserver.listen`](#the-web-report) | Its own port, or address | The one started second doesn't start: `address already in use`, with the address |
| [`homeassistant`](home-assistant-integration.md#several-devices) `port`, or `listen` | Its own port, when both have the block: 6053 by default | The same |
| `homeassistant.key_provisioning_state_file`, with `key_provisioning: true` | Its own file: by default `homeassistant.state` beside the configuration, so two configurations in one folder name theirs. None with a `key` | The one started second doesn't start, and says which file |
| `homeassistant.name` | Its own name: `ipv6ddns` by default | The one started second runs, but isn't announced to Home Assistant, and logs why |
| `-live` | Its own terminal | |

Nothing else is theirs in common: no lock, no file, no port of the discovery. An instance that doesn't start for one of these has updated nothing, and announced nothing. Stopping one leaves the others as they were: its ports are free at once, and only its own device is taken back from Home Assistant.

They share what is the system's. The IPv4 neighbor table: what the sweep of one resolved, another that listens for IPv4 reads too, and one that doesn't take IPv4 has none of it. And the answers to the multicast pings, which come to the machine: each instance asks the MAC of a host that answered any of them, so the hosts are solicited once more for each instance, and no more.

### On several machines of one network

Each hears the probes of the others. To each, another's machine is a host as any, with its real addresses at its MAC: a [`self`](filtering.md#filterself) filter takes the instance's own machine only. What one asks for, the EUI-64 and IPv4 addresses its own filters want, tells the others nothing they then publish. Nothing heard from another makes an instance probe, so each sends on the network what it sends alone. And a host that leaves goes from each after that instance's own lifetime.

With a `homeassistant` block, each needs its own [name](home-assistant-integration.md#several-devices).

### One name kept by two instances

Two instances can keep the same name at the same provider, as a second machine standing in for the first when it is down, when both give it the same addresses: the same filters, of the same hosts, on a network both discover. An update makes a name's records exactly what its instance has, and runs only when that changes, never to check: so two that find the same end with the same records, each writing only what is missing, and then leave them alone.

- An instance that starts writes what it has found so far, and takes off what it hasn't yet, until it finds it: as one alone does when it restarts. That is seconds for an address its host uses, and longer for one it keeps quiet: see [after a start](discovery.md#after-a-start).
- A host that leaves goes from the name when the first of them lets it go: after the shorter lifetime.
- Two updates at once can collide at the provider. The one refused logs it, tries again after its `retry`, and finds the records there.

It isn't for instances that would give the name different addresses: a `self` filter, which is each machine's own; filters or [sources](sources.md) that differ; hosts that only one of them reaches. Nothing merges them: the records are those of whichever wrote last, and change hands whenever what either has changes. For one name with the addresses of two machines, one instance takes both, each with its `mac` filter.

## Stopping

On SIGINT or SIGTERM, it stops discovering and scheduling updates, and gives the updates running up to 30 seconds to end. With `-live`, a key that quits the view does the same. A second signal while it waits ends it at once.
