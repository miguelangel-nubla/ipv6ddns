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
    command: ["-config_file", "/config.yaml"]
    volumes:
      - ./config.yaml:/config.yaml:ro
    environment:
      CLOUDFLARE_TOKEN: ${CLOUDFLARE_TOKEN}
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://127.0.0.1:8053/healthz"]
```

The health check needs the web server reachable at `127.0.0.1:8053`: `webserver.listen` `8053`, `:8053` or `127.0.0.1:8053`. The image has `bash`, `curl`, `jq`, `dig` and `ip` for the scripts of [command sources](sources.md).

## Flags

| Flag | |
|---|---|
| `-config_file` | The configuration file, YAML or JSON. Default: `config.yaml` |
| `-lifetime` | How long a discovered address stays after it was last seen. Default: 1h |
| `-log_level` | `debug`, `info`, `warn`, `error`, `dpanic`, `panic`, `fatal`. Default: `info` |
| `-webserver_listen` | Where to serve the web report: below |
| `-live` | Show the report in the terminal, updating, instead of the log: nothing is logged but what stops the start, so the configuration's warnings and the errors of the plugins don't show. It needs a terminal, and `q`, Esc, Ctrl-C or a signal ends it |
| `-version` | Print the version |

`-lifetime`, `-log_level` and `-webserver_listen` are in the [configuration file](reference/configuration.md#top-level) too, as `lifetime`, `log_level` and `webserver.listen`: a flag given on the command line wins over the file.

## The web report

`webserver.listen` takes a list of what to listen on, in any combination; on the command line, comma separated:

```yaml
webserver:
  listen: [127.0.0.1:8053, 10.2.3.0/24]
```

| Entry | Listens on |
|---|---|
| `8053`, `:8053` | that port, on all addresses, IPv4 and IPv6 |
| `0.0.0.0:8053`, `[::]:8053` | that port, on all IPv4 addresses, or on all IPv6 ones |
| `192.0.2.1:8053`, `[2001:db8::1]:8053` | that address and port |
| `192.0.2.1`, `2001:db8::1`, `[2001:db8::1]` | that address, port 80 |
| `10.2.3.0/24`, `fd00::/64` | each address of the machine in that network, at start, port 80 |
| `myhost:8053`, `myhost` | every address the name resolves to, at start |

Networks and host names are read once, at start: an address the machine gets later, as from DHCP or a new prefix, isn't listened on until a restart, and a network with no address of the machine, or a name that doesn't resolve, stops the start. A network doesn't take link-local addresses, which need their interface: list those as `fe80::1%eth0`.

[`homeassistant.listen`](home-assistant-integration.md#a-machine-on-several-networks) takes the same entries, with its port, 6053, for those without one.

The report has no authentication: behind a reverse proxy, list only an address the proxy reaches. It hides the credentials, the plugins' params, the commands' arguments, the `urls` of http sources but their host, and the errors of the updates and of the sources.

| Path | Serves |
|---|---|
| `/` | The report, as text: the names and their records, the discovered hosts, and the configuration |
| `/healthz` | `ok`, while the process runs: for health checks |
| `/status.json` | The state, as JSON: the names and their records, the discovered hosts, and the sources' runs |
| `/metrics` | Prometheus metrics: the addresses of each name, the updates by result, the last success |

## Stopping

On SIGINT or SIGTERM, it stops discovering and scheduling updates, and gives the updates running up to 30 seconds to end. With `-live`, a key that quits the view does the same. A second signal while it waits ends it at once.
