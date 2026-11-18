# Installation and running

## Getting it

- **A release**: download the binary for your system from the [latest release](https://github.com/miguelangel-nubla/ipv6ddns/releases/latest).
- **Docker**: `ghcr.io/miguelangel-nubla/ipv6ddns`, for linux/386, amd64, arm/v6, arm/v7 and arm64. `:v0` follows the latest v0 release, `:v0.18` its patches, `:v0.18.0` stays on one.
- **From source**, with [Go](https://go.dev/doc/install): `go install github.com/miguelangel-nubla/ipv6ddns/cmd/ipv6ddns@latest`.
- **On a Mikrotik router**, as a container: see [Mikrotik](mikrotik.md#running-as-a-container-on-routeros).

## What discovery needs

Local discovery listens to the network and sends probes, which needs raw sockets:

- **Root**, or the `CAP_NET_RAW` capability, for the binary.
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

The health check needs `webserver_listen` to include `127.0.0.1:8053`. The image has `bash`, `curl`, `jq`, `dig` and `ip` for the scripts of [command sources](sources.md).

## Flags

| Flag | |
|---|---|
| `-config_file` | The configuration file, YAML or JSON. Default: `config.yaml` |
| `-lifetime` | How long a discovered address stays after it was last seen. Default: 1h |
| `-log_level` | `debug`, `info`, `warn`, `error`. Default: `info` |
| `-webserver_listen` | Where to serve the web report: below |
| `-live` | Show the report in the terminal, updating, instead of the log |
| `-version` | Print the version |

`-lifetime`, `-log_level` and `-webserver_listen` are in the [configuration file](reference/configuration.md#top-level) too, as `lifetime`, `log_level` and `webserver_listen`: a flag given on the command line wins over the file.

## The web report

`webserver_listen` takes a list of what to listen on, in any combination; on the command line, comma separated:

| Entry | Listens on |
|---|---|
| `8053`, `:8053` | that port, on all addresses |
| `192.0.2.1:8053`, `[2001:db8::1]:8053` | that address and port |
| `192.0.2.1`, `2001:db8::1`, `[2001:db8::1]` | that address, port 80 |
| `myhost:8053`, `myhost` | every address the name resolves to, at start |

The report has no authentication: behind a reverse proxy, list only an address the proxy reaches. It hides the credentials, the plugins' and commands' arguments, and the update errors.

| Path | Serves |
|---|---|
| `/` | The report, as text: the names and their records, and the discovered hosts |
| `/healthz` | `ok`, while the process runs: for health checks |
| `/status.json` | The same as the report, as JSON |
| `/metrics` | Prometheus metrics: the addresses of each name, the updates by result, the last success |

## Stopping

On SIGINT or SIGTERM, it stops discovering and scheduling updates, and gives the updates running up to 30 seconds to end.
