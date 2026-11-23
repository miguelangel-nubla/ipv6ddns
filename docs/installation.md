# Installation and running

## Getting it

- **A release**: download the binary for your system from the [latest release](https://github.com/miguelangel-nubla/ipv6ddns/releases/latest).
- **A package**, from the [latest release](https://github.com/miguelangel-nubla/ipv6ddns/releases/latest), for your architecture. See [as a service](#as-a-service).

  | System | Package | Install it with |
  |---|---|---|
  | Debian, Ubuntu and their kin | `.deb` | `sudo apt install ./ipv6ddns_*.deb` |
  | Fedora, RHEL and theirs | `.rpm` | `sudo dnf install ./ipv6ddns_*.rpm` |
  | Alpine | `.apk` | `apk add --allow-untrusted ./ipv6ddns_*.apk` |
- **Docker**: `ghcr.io/miguelangel-nubla/ipv6ddns`, for linux/386, amd64, arm/v6, arm/v7 and arm64. `:latest` and `:v0` follow the latest release, `:v0.18` follows that minor version's patches, and `:v0.18.0` stays on that exact version.
- **From source**, with [Go](https://go.dev/doc/install): `go install github.com/miguelangel-nubla/ipv6ddns/cmd/ipv6ddns@latest`.
- **On a MikroTik router**, as a container: see [MikroTik](mikrotik.md#running-as-a-container-on-routeros).
- **In Home Assistant**, as an app: see [its documentation](../homeassistant/addon/DOCS.md).

## What discovery needs

Local discovery listens to the network and sends probes. Both need raw sockets:

- **As a binary:** run it as root, or give it the `CAP_NET_RAW` capability. `sudo setcap cap_net_raw+ep $(command -v ipv6ddns)` lets another user run it.
- **In Docker:**
  - **Use the host's network**, `network_mode: host` or `--network host`. On a Docker network of its own, the container sees none of the hosts. You don't need Docker's `"ipv6": true` in `daemon.json`: it only affects the networks Docker creates, not the host's.
  - **Keep `NET_RAW`.** Docker grants it by default, but other runtimes, or a Kubernetes `securityContext`, can drop it. Without it, discovery logs `operation not permitted`.

Without raw sockets, [plugins](discovery.md#plugins) still find hosts, by reading your routers' neighbor tables. If you only use plugins, the container needs no privileges and no host network.

On a machine that runs other containers, exclude their bridges from discovery: see [interfaces](discovery.md#interfaces).

## As a service

The packages install ipv6ddns as a service, with a starting configuration and a manual page, `man ipv6ddns`. The service is systemd's in the `.deb` and the `.rpm`, and OpenRC's in Alpine's `.apk`.

1. **Edit `/etc/ipv6ddns/config.yaml`.** Only root can read it, since it holds the credentials. As installed, it only discovers, and serves the report at `http://127.0.0.1:8053`.
2. **Start it**, now and at every boot. Installing the package starts nothing.
3. **After a change** to the configuration, restart it.

| | systemd | OpenRC, on Alpine |
|---|---|---|
| Start it, now and at every boot | `sudo systemctl enable --now ipv6ddns` | `rc-update add ipv6ddns default && rc-service ipv6ddns start` |
| Restart it | `sudo systemctl restart ipv6ddns` | `rc-service ipv6ddns restart` |
| The log | `journalctl -u ipv6ddns` | `/var/log/messages`, by syslog |

- **An upgrade** keeps your configuration, and restarts the service if it runs.
- **A removal** stops the service and leaves the configuration you changed.
- **Under systemd, the service runs as root with two capabilities only**, `CAP_NET_RAW` for discovery and `CAP_NET_BIND_SERVICE` for a [resolver](resolver.md) on port 53. The file system is read-only to it, except `/etc/ipv6ddns`, where it keeps the key Home Assistant gives it. A [`command` source](sources.md) runs inside those limits. To loosen them, use `sudo systemctl edit ipv6ddns` rather than editing the unit, which an upgrade replaces.
- **Under OpenRC, the service runs as root**, without those limits.

The packages have no repository yet, so `apt`, `dnf` and `apk` don't upgrade them by themselves: install the new release's package over the old one.

## With Docker Compose

```yaml
services:
  ipv6ddns:
    image: ghcr.io/miguelangel-nubla/ipv6ddns:v0
    network_mode: host
    restart: unless-stopped
    command:
      - "--config"
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

The health check needs to reach the web server at `127.0.0.1:8053`, so set `webserver.listen` to `8053`, `:8053` or `127.0.0.1:8053`.

The image includes `bash`, `curl`, `jq`, `dig` and `ip`, for the scripts that [command sources](sources.md) run.

To make the container a [Home Assistant](home-assistant-integration.md) device, give it the device's key yourself. Generate the key once with `openssl rand -base64 32`. Then pass it in the container's environment, as `HOMEASSISTANT_KEY: ${HOMEASSISTANT_KEY}` next to the token, and use it in the configuration:

```yaml
homeassistant:
  listen: 192.168.1.0/24    # the network Home Assistant is on
  key: ${HOMEASSISTANT_KEY}
```

This way nothing is written to disk: the configuration stays mounted read-only, and the container needs no data volume.

The alternative is `key_provisioning: true`, where Home Assistant provides the key. ipv6ddns then keeps the key in a file next to the configuration. That file disappears with the container unless its folder is a writable volume: see [the key](home-assistant-integration.md#the-key).

## Flags

| Flag | |
|---|---|
| `--config` | The configuration file, YAML or JSON. Without it: `config.yaml` in the working directory, or else `/etc/ipv6ddns/config.yaml` |
| `--live` | Show the report in the terminal, updating live, instead of the log. It needs a terminal. `q`, Esc, Ctrl-C or a signal ends it. It uses the terminal's colors, and none when `NO_COLOR` is set. Only errors that stop the start are logged, so you don't see the configuration's warnings or the plugins' errors |
| `--version` | Print the version |

Everything else is set in the [configuration file](reference/configuration.md). For example, `log_level` sets the log level, `webserver.listen` sets where the web report is served, and `discovery.lifetime` sets how long addresses last.

An unknown flag is an error. The error lists the flags that exist, as `--help` does.

To turn a boolean flag off, write `--live=false`, not `--live false`. A word that is neither a flag nor a flag's value is an error.

## The web report

`webserver.listen` says where the web report is served. It takes a list of entries, in any combination, or a single comma-separated string:

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
| `10.2.3.0/24`, `fd00::/64` | each address the machine has in that network at start, port 8053 |
| `myhost:8053`, `myhost` | every address the name resolves to, at start |

Networks and host names are resolved once, at start:

- An address the machine gets later, for example from DHCP or a new prefix, isn't listened on until a restart.
- A network with none of the machine's addresses, or a name that doesn't resolve, stops the start.
- A network entry doesn't include link-local addresses, because those need their interface. List them one by one, in the form `fe80::1%eth0`.

[`homeassistant.listen`](home-assistant-integration.md#where-it-listens) takes the same entries, with its own default port, 6053.

The report has no authentication. If you put it behind a reverse proxy, listen only on an address the proxy reaches.

The report hides:

- the credentials;
- the plugins' settings;
- the commands' arguments;
- the `urls` of http sources, except their host;
- the error messages of updates and sources.

The web server has these paths:

| Path | Serves |
|---|---|
| `/` | The report: the names and their records, the [resolvers](resolver.md), the discovered hosts with their [names](discovery.md#names), the protocols that run, and the configuration. A browser gets it as a web page with colors, in the browser's light or dark theme: red for what fails, amber for what waits or has no address, green for what works. Anything else, such as `curl`, gets the same report as text |
| `/status.txt` | The report as text, for a browser too |
| `/healthz` | `ok` while the process runs and its [resolvers](resolver.md) answer; 503, with the reason, when one doesn't. For health checks |
| `/status.json` | The same state as JSON: the names and their records, the discovered hosts with their `names`, the `protocols` that run, and the sources' runs |
| `/metrics` | Prometheus metrics. For each name: its addresses, its updates by result, and its last success. For the program itself: `go_goroutines`, `go_memstats_heap_inuse_bytes` and, on Linux, `process_open_fds`, which should all stay level over days |

## Several instances

You can run any number of instances at once, each with its own configuration file, on one machine or on several machines of a network. Each instance has its own tasks, filters, credentials, sources, lifetimes and discovery. It discovers, updates and serves exactly what it would if it ran alone.

### On one machine

Two instances on one machine must differ in anything both would claim:

| Setting | Each instance needs | Otherwise |
|---|---|---|
| [`webserver.listen`](#the-web-report) | Its own port, or address | The one started second doesn't start: `address already in use`, with the address |
| [`homeassistant`](home-assistant-integration.md#several-devices) `port`, or `listen` | Its own port, when both have the block. The default is 6053 | The same error |
| `homeassistant.key_provisioning_state_file`, with `key_provisioning: true` | Its own file. The default is `homeassistant.state` beside the configuration, so two configurations in one folder must each name theirs. Not needed with a `key` | The one started second doesn't start, and says which file |
| `homeassistant.name` | Its own name. The default is `ipv6ddns` | The one started second runs, but isn't announced to Home Assistant, and logs why |
| `--live` | Its own terminal | |

Nothing else is shared: no lock, no file, no discovery port.

- An instance that fails to start for one of these reasons has updated nothing and announced nothing.
- Stopping one instance leaves the others as they were. Its ports are free at once, and only its own device is withdrawn from Home Assistant.

The instances do share what belongs to the operating system:

- **The IPv4 neighbor table.** When one instance's sweep resolves a host, every other instance that listens for IPv4 reads that entry too. An instance without IPv4 reads none of it.
- **The answers to multicast pings.** They arrive at the machine, whichever instance sent the ping. Each instance then asks for the MAC of any host that answered, so each extra instance means one more solicitation per host, and no more.

### On several machines of one network

Each instance hears the others' probes. To each instance, the machine another instance runs on is just a host, with its real addresses at its MAC. A [`self`](filtering.md#filterself) filter only takes the instance's own machine.

- One instance's solicitations, for the EUI-64 and IPv4 addresses its own filters want, never make another instance publish anything.
- An instance never probes because of something it heard from another instance. So each one sends on the network only what it would send alone.
- A host that leaves is dropped by each instance after that instance's own lifetime.

With a `homeassistant` block, each instance needs its own [name](home-assistant-integration.md#several-devices).

### One name kept by two instances

Two instances can keep the same name at the same provider. For example, a second machine can stand in for the first when it's down. This works as long as both give the name the same addresses: the same filters, for the same hosts, on a network both discover.

An update makes a name's records exactly the addresses its instance has. It only runs when those addresses change, never just to check. So two instances that find the same addresses end up with the same records. Each writes only what's missing, and then both leave the records alone.

- **An instance that starts** writes the addresses it has found so far, and removes the ones it hasn't found yet. A single instance does the same when it restarts. Finding an address takes seconds if its host is using it, and longer if the host keeps it quiet: see [after a start](discovery.md#after-a-start).
- **A host that leaves** disappears from the name as soon as the first instance drops it, which is after the shorter of the two lifetimes.
- **Two updates at the same moment** can collide at the provider. The instance that is refused logs the error, tries again after its `retry`, and finds the records already there.

This doesn't work when the instances would give the name different addresses:

- a `self` filter, which means each instance's own machine;
- different filters or [sources](sources.md);
- hosts that only one of the instances reaches.

Nothing merges the two sets of addresses. The records are whatever was written last, and they flip whenever either instance's addresses change. To give one name the addresses of two machines, let a single instance take both, each with its own `mac` filter.

## Stopping

On SIGINT or SIGTERM, ipv6ddns stops discovering and stops scheduling updates. It gives the updates in progress up to 30 seconds to finish. A second signal during that wait stops it at once. With `--live`, a key that quits the view stops it the same way.
