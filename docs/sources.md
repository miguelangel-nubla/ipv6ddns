# Sources

A source gives addresses that have no MAC, which discovery therefore can't find: the network's public IPv4, or an address a script knows. A task gets the addresses of the sources it names in its `sources`, in addition to those of its [filters](filtering.md). The keys are in the [reference](reference/configuration.md#sources).

## The public IPv4

Behind IPv4 NAT, a server has a private address, and the internet reaches it at the router's public address, through a port forward. So its A record must be the network's public IPv4. A `dns` source finds it:

```yaml
sources:
  wan:
    type: dns
tasks:
  web:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
        ip:
          type:             # the server's own IPv6, for the AAAA record
            - global
    sources:                # and the public IPv4, for the A record
      - wan
    endpoints:
      cloudflare:
        - www
credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: ${CLOUDFLARE_TOKEN}
      zone: example.com
      ttl: 1h
      proxied: false
```

## Types

| Type | Gives |
|---|---|
| `dns` | The network's public address for each `family`, as public resolvers see it: OpenDNS's `myip.opendns.com`, or Google's `o-o.myaddr.l.google.com` if OpenDNS fails. Each query goes out over its own family, so it gets that family's public address |
| `http` | The same, from echo services over HTTPS: ipify, icanhazip and ident.me in turn, or the `urls` you give, which must answer with the address alone |
| `command` | The addresses a `command`, with its `args`, prints, one per line. It runs in the configuration's directory |
| `static` | The `addresses` listed, for an address that doesn't change, or that discovery can't reach |
| `homeassistant` | The addresses in the state of a Home Assistant `entity`, or of its `attribute`: see the [Home Assistant integration](home-assistant-integration.md#an-entitys-addresses) |

A `dns` or `http` source asks its services in order until one answers, each within its share of the run's time. So a service that hangs doesn't stop the next one being asked, and one family doesn't hold up the other.

A `dns` source asks the public resolvers directly, over UDP port 53. Some networks redirect all outgoing DNS to a resolver of their own: a router rule that forces DNS through Pi-hole or AdGuard, or some ISPs. Then that resolver asks on its behalf, and the answer can be the resolver's address instead of the network's. Use `type: http` there. ipv6ddns refuses answers it can tell were relayed, but it can't always tell.

An `http` source goes through the `HTTPS_PROXY` proxy when it's set, and the address found is then the one the proxy goes out from.

A source's addresses are published as given. Unlike discovery, ipv6ddns doesn't refuse a loopback, unspecified or multicast address from a command, a list or an entity.

For `dns` and `http`, `family` is `[4]` by default. `[4, 6]` finds the public IPv6 too, for a network whose hosts all go out through one address.

## Runs and lifetimes

A source runs at start and then every `interval`; a `homeassistant` source also runs as soon as its entity changes. A run has the interval minus a second, and a minute at most. A command still running then is killed, along with anything it started, and the run fails. Each run ends in one of these ways:

| A run | The source's addresses | The log |
|---|---|---|
| **Works** | Those it gives now. One it no longer gives, as the public address before the ISP changed it, goes at once; with none, the source has none, and a name that has no other loses its record | — |
| **Fails** | Kept for their `lifetime` after the last run that gave them, so a service down for a while doesn't take the record away | An error, each run |
| **Fails for a part**, as one `family` of two, or a line of a command's that isn't an address | Those it gives are added, and the others kept for their `lifetime`: a name can have the old address and the new until the old expires | An error, each run |
| **Waits**, `homeassistant` only | Kept for their `lifetime`, as through a failure, while Home Assistant restarts | When the wait starts and ends; a warning if it outlasts the lifetime |

The defaults of `interval` and `lifetime` are in the [reference](reference/configuration.md#sources). A static source never expires.

What a run that gives no address means, by source:

| Source | Gives no address when | That is |
|---|---|---|
| `command` | The command exits 0 and prints nothing, or blank lines | None: the addresses go at once |
| `homeassistant` | The state is empty, as an `input_text` cleared | None: the addresses go at once |
| | The state is `unknown` or `unavailable`, an attribute is `None`, without a value, or Home Assistant isn't connected | A wait |
| `http`, `dns` | The service doesn't answer with an address | A failure: a network always has a public address, so no answer is the service's |

A static source always gives its `addresses`; one without any is refused when the configuration is read.

A command that can't tell, as when what it asks is down, should exit non-zero. That's a failure, which keeps the addresses. Printing nothing means there are none.

`/status.json` shows each source's runs and failures, and the log shows its errors.

## A script of yours

For anything else, a command source runs your script:

```yaml
sources:
  from-the-router:
    type: command
    command: ./wan_address.sh
    interval: 1m
    lifetime: 5m
```

The script prints the addresses, one per line, and exits 0. With none to give, it prints nothing, and the addresses go. When it can't tell, as when what it asks doesn't answer, it exits non-zero, and the addresses stay for their `lifetime`; with `set -euo pipefail`, a failing `curl` does that for you. A line that isn't an address is an error, such as the `null` that `jq` prints for a missing field: `jq -e` exits non-zero there instead.

The image has the [tools](installation.md#with-docker-compose) such scripts usually need.
