# Sources

A source gives addresses that have no MAC, so that discovery can't find: the network's public IPv4, an address a script knows. A task gets the addresses of the sources it names in its `sources`, besides those of its [filters](filtering.md). The keys are in the [reference](reference/configuration.md#sources).

## The public IPv4

With IPv4 behind NAT, a server has a private address, and the world reaches it at the router's public one, through a port forward: its A record is the network's public IPv4. A `dns` source finds it:

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
| `dns` | The public address of each of its `family`, as resolvers see it: OpenDNS's `myip.opendns.com`, or Google's `o-o.myaddr.l.google.com` when OpenDNS fails. Each query goes over its family, so it gets that family's public address |
| `http` | The same, from echo services over HTTPS: ipify, icanhazip and ident.me in order, or the `urls` you give, which answer the address alone |
| `command` | The addresses a `command`, with its `args`, prints, one per line. It runs in the configuration's directory |
| `static` | The `addresses` listed, for an address that doesn't change, or that discovery can't reach |
| `homeassistant` | The addresses in the state of a Home Assistant `entity`, or of its `attribute`: see the [Home Assistant integration](home-assistant-integration.md#an-entitys-addresses) |

A `dns` or `http` source asks its services in order until one answers, each within its share of the run's time: one that hangs doesn't keep the next from being asked, nor a family the other.

A `dns` source asks the resolvers themselves, over UDP port 53. A network that redirects outgoing DNS to a resolver of its own, as a router's rule that forces all DNS to Pi-hole or AdGuard, or some ISPs, has that resolver ask in its place, and the answer can be that resolver's address, not the network's: use `type: http` there. ipv6ddns refuses the answers it can tell were relayed, which aren't all.

An `http` source goes through the proxy of `HTTPS_PROXY`, when set: the address is then the one the proxy goes out with.

A source's addresses are published as given: ipv6ddns doesn't refuse a loopback, unspecified or multicast one from a command, a list or an entity, as discovery does.

`family`, for `dns` and `http`, is `[4]` by default; `[4, 6]` finds the public IPv6 too, for a network whose hosts all go out through one address.

## Runs and lifetimes

A source runs at start, then every `interval`; a `homeassistant` one also as soon as its entity changes. A run has the interval less a second, and a minute at most; a command still running then is killed, with what it started, and the run fails. Each run ends one of these ways:

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

A static source always gives its `addresses`: one without any is refused when the configuration is read.

A command that can't tell, as when what it asks is down, exits non-zero: a failure, which keeps the addresses. Printing nothing says there are none.

`/status.json` shows each source's runs and failures; the log, its errors.

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

It prints the addresses, one per line, and exits 0; with none to give, it prints nothing, and the addresses go. When it can't tell, as when what it asks doesn't answer, it exits non-zero, and they stay for their `lifetime`: with `set -euo pipefail`, a failing `curl` does. A line that isn't an address is an error, as `null` from `jq` of a missing field: `jq -e` exits non-zero there instead.

The image has the [tools](installation.md#with-docker-compose) such scripts usually need.
