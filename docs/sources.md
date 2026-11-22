# Sources

A source gives addresses that have no MAC, which discovery therefore can't find. Examples are the network's public IPv4, or an address that a script knows. A task gets the addresses of the sources it names in its `sources`, in addition to the addresses its [filters](filtering.md) choose. The keys are in the [reference](reference/configuration.md#sources).

## The public IPv4

Behind IPv4 NAT, a server has a private address. The internet reaches the server at the router's public address, through a port forward. So the server's A record must be the network's public IPv4. A `dns` source finds that address:

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
| `dns` | The network's public address for each `family`, as public resolvers see it. It asks OpenDNS for `myip.opendns.com`, or Google for `o-o.myaddr.l.google.com` if OpenDNS fails. Each query goes out over its own family, so it gets that family's public address |
| `http` | The same public address, from echo services over HTTPS. It asks ipify, icanhazip and ident.me in turn, or the `urls` you give, which must answer with the address alone |
| `command` | The addresses that a `command`, run with its `args`, prints one per line. The command runs in the configuration's directory |
| `static` | The `addresses` you list. Use it for an address that doesn't change, or that discovery can't reach |
| `homeassistant` | The addresses in the state of a Home Assistant `entity`, or of its `attribute`: see the [Home Assistant integration](home-assistant-integration.md#an-entitys-addresses) |

A `dns` or `http` source asks its services in order until one answers. Each service gets its share of the run's time. So a service that hangs doesn't stop the next one from being asked, and one family doesn't hold up the other.

A `dns` source asks the public resolvers directly, over UDP port 53. Some networks redirect all outgoing DNS to a resolver of their own, for example with a router rule that forces DNS through Pi-hole or AdGuard. Some ISPs do the same. That resolver then asks on the source's behalf, and the answer can be the resolver's address instead of the network's. On such a network, use `type: http`. ipv6ddns refuses the answers it can tell were relayed, but it can't always tell.

An `http` source goes through the `HTTPS_PROXY` proxy when that variable is set. The address it finds is then the one the proxy goes out from.

A source's addresses are published as given. Discovery refuses loopback, unspecified and multicast addresses, but a source doesn't: such an address from a command, a list or an entity is published.

For `dns` and `http`, `family` is `[4]` by default. `[4, 6]` also finds the public IPv6, for a network whose hosts all go out through one address.

## Runs and lifetimes

A source runs at start, and then every `interval`. A `homeassistant` source also runs as soon as its entity changes.

A run may take up to the interval minus a second, and a minute at most. A command that is still running then is killed, along with anything it started, and the run fails.

Each run ends in one of these ways:

| A run | The source's addresses | The log |
|---|---|---|
| **Works** | The source has the addresses the run gives. An address it no longer gives goes at once, such as the public address from before the ISP changed it. If the run gives none, the source has none, and a name with no other address loses its record | — |
| **Fails** | Each address is kept for its `lifetime` after the last run that gave it. So a service that is down for a while doesn't take the record away | An error, each run |
| **Fails in part**, such as one `family` of two, or one line of a command's output that isn't an address | The addresses the run gives are added, and the others are kept for their `lifetime`. A name can have both the old address and the new one until the old one expires | An error, each run |
| **Waits**, `homeassistant` only | The addresses are kept for their `lifetime`, as after a failure, while Home Assistant restarts | A line when the wait starts and when it ends, and a warning if the wait outlasts the lifetime |

The defaults of `interval` and `lifetime` are in the [reference](reference/configuration.md#sources). A static source never expires.

A run that gives no address means different things for different sources:

| Source | Gives no address when | Which counts as |
|---|---|---|
| `command` | The command exits 0 and prints nothing, or only blank lines | No addresses: the old ones go at once |
| `homeassistant` | The state is empty, such as a cleared `input_text` | No addresses: the old ones go at once |
| | The state is `unknown` or `unavailable`, an attribute is `None`, which means it has no value, or Home Assistant isn't connected | A wait |
| `http`, `dns` | The service doesn't answer with an address | A failure. A network always has a public address, so a missing answer is the service's fault |

A static source always gives its `addresses`. A static source without any is refused when the configuration is read.

A command that can't tell what the addresses are, for example because the service it asks is down, should exit non-zero. That's a failure, which keeps the addresses. Printing nothing means there are none.

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

What the script must do:

- **With addresses to give:** print them, one per line, and exit 0.
- **With none to give:** print nothing and exit 0. The addresses go.
- **When it can't tell**, for example because the service it asks doesn't answer: exit non-zero. The addresses stay for their `lifetime`. With `set -euo pipefail`, a failing `curl` does that for you.

A line that isn't an address is an error. One example is the `null` that `jq` prints for a missing field. Use `jq -e`, which exits non-zero there instead.

The image has the [tools](installation.md#with-docker-compose) such scripts usually need.
