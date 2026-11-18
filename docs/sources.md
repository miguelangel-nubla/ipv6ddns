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
          type: [global]    # the server's own IPv6, for the AAAA record
    sources: [wan]          # and the public IPv4, for the A record
    endpoints:
      cloudflare: [www]
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

`family`, for `dns` and `http`, is `[4]` by default; `[4, 6]` finds the public IPv6 too, for a network whose hosts all go out through one address.

## Runs and lifetimes

A source runs at start, then every `interval`; a `homeassistant` one also as soon as its entity changes. A run that works gives the source's addresses: one it no longer gives, as the public address before the ISP changed it, goes at once. A run that fails keeps them for their `lifetime` after the last run that gave them, so a service down for a while doesn't take the record away: the defaults are in the [reference](reference/configuration.md#sources). A static source never expires.

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

The image has the [tools](installation.md#with-docker-compose) such scripts usually need. A task's `ipv4` block, from before sources, is such a command: it still works, as a source named `<task>.ipv4`, and the log says how to move it.
