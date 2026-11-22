# ipv6ddns

[![ci](https://github.com/miguelangel-nubla/ipv6ddns/actions/workflows/ci.yaml/badge.svg)](https://github.com/miguelangel-nubla/ipv6ddns/actions/workflows/ci.yaml)
[![release](https://img.shields.io/github/v/release/miguelangel-nubla/ipv6ddns)](https://github.com/miguelangel-nubla/ipv6ddns/releases/latest)

**DNS names for every device on your network, wherever its addresses move.**

ipv6ddns finds every host on your LAN, IPv6 and IPv4, and keeps their names: at your DNS provider, at your router, or answered by ipv6ddns itself as the LAN's DNS server. No software on the devices, no static addresses.

- **Dynamic DNS for any device.** A server, a camera, a container: found by its MAC address, and its name kept at Cloudflare, Route 53, DuckDNS and others, with the network's public IPv4 beside its IPv6. Your ISP changes the IPv6 prefix, a laptop picks a new address: `myserver.example.com` keeps working.
- **Every machine by name, with nothing set per host.** Each host is named by what it calls itself, as `printer.home.arpa` or `laptop.home.arpa`, as hosts come and go.
- **The LAN's DNS server, if you want one.** ipv6ddns answers those names itself, with records of your own and their reverse, and forwards the rest, over TLS or HTTPS if you like, with a cache.

It runs on one machine of the network, or as a [Home Assistant add-on](homeassistant/addon/DOCS.md), which also makes it a device in Home Assistant.

## What you can do with it

| You want | Start here |
|---|---|
| Every machine on the network reachable by name, from every device | [Guide: every machine on the network by name](docs/guides/network-wide-names.md) |
| A server's public name kept up to date, as its IPv6 prefix changes | [Quick start](#quick-start), then [filtering](docs/filtering.md) for which of its addresses |
| Home Assistant itself at a public name, as `ha.example.com` | [The add-on: publishing Home Assistant](homeassistant/addon/DOCS.md#publishing-home-assistant-itself) |
| The names in your router's DNS: MikroTik, OpenWrt, OPNsense, pfSense | [Your router's DNS instead](docs/guides/network-wide-names.md#your-routers-dns-instead), and the [providers](docs/reference/providers.md) |
| A DNS server for the LAN, with your own records | [The resolver](docs/resolver.md) |
| The network's public IPv4 under the same name as the IPv6 | [Sources](docs/sources.md) |

More in the [guides](docs/guides/README.md), and [for the Home Assistant add-on](docs/guides/home-assistant/README.md).

## What it looks like

The web report, or `-live` in a terminal, shows each name with its addresses and how its updates go, and every host found, with its names and how each address was seen:

```
DNS: 3 names, 3 with addresses, 0 without; 0 failing
    Provider: cloudflare
        Endpoint: cloudflare
            www.example.com: (last update: 2026-01-25T01:49:35Z)
                [2001:db8:1234:5678:abcd:ef01:2345:6789]   35m15s    2d 5h        12:34:56:78:90:ab  eth0, router
                203.0.113.99                               27m 2s       9h14m     source wan
    Provider: technitium
        Endpoint: home-dns
            nas.home.example.com: (next update: 7s, waiting for the 10s debounce)
                192.168.1.50                                2m51s   12d           00:11:22:33:44:55  eth0
                [fd12:3456:789a::50]                       41m37s   12d           00:11:22:33:44:55  eth0
Discovery: 2 hosts, 1 named, 3 addresses
    00:11:22:33:44:55
        names:
            nas                                      3h59m12s   12d
                mdns on eth0                         3h59m12s   12d
                reported by router from leases       3h51m 7s    3d 4h
        addresses:
            192.168.1.50                                2m51s   12d
                arp:answered on eth0                    2m51s   12d
                reported by router from leases        (lease)    3d 4h
            fd12:3456:789a::50                         41m37s   12d
                ndp:answered on eth0                   41m37s   12d
                mdns:announced on eth0                 38m 5s       6h20m
```

Each time is how long the address has left, then how long it has been seen. The same is at `/status.json`, and as Prometheus metrics at `/metrics`.

## How it works

1. **Discovery** finds the hosts of the network and their addresses, by MAC: listening to the network, probing it, and reading your routers' tables. IPv6, and local IPv4. It learns what each host is called, from mDNS, DHCP, NetBIOS and others.
2. **Tasks** give names addresses. A task's filters choose them: this MAC, global addresses only, the stable one. A task's name can be a template, `{hostname}`, for a name for every host it matches.
3. **Sources** add addresses that have no MAC: the network's public IPv4, a command's output, a Home Assistant entity.
4. **The names are kept** wherever you say, as the addresses change: at DNS providers and routers, Cloudflare, Route 53, DuckDNS, MikroTik, OpenWrt, pfSense, OPNsense, Technitium, Windows DNS, Gravity; or in a zone of ipv6ddns's own [resolver](docs/resolver.md), which the LAN asks.

[Why this design](docs/how-it-works.md): the problem with DDNS on IPv6, and what else it does, as roaming over several ISPs.

## Quick start

A `config.yaml`, for one server's global addresses at Cloudflare:

```yaml
webserver:
  listen: 127.0.0.1:8053

tasks:
  webserver:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
        ip:
          type:
            - global
    endpoints:
      cloudflare:
        - www           # www.example.com

credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: ${CLOUDFLARE_TOKEN}
      zone: example.com
      ttl: 1h
      proxied: false
```

Run it with Docker as the [installation](docs/installation.md#with-docker-compose) says, on the host's network, with `CLOUDFLARE_TOKEN` in its environment; the report is then at `http://127.0.0.1:8053`. Or pick a [guide](docs/guides/README.md) for a whole setup.

## Install

- **Binaries** for Linux, macOS, FreeBSD and the other BSDs, on the [releases](https://github.com/miguelangel-nubla/ipv6ddns/releases). Discovery listens to the network, so it needs [a few rights](docs/installation.md#what-discovery-needs).
- **Docker**: `ghcr.io/miguelangel-nubla/ipv6ddns`, on the host's network. See [installation](docs/installation.md).
- **Home Assistant**: [the add-on](homeassistant/addon/DOCS.md).

## Documentation

The whole map is in [docs](docs/README.md).

| | |
|---|---|
| **Getting started** | |
| [Installation and running](docs/installation.md) | Binaries, Docker, flags, the web report, health and metrics, several instances at once |
| [Guides](docs/guides/README.md) | Common setups from start to end; and [for the Home Assistant add-on](docs/guides/home-assistant/README.md) |
| **Configuring** | |
| [Configuration](docs/configuration.md) | The file's structure, secrets, validation |
| [Filtering](docs/filtering.md) | Choosing the addresses of a name |
| [Discovery](docs/discovery.md) | How hosts are found: IPv6 and IPv4, the protocols, the hosts' names, plugins, interfaces, lifetimes |
| [Names by the hosts' names](docs/hostnames.md) | A name for every host of the LAN, by what it is called: `{hostname}`, `{n}`, `{mac}` |
| [Sources](docs/sources.md) | The public IPv4, and addresses without a MAC |
| [Resolver](docs/resolver.md) | ipv6ddns as the LAN's DNS server: its zones, records, and what it forwards |
| **Home Assistant** | |
| [The add-on](homeassistant/addon/DOCS.md) | Installing it, its configuration, and [how it is made](docs/home-assistant.md) |
| [The integration](docs/home-assistant-integration.md) | ipv6ddns as a device in Home Assistant, and entities' states as addresses |
| **Platforms** | |
| [MikroTik](docs/mikrotik.md) | RouterOS as a DNS provider, a discovery plugin, and a container host |
| **Reference** | |
| [Configuration reference](docs/reference/configuration.md) | Every key, generated from the schema |
| [Providers reference](docs/reference/providers.md) | Every provider's settings |
| **Background** | |
| [How it works](docs/how-it-works.md) | The problem, and the design |

Host discovery is the [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc) library, which works on its own too.

Contributing, as adding a DNS provider: [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).
