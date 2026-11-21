# Network wide IPv6 DDNS Updater

[![ci](https://github.com/miguelangel-nubla/ipv6ddns/actions/workflows/ci.yaml/badge.svg)](https://github.com/miguelangel-nubla/ipv6ddns/actions/workflows/ci.yaml)
[![release](https://img.shields.io/github/v/release/miguelangel-nubla/ipv6ddns)](https://github.com/miguelangel-nubla/ipv6ddns/releases/latest)

`ipv6ddns` keeps DNS records pointing at the devices of your network, wherever their addresses move. It runs on one machine, finds every device by its MAC address, and updates their names at your DNS providers: a Dynamic DNS client for your **entire** network, with no software on the devices.

> [!TIP]
> Your ISP changes your IPv6 prefix, a laptop picks a new address, a camera can't run a DDNS client: `myserver.example.com` keeps working.

```
DNS:
    Provider: cloudflare
        Endpoint: cloudflare
            www.example.com: (last update: 2026-01-25T01:49:35Z)
                [2001:db8:1234:5678:abcd:ef01:2345:6789] from 12:34:56:78:90:ab seen over eth0,router
                203.0.113.99 from source wan
    Provider: technitium
        Endpoint: home-dns
            nas.home.example.com: (last update: 2026-01-25T01:22:03Z)
                192.168.1.50 from 00:11:22:33:44:55 seen over eth0
                [fd12:3456:789a::50] from 00:11:22:33:44:55 seen over eth0
Discovery:
    00:11:22:33:44:55
        192.168.1.50 2m51s eth0
        fd12:3456:789a::50 41m37s eth0
    12:34:56:78:90:ab
        2001:db8:1234:5678:abcd:ef01:2345:6789 35m15s eth0,router
```

## How it works

1. **Discovery** finds the addresses of the hosts on the network, by MAC: listening to the network, probing it, and reading the neighbor tables of your routers. IPv6, and local IPv4 too.
2. **Tasks** choose, with filters, the addresses of each name: this MAC, global addresses only, the stable one.
3. **Sources** add addresses without a MAC: the network's public IPv4, the output of a command.
4. **Providers** get the names' records updated as the addresses change: Cloudflare, Route 53, DuckDNS, Mikrotik, OpenWrt, pfSense, OPNsense, Technitium, Windows DNS, Gravity.

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

Run it with Docker as the [installation](docs/installation.md#with-docker-compose) says, on the host's network, with `CLOUDFLARE_TOKEN` in its environment; the report is then at `http://127.0.0.1:8053`.

## Documentation

| | |
|---|---|
| [Installation and running](docs/installation.md) | Binaries, Docker, flags, the web report, health and metrics, several instances at once |
| [Configuration](docs/configuration.md) | The file's structure, secrets, validation, and what changed for a configuration from v0.22.3 |
| [Filtering](docs/filtering.md) | Choosing the addresses of a name |
| [Discovery](docs/discovery.md) | How hosts are found: IPv6 and IPv4, the protocols, the hosts' names, plugins, interfaces, lifetimes |
| [Names by the hosts' names](docs/hostnames.md) | A name in DNS for every host of the LAN, by what it is called: `{hostname}`, `{n}`, `{mac}` |
| [Sources](docs/sources.md) | The public IPv4, and addresses without a MAC |
| [Resolver](docs/resolver.md) | ipv6ddns as the LAN's DNS server: its zones, records, and what it forwards |
| [Home Assistant](homeassistant/addon/DOCS.md) | The add-on, and [how it is made](docs/home-assistant.md) |
| [Home Assistant integration](docs/home-assistant-integration.md) | ipv6ddns as a device in Home Assistant, and entities' states as addresses |
| [Mikrotik](docs/mikrotik.md) | RouterOS as a DNS provider, a discovery plugin, and a container host |
| [Configuration reference](docs/reference/configuration.md) | Every key, generated from the schema |
| [Providers reference](docs/reference/providers.md) | Every provider's settings |
| [How it works](docs/how-it-works.md) | The problem, and the design |

Host discovery is the [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc) library, which works on its own too.

Contributing, as adding a DNS provider: [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).
