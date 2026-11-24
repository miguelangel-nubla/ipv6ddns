# ipv6ddns documentation

ipv6ddns gives every device on your network a DNS name that follows the device as its addresses change. It finds the hosts, and keeps their names up to date at your DNS provider, at your router, or in its own resolver.

New here? The [README](../README.md) explains what ipv6ddns does. Each [guide](guides/README.md) sets up one thing, from start to end.

## Getting started

- [Installation and running](installation.md): binaries, Docker, what discovery needs, flags, the web report, health and metrics, several instances at once.
- [Guides](guides/README.md): complete common setups, such as [every machine on the network by name](guides/network-wide-names.md) and [a public name for any device, over IPv6](guides/public-ipv6-names.md). With [AdGuard Home](guides/adguard-home.md) or [Pi-hole](guides/pi-hole.md), ipv6ddns writes the names into the one you already run.
- [Guides for the Home Assistant app](guides/home-assistant/README.md): what changes in each guide when ipv6ddns runs as the app.

## Configuring

- [Configuration](configuration.md): the file's structure, its parts, secrets, validation.
- [Discovery](discovery.md): how hosts are found over IPv6 and IPv4, and by which protocols. Also the hosts' names, the plugins that read your routers, interfaces, and lifetimes.
- [Filtering](filtering.md): which addresses of which hosts a name gets.
- [Names by the hosts' names](hostnames.md): a name for every host, from what the host calls itself, with `{hostname}`, `{n}` and `{mac}`.
- [Sources](sources.md): addresses without a MAC, such as the network's public IPv4.
- [The resolver](resolver.md): ipv6ddns as the LAN's DNS server, with its zones, records, reverse names, cache and upstream servers.

## Home Assistant

- [The app](../homeassistant/addon/DOCS.md): installing it, and its configuration.
- [The integration](home-assistant-integration.md): ipv6ddns as a device in Home Assistant, and entity states used as addresses.
- [How the app is built](home-assistant.md).

## Platforms

- [MikroTik](mikrotik.md): RouterOS as a DNS provider, a discovery plugin, and a container host.

## Reference

- [Configuration reference](reference/configuration.md): every key, generated from the schema.
- [Providers reference](reference/providers.md): every DNS provider's settings.

## Background

- [How it works](how-it-works.md): the problem with DDNS on IPv6, and how the design solves it.
