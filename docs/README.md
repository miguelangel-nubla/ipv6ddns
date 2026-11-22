# ipv6ddns documentation

ipv6ddns gives every device on your network a DNS name, wherever its addresses move: it finds the hosts, and keeps their names at your DNS provider, at your router, or answered by its own resolver. New here? The [README](../README.md) says what it does, and the [guides](guides/README.md) set up one thing each, from start to end.

## Getting started

- [Installation and running](installation.md): binaries, Docker, what discovery needs, flags, the web report, health and metrics, several instances at once.
- [Guides](guides/README.md): common setups, each whole: [every machine on the network by name](guides/network-wide-names.md).
- [Guides for the Home Assistant add-on](guides/home-assistant/README.md): the add-on's side of each.

## Configuring

- [Configuration](configuration.md): the file's structure, its parts, secrets, validation.
- [Discovery](discovery.md): how hosts are found, IPv6 and IPv4, by which protocols; the hosts' names, plugins that read your routers, interfaces, lifetimes.
- [Filtering](filtering.md): which addresses of which hosts a name gets.
- [Names by the hosts' names](hostnames.md): a name for every host, by what it is called, with `{hostname}`, `{n}` and `{mac}`.
- [Sources](sources.md): addresses without a MAC, as the network's public IPv4.
- [The resolver](resolver.md): ipv6ddns as the LAN's DNS server, with its zones, records, reverse names, cache and upstream servers.

## Home Assistant

- [The add-on](../homeassistant/addon/DOCS.md): installing it, and its configuration.
- [The integration](home-assistant-integration.md): ipv6ddns as a device in Home Assistant, and entities' states as addresses.
- [How the add-on is made](home-assistant.md).

## Platforms

- [MikroTik](mikrotik.md): RouterOS as a DNS provider, a discovery plugin, and a container host.

## Reference

- [Configuration reference](reference/configuration.md): every key, generated from the schema.
- [Providers reference](reference/providers.md): every DNS provider's settings.

## Background

- [How it works](how-it-works.md): the problem with DDNS on IPv6, and the design.
