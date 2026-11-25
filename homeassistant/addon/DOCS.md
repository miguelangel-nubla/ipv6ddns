# Home Assistant app: ipv6ddns

[ipv6ddns](https://github.com/miguelangel-nubla/ipv6ddns) gives every device
on your network a DNS name, and keeps the name right when the device's
addresses change: a new IPv6 prefix from your ISP, a new address on a device,
a new public IPv4 for the network. It finds the hosts on the network. It then
keeps their names at your DNS provider or your router, or answers them itself
as the LAN's DNS server.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/miguelangel-nubla/ipv6ddns/main/docs/images/architecture-dark.svg">
  <img src="https://raw.githubusercontent.com/miguelangel-nubla/ipv6ddns/main/docs/images/architecture-light.svg" alt="ipv6ddns, a single instance anywhere on the LAN, finds the devices on your network, such as a server, a camera, a laptop or a printer, with no software on them, and keeps a DNS name pointing at each: at your DNS provider, in your router, or in its own DNS server. When a device's address changes, its name follows: server.mydomain.com has its AAAA record move from 2001:db8:1::a to 2001:db8:2::a, and its A record from 203.0.113.7 to 203.0.113.9; and a name on the LAN too: printer.mydomain.com keeps its AAAA record, of the ULA address fd12:3456:789a::20, and has its A record move from 192.168.1.20 to 192.168.1.35.">
</picture>

Home Assistant used to call apps add-ons. This is the same thing.

## Installation

1. Add the repository of these apps to Home Assistant, as its
   [README](https://github.com/miguelangel-nubla/hassio-repository) says, and
   install ipv6ddns.
2. Start the app. It writes a starting `config.yaml` in its folder,
   `addon_configs/<id>_ipv6ddns` (`app_configs` in recent versions of Home
   Assistant), and starts discovering. Its page lists the hosts on your
   network, with their MAC addresses.
3. Edit that `config.yaml` with the File editor or Studio Code Server app,
   and restart the app.

For common setups, such as every machine on the network by name, see the
[guides for the app](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/guides/home-assistant/README.md).

## Configuration

Every setting is in `config.yaml`, as in any other install of ipv6ddns. The
app has no options of its own. The
[documentation](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/configuration.md)
of ipv6ddns describes the file.

- **Secrets.** To the app, a file next to `config.yaml` is
  `/config/<file>`. So you can keep a token out of `config.yaml`: put it in a
  file, and write `${file:/config/cloudflare_token}`.
- **The log level** is `log_level`, one of `debug`, `info`, `warn` or `error`.
  The starting configuration has it at `info`.

Keep these lines of the starting configuration. They serve the report on
[the app's page](#the-apps-page):

```yaml
webserver:
  listen: 172.30.32.1:8053
```

## Publishing Home Assistant itself

To publish Home Assistant, use `self: true` in a filter. It takes the addresses
of the machine the app runs on, which are the addresses of Home Assistant
and its apps, so there's no MAC to look up.

This example takes the machine's stable public IPv6 addresses. It adds the
network's public IPv4, for a router that forwards a port to the machine:

```yaml
sources:
  wan:
    type: dns
tasks:
  homeassistant:
    filter:
      - self: true
        ip:
          type:
            - global
            - "!temporary"
    sources:
      - wan
    endpoints:
      cloudflare:             # ha.example.com
        - ha
credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: ${file:/config/cloudflare_token}
      zone: example.com
      ttl: 1h
      proxied: false
discovery:
  exclude_interfaces:
    - hassio
    - docker0
    - "veth*"
```

The names of all your apps can be endpoints of this one task, such as `ha`,
`mqtt` and `nodered`:

- Home Assistant, and the apps on the host's network, have the host's
  addresses.
- The other apps have addresses of their own, but on `hassio`, a network
  inside the host that nothing outside reaches. From outside, they're reached
  at the host's addresses, on the ports they publish.

For a local DNS, use the machine's LAN address instead: `self: true` with `ip`
`family` `4` and `type` `private`, and `discovery.ipv4.enabled: true`. The
other filters and options are in
[filtering](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/filtering.md).

## In Home Assistant

The starting configuration makes ipv6ddns a device of Home Assistant's ESPHome
integration, with `key_provisioning: true`. Home Assistant finds the device
under *Settings → Devices & services → Discovered*. When you add it, Home
Assistant makes its encryption key and gives the key to the device, as it does
for ESPHome devices. The app keeps the key in `homeassistant.state` in its
folder, where it survives restarts and updates.

The device shows each name's addresses, its last update and any problem with
the update. It also shows the number of hosts discovered, and has a button to
update now. In the other direction, `homeassistant` sources can read your
entities, such as a router's WAN address. See the
[integration](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/home-assistant-integration.md).

## The app's page

The app's page shows the ipv6ddns report: the names and their records, and
the hosts discovered.

The report is served to Home Assistant only, not to your network. It's served
at `172.30.32.1:8053`, the address where Home Assistant's Supervisor reaches
the app. `webserver.listen` in the starting `config.yaml` sets that address.

## Network

The app runs on the host's network, with the `NET_RAW` capability. So
discovery hears and probes the network just as ipv6ddns would when run on the
host. The
[plugins](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/discovery.md#plugins)
can read your routers' tables as well.

The starting configuration leaves out the bridges of Home Assistant's own
containers, `hassio`, `docker0` and `veth*`, with
`discovery.exclude_interfaces`. Keep that setting.

## Encrypted DNS

The resolver can answer the network over DNS over TLS, HTTPS and QUIC, with a
certificate:
[encrypted DNS for the clients](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/resolver.md#encrypted-dns-for-the-clients).
The app reads Home Assistant's `ssl` folder, where the Let's Encrypt app
writes its certificates, at `/ssl`:

```yaml
resolvers:
  lan:
    listen:
      - 192.168.1.0/24
      - tls://192.168.1.0/24
    tls: home
    upstream:
      - 192.168.1.1

certificates:
  home:
    certificate: /ssl/fullchain.pem
    key: /ssl/privkey.pem
```

The certificate must be for the name the clients use, such as
`dns.lan.example.com`: ask the Let's Encrypt app for it with its DNS
challenge. Or let ipv6ddns get it and renew it itself, with
[`acme`](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/resolver.md#a-certificate-from-lets-encrypt):
it then keeps it in the app's folder. Port 443 may be taken on the Home Assistant machine, by an app
such as NGINX: give DNS over HTTPS another port, as
`https://192.168.1.2:8443`, the machine's address with the port.

## A router's updates

A [push source](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/sources.md#a-routers-updates)
takes the addresses your router sends, as to a DynDNS service, through the
web server. The starting configuration serves the web server to Home
Assistant alone: add the machine's address on the LAN, for the router to
reach it.

```yaml
webserver:
  listen:
    - 172.30.32.1:8053
    - 192.168.1.2:8053
```
