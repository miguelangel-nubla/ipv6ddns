# Home Assistant add-on: ipv6ddns

[ipv6ddns](https://github.com/miguelangel-nubla/ipv6ddns) gives every device
on your network a DNS name, and keeps the name right when the device's
addresses change: a new IPv6 prefix from your ISP, a new address on a device,
a new public IPv4 for the network. It finds the hosts on the network. It then
keeps their names at your DNS provider or your router, or answers them itself
as the LAN's DNS server.

## Installation

1. Add the repository of these add-ons to Home Assistant, as its
   [README](https://github.com/miguelangel-nubla/hassio-repository) says, and
   install ipv6ddns.
2. Start the add-on. It writes a starting `config.yaml` in its folder,
   `addon_configs/<id>_ipv6ddns` (`app_configs` in recent versions of Home
   Assistant), and starts discovering. Its page lists the hosts on your
   network, with their MAC addresses.
3. Edit that `config.yaml` with the File editor or Studio Code Server add-on,
   and restart the add-on.

For common setups, such as every machine on the network by name, see the
[guides for the add-on](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/guides/home-assistant/README.md).

## Configuration

Every setting is in `config.yaml`, as in any other install of ipv6ddns. The
add-on has no options of its own. The
[documentation](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/configuration.md)
of ipv6ddns describes the file.

- **Secrets.** To the add-on, a file next to `config.yaml` is
  `/config/<file>`. So you can keep a token out of `config.yaml`: put it in a
  file, and write `${file:/config/cloudflare_token}`.
- **The log level** is `log_level`, one of `debug`, `info`, `warn` or `error`.
  The starting configuration has it at `info`.

Keep these lines of the starting configuration. They serve the report on
[the add-on's page](#the-add-ons-page):

```yaml
webserver:
  listen: 172.30.32.1:8053
```

## Publishing Home Assistant itself

To publish Home Assistant, use `self: true` in a filter. It takes the addresses
of the machine the add-on runs on, which are the addresses of Home Assistant
and its add-ons, so there's no MAC to look up.

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

The names of all your add-ons can be endpoints of this one task, such as `ha`,
`mqtt` and `nodered`:

- Home Assistant, and the add-ons on the host's network, have the host's
  addresses.
- The other add-ons have addresses of their own, but on `hassio`, a network
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
for ESPHome devices. The add-on keeps the key in `homeassistant.state` in its
folder, where it survives restarts and updates.

The device shows each name's addresses, its last update and any problem with
the update. It also shows the number of hosts discovered, and has a button to
update now. In the other direction, `homeassistant` sources can read your
entities, such as a router's WAN address. See the
[integration](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/home-assistant-integration.md).

## The add-on's page

The add-on's page shows the ipv6ddns report: the names and their records, and
the hosts discovered.

The report is served to Home Assistant only, not to your network. It's served
at `172.30.32.1:8053`, the address where Home Assistant's Supervisor reaches
the add-on. `webserver.listen` in the starting `config.yaml` sets that address.

## Network

The add-on runs on the host's network, with the `NET_RAW` capability. So
discovery hears and probes the network just as ipv6ddns would when run on the
host. The
[plugins](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/discovery.md#plugins)
can read your routers' tables as well.

The starting configuration leaves out the bridges of Home Assistant's own
containers, `hassio`, `docker0` and `veth*`, with
`discovery.exclude_interfaces`. Keep that setting.
