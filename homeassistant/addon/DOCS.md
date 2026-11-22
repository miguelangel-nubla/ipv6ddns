# Home Assistant add-on: ipv6ddns

[ipv6ddns](https://github.com/miguelangel-nubla/ipv6ddns) gives every device
on your network a DNS name, wherever its addresses move: your ISP's new IPv6
prefix, a device's new address, the network's public IPv4. It finds the hosts,
and keeps their names at your DNS provider or your router, or answers them
itself as the LAN's DNS server.

## Installation

1. Add the repository of these add-ons to Home Assistant, as its
   [README](https://github.com/miguelangel-nubla/hassio-repository) says, and
   install ipv6ddns.
2. Start it. It writes a starting `config.yaml` in its folder,
   `addon_configs/<id>_ipv6ddns` (`app_configs` in recent versions of Home
   Assistant), and starts discovering: its page lists the hosts on your
   network, with their MAC addresses.
3. Edit that `config.yaml` with the File editor or Studio Code Server add-on,
   and restart the add-on.

For common setups, such as every machine on the network by name, see the
[guides for the add-on](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/guides/home-assistant/README.md).

## Configuration

`config.yaml` is the configuration of ipv6ddns, as its
[documentation](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/configuration.md)
describes. To the add-on, a file next to it is `/config/<file>`, so you can
keep a token out of `config.yaml` with `${file:/config/cloudflare_token}`.

Every setting is in `config.yaml`, as in any other install of ipv6ddns: the
add-on has no options of its own. The log level is `log_level` there, one of
`debug`, `info`, `warn` or `error`, and the starting configuration has it at
`info`. Keep these lines of it, which serve the report on
[the add-on's page](#the-add-ons-page):

```yaml
webserver:
  listen: 172.30.32.1:8053
```

## Publishing Home Assistant itself

`self: true` in a filter takes the addresses of the machine the add-on runs on,
which are Home Assistant's and its add-ons', with no MAC to look up. Here, its
stable public IPv6 addresses, plus the network's public IPv4, for a router that
forwards a port to it:

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

Home Assistant, and the add-ons on the host's network, have the host's
addresses. The other add-ons have addresses of their own, but on `hassio`, a
network inside the host that nothing outside reaches: they're reached at the
host's addresses, on the ports they publish. So all their names can be
endpoints of this one task, as `ha`, `mqtt` and `nodered`.

For a local DNS, use its LAN address instead: `self: true` with `ip` `family`
`4` and `type` `private`, and `discovery.ipv4.enabled: true`. The other filters
and options are in
[filtering](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/filtering.md).

## In Home Assistant

The starting configuration makes ipv6ddns a device of Home Assistant's ESPHome
integration, with `key_provisioning: true`. Home Assistant finds it under
*Settings → Devices & services → Discovered*. When you add it, Home Assistant
makes its encryption key and gives it to the device, as it does for ESPHome
devices. The add-on keeps the key in `homeassistant.state` in its folder, which
survives restarts and updates.

The device shows each name's addresses, last update and update problems, and
the number of hosts discovered, with a button to update now. And
`homeassistant` sources can read your entities, such as a router's WAN address.
See the
[integration](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/home-assistant-integration.md).

## The add-on's page

It shows the ipv6ddns report: the names and their records, and the hosts
discovered. It's served to Home Assistant only, not to your network: at
`172.30.32.1:8053`, the address Home Assistant's Supervisor reaches the add-on
at, as `webserver.listen` in the starting `config.yaml` says.

## Network

The add-on runs on the host's network, with the `NET_RAW` capability, so
discovery hears and probes the network as ipv6ddns would on the host. The
[plugins](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/discovery.md#plugins)
can read your routers' tables as well. The starting configuration leaves out
the bridges of Home Assistant's own containers, `hassio`, `docker0` and
`veth*`, with `discovery.exclude_interfaces`: keep that.
