# Home Assistant add-on: ipv6ddns

[ipv6ddns](https://github.com/miguelangel-nubla/ipv6ddns) finds the devices of
your network by their MAC address, and keeps their names at your DNS providers
as their addresses change: your ISP's new IPv6 prefix, a device's new address,
the network's public IPv4.

## Installation

1. Add the repository of these add-ons to Home Assistant, as its
   [README](https://github.com/miguelangel-nubla/hassio-repository) says, and
   install ipv6ddns.
2. Start it. It writes a starting `config.yaml` in its folder,
   `addon_configs/<id>_ipv6ddns`, called `app_configs` in recent versions of
   Home Assistant, and discovers: its page lists the hosts of the network and
   their MAC addresses.
3. Edit that `config.yaml`, with the File editor or Studio Code Server add-on,
   and restart the add-on.

## Configuration

`config.yaml` is the configuration of ipv6ddns, as its
[documentation](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/configuration.md)
says. A file beside it is `/config/<file>` for the add-on: keep a token out of
`config.yaml` with `${file:/config/cloudflare_token}`.

Every setting is there, as in any other install of ipv6ddns: the add-on has no
options of its own. How much the log says is `log_level` in `config.yaml`,
`debug`, `info`, `warn` or `error`: the starting configuration has it at
`info`. And these lines of it serve the report for [the add-on's
page](#the-add-ons-page): keep them.

```yaml
webserver:
  listen: 172.30.32.1:8053
```

## Publishing Home Assistant itself

`self: true` in a filter takes the addresses of the machine the add-on runs
on: Home Assistant's, and its add-ons', with no MAC to look up. Its stable
public IPv6 addresses, and the network's public IPv4 for a router that
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
          type: [global, "!temporary"]
    sources: [wan]
    endpoints:
      cloudflare: [ha]        # ha.example.com
credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: ${file:/config/cloudflare_token}
      zone: example.com
      ttl: 1h
      proxied: false
discovery:
  exclude_interfaces: [hassio, docker0, "veth*"]
```

Home Assistant, and the add-ons on the host's network, have the host's
addresses. The other add-ons have addresses of their own, but on a network
inside the host, `hassio`, which nothing outside reaches: they are reached at
the host's addresses, on the ports they publish. So the names of all of them
are endpoints of this one task: `[ha, mqtt, nodered]`.

For
a local DNS, its LAN address: `self: true` with `ip: {family: [4], type:
[private]}`, and `discovery: {ipv4: {enabled: true}}`. The other filters and options:
[filtering](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/filtering.md).

## In Home Assistant

The starting configuration makes ipv6ddns a device of Home Assistant's ESPHome
integration, with `key_provisioning: true`: Home Assistant finds it under
*Settings → Devices & services → Discovered*. Add it: Home Assistant makes its
encryption key and gives it, as to ESPHome's devices, and the add-on keeps it in
`homeassistant.state` in its folder, which stays through restarts and updates.
It shows each name's addresses,
last update and update problems, and the hosts discovered, with a button to
update now; and `homeassistant` sources read your entities, as a router's WAN
address. See the
[integration](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/home-assistant-integration.md).

A `config.yaml` from before `key_provisioning`, up to v0.22.3, has
`homeassistant: {}`, and the add-on doesn't start with it: its log says the
device needs its key, and then that it needs `listen`. The add-on leaves your `config.yaml` as it is: change
those lines yourself, to

```yaml
homeassistant:
  listen: 6053
  key_provisioning: true
```

and restart the add-on. It reads the `homeassistant.state` it has: the device,
its key and its entities stay as they were in Home Assistant.

## The add-on's page

It shows the report of ipv6ddns: the names and their records, and the hosts
discovered. It is served to Home Assistant only, not to the network: at
`172.30.32.1:8053`, the address Home Assistant's Supervisor reaches the add-on
at, which `webserver.listen` in the starting `config.yaml` says.

A `config.yaml` from up to v0.22.3 doesn't have those lines: the add-on gave
the address itself then, and took the level of the log from an option of its
own, which is gone. With such a file the add-on still runs, and updates your
names, but its page in Home Assistant shows an error, as nothing serves it. The add-on leaves your `config.yaml` as it is: add these
lines to it yourself, at the top level, as `tasks` is,

```yaml
webserver:
  listen: 172.30.32.1:8053
```

and restart the add-on. If the log level option was not `info`, add
`log_level: debug`, or the level it had, the same way.

## Network

The add-on is on the host's network, with the `NET_RAW` capability, so that
discovery hears and probes the network as ipv6ddns on the host would. The
[plugins](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/discovery.md#plugins)
read your routers' tables besides. The starting configuration leaves out the
bridges of Home Assistant's own containers, `hassio`, `docker0` and `veth*`,
with `discovery.exclude_interfaces`: keep that.
