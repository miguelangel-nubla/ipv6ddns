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

The add-on's own option:

| Option | |
|---|---|
| `log_level` | `debug`, `info`, `warn` or `error`. Default: `info` |

The lifetime, and everything else, are in `config.yaml`.

## The add-on's page

It shows the report of ipv6ddns: the names and their records, and the hosts
discovered. It is served to Home Assistant only, not to the network.

## Network

The add-on is on the host's network, with the `NET_RAW` capability, so that
discovery hears and probes the network as ipv6ddns on the host would. The
[plugins](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/docs/discovery.md#plugins)
read your routers' tables besides. The starting configuration leaves out the
bridges of Home Assistant's own containers, `hassio`, `docker0` and `veth*`,
with `discovery.exclude_interfaces`: keep that.
