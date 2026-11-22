# Every machine on the network by name, from Home Assistant

The Home Assistant machine is always on, and already on the network, so it makes a good DNS server for it: the add-on answers `nas.home.arpa`, `printer.home.arpa`, and Home Assistant's own name, for every device on the network.

This page is the add-on's side of [every machine on the network by name](../network-wide-names.md): the configuration as the add-on's file has it, and how to check it from Home Assistant. Pointing the network at it is the same as anywhere, and comes back to that guide. The steps every add-on guide shares are [here](README.md#the-add-ons-side-for-every-guide).

## The configuration

This is the whole `config.yaml`: the starting file's blocks, with the guide's added into them. The examples use `192.168.1.0/24` for the LAN, `192.168.1.1` for the router, and `192.168.1.2` for the Home Assistant machine. Use your own.

```yaml
resolvers:
  lan:
    listen:
      - 192.168.1.0/24     # Home Assistant's address on the LAN, port 53
      - 172.30.32.1        # and on the internal network, for Home Assistant and its add-ons
    upstream:
      - 192.168.1.1        # the rest of the world's names: your router, or 1.1.1.1

credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa

tasks:
  lan:
    filter:
      - ip:
          family:
            - 4
            - 6
          type:
            - "!link_local"
    endpoints:
      home:
        - "{hostname}"     # printer.home.arpa
        - "{n}.{hostname}" # 1.printer.home.arpa, 2.printer.home.arpa when two say printer
  homeassistant:
    filter:
      - self: true         # this machine: Home Assistant, and the add-ons on its network
        ip:
          family:
            - 4
            - 6
          type:
            - "!link_local"
    endpoints:
      home:
        - homeassistant    # homeassistant.home.arpa

# From the starting file: keep these.
webserver:
  listen: 172.30.32.1:8053

log_level: info

homeassistant:
  listen: 6053
  key_provisioning: true

discovery:
  ipv4:
    enabled: true          # added: the IPv4 addresses too
  exclude_interfaces:
    - hassio
    - docker0
    - "veth*"
```

What the add-on adds to the plain guide's:

- **The `homeassistant` task** names Home Assistant itself. `self: true` takes the addresses of the machine the add-on runs on, so it doesn't depend on Home Assistant saying its name. The add-ons on the host's network, as Mosquitto or Node-RED, are at the same addresses: add their names under the same endpoint, as `mqtt`, if you want them.
- **`discovery.ipv4`** goes into the `discovery` block the file already has, beside `exclude_interfaces`.
- **No `webserver` of its own.** The guide's web report is the add-on's page here, which the starting file's `webserver` block already serves.

The resolver listens on port 53 at two addresses: Home Assistant's on the LAN, for the devices, and `172.30.32.1` on its internal network, for Home Assistant and the add-ons. The Supervisor's own DNS is at `172.30.32.3`, so the two don't get in each other's way. `allow` is left out: it defaults to the networks of both addresses.

Restart the add-on. Its *Log* says `resolver lan listening on 192.168.1.2:53, 172.30.32.1:53`.

Home Assistant also announces itself as `homeassistant` over mDNS, so the `lan` task may find it called so. The name written in the `homeassistant` task wins, and the log says it once: `homeassistant.home.arpa is written in the configuration, so it keeps its own addresses`. That is expected.

## Point the network at it

Give the devices the Home Assistant machine's address as their DNS server, in the router's DHCP settings, as the plain guide says: [point the network at it](../network-wide-names.md#point-the-network-at-it).

## Point Home Assistant at it

Home Assistant and its add-ons look names up through the Supervisor's DNS, on the internal network. It asks the machine's DNS servers, unless it's been given servers of its own. Point it at the add-on, so that an integration set up by host name, as `printer.home.arpa`, works as it does on the rest of the network. There are two ways:

- **The machine's DNS server**, in *Settings → System → Network*: set it to `192.168.1.2`. Home Assistant, the add-ons and the machine itself then use the add-on. If the machine gets its address from the router's DHCP, it already got the add-on as its DNS server in the step above, and there is nothing to do.
- **Only Home Assistant and the add-ons**, from the *Terminal & SSH* add-on: `ha dns options --servers dns://172.30.32.1`. The machine keeps its own DNS servers. `ha dns reset` undoes it.

Give only the add-on's address. With a second server, as the router, some lookups go there instead, and the local names fail now and then.

While the add-on is stopped, the local names don't resolve. With the machine's DNS server set to it, the machine can't look up any name either, updates included, until the add-on is started again. The second way leaves the machine's own lookups alone.

## Check that it works

The add-on's page, *Open Web UI*, lists under `Resolvers` the zone and how many names it has, and under `DNS` each name with its addresses. From any device on the network, the plain guide's [checks](../network-wide-names.md#check-that-it-works): `dig printer.home.arpa`, `dig homeassistant.home.arpa`.

From Home Assistant's side, in the *Terminal & SSH* add-on, which looks names up as Home Assistant does: `nslookup printer.home.arpa` answers with the printer's addresses.

The ipv6ddns device in Home Assistant has an entity for each name written in the configuration, as `homeassistant`, with its addresses and its last update. The names made for the hosts, `{hostname}`, have none, as they come and go.

## More

- [A name that matters](../network-wide-names.md#a-name-that-matters): a fixed name for a device, by its MAC.
- [Common problems](../network-wide-names.md#common-problems).
- [Your router's DNS instead](../network-wide-names.md#your-routers-dns-instead): there, a password file is `${file:/config/mikrotik_password}`.
