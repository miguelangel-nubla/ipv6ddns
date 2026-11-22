# Discovery

Discovery finds the hosts on the network and their addresses, each with its MAC. The tasks' [filters](filtering.md) then choose from what it finds.

Discovery is done by the [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc) library, and the `discovery` block is ipv6disc's configuration. It takes the same keys as ipv6disc's own command, reads them the same way, and reports the same errors, so a file written for one works as the block of the other. [ipv6disc's documentation](https://github.com/miguelangel-nubla/ipv6disc/blob/main/docs/discovery.md) has the details of each protocol, and every key is in the [configuration reference](reference/configuration.md#discovery).

ipv6ddns differs from ipv6disc in two things:

- The default lifetime is one hour, where ipv6disc's is four.
- [`solicit`](#solicitation) is ipv6ddns's own key. It asks for the hosts the filters name.

## Families and ways

IPv6 is discovered by default. IPv4 is discovered only when you turn it on. Each family has its own switches, under `ipv6` and `ipv4`:

| Switch | Default | What it does |
|---|---|---|
| `enabled` | On for `ipv6`, off for `ipv4` | Turns the whole family on or off |
| `listen` | On | Local discovery: finds hosts by listening |
| `active` | On | Probes every host |
| `lifetime` | [`discovery.lifetime`](#lifetimes) | How long the family's addresses stay after they were last seen |

What each switch means depends on the family:

- **`listen`**
  - IPv6: listens to NDP, and to the answers to the probes.
  - IPv4: reads the kernel's neighbor table, through netlink on Linux and `arp -an` on macOS and the BSDs. On Linux, it also hears the ARP packets the hosts send.
- **`active`**
  - IPv6: sends a multicast ping, an SSDP search and a WS-Discovery probe on each link.
  - IPv4: runs a sweep. It sends a UDP packet to each address of the local subnets, so that the kernel resolves the hosts, which broadcasts an ARP request for each address. A subnet is swept whole up to a /22. In a larger one, only the /24 of the machine's address is swept.
- **Plugins** read the routers' IPv6 neighbor tables for `ipv6`, and their ARP tables for `ipv4`.

A family is always a mapping of its switches, never `true` or `false` on its own. `ipv4: true` is an error, which says to write `enabled: true` under `ipv4` instead.

```yaml
discovery:
  ipv4:
    enabled: true
    active: false       # no broadcast sweep
  solicit:
    ipv4: true          # ask for the hosts the filters name
```

Active probing and IPv6 solicitation need `listen`, because `listen` is what reads their answers. Without it, they do nothing.

## Protocols

A family's switches turn all of its protocols on or off at once. To control one protocol, use its entry under `protocols`. Each protocol has its own `enabled`, with its options beside it. Like a family, a protocol is always written as a mapping.

A protocol runs when all of these are true:

- the protocol is enabled;
- its family is enabled;
- its family listens. For the sweep, the family must be active instead.

| Protocol | Default | Family | What it does |
|---|---|---|---|
| `ndp` | on | IPv6 | Listens to each link's neighbor discovery, which gives an address and its MAC |
| `ping` | on | IPv6 | Pings an address before it expires. With `active`, pings every host by multicast |
| `ssdp`, `wsd` | on | IPv6 | With `active`, sends a search for UPnP devices and a WS-Discovery probe, and hears the answers |
| `arp` | on | IPv4 | Reads the kernel's neighbor table every minute |
| `arp-sweep` | on | IPv4 | With `active`, sweeps the subnets that are no larger than its `max_prefix` |
| `arp-listen` | on, on Linux | IPv4 | Hears the ARP packets the hosts send. Linux only |
| `mdns` | on | Either | Anything that sends to the mDNS groups is a host, and what it announces is its [name](#names) |
| `dhcp`, `lldp` | on, on Linux | Either | Hears what DHCP clients and LLDP neighbors say. Linux only |
| `netbios`, `llmnr`, `dns` | on | | Learn [names](#names) only. `netbios` and `llmnr` ask a host for its name. `dns` asks the servers listed in its `servers`, and asks nobody until it has some |

By default every protocol is on, and so are its options: `ssdp` and `wsd` fetch names, and `mdns` asks questions. The protocols that listen for raw frames are on wherever they can run, which is on Linux. They need the `CAP_NET_RAW` privilege. Without it, the log says so once, and everything else runs.

A protocol that is off sends nothing, joins no group and opens no socket:

```yaml
discovery:
  protocols:
    ssdp:
      enabled: false
    wsd:
      enabled: false
    llmnr:                    # its questions go to every host on the link
      enabled: false
```

A protocol that can't run is an error at start, instead of being silently left out. These are errors:

- a protocol that doesn't exist;
- `ping`, `ssdp` or `wsd` without `ndp`, because `ndp` finds the MAC of what they hear;
- `arp-listen`, `dhcp` or `lldp` on any system but Linux.

To see which protocols run:

- The log lists them at start.
- The web report and `-live` show them under `Protocols`.
- `/status.json` has them as `protocols`.

Each protocol, with its options and defaults, is in the [reference](reference/configuration.md#discovery-protocols).

## Names

Discovery keeps the names the hosts go by. They come from two places: the protocols that learn names, such as mDNS, and the plugins, which read them in their routers' DHCP leases.

A name is whatever the device claims, cleaned into one DNS label. Nothing proves it, and two hosts can claim the same name.

To learn no names, turn off the protocols that learn them. The `hostnames` key has only the names' `lifetime`:

```yaml
discovery:
  hostnames:
    lifetime: 4h
  protocols:
    mdns:
      enabled: false
    dhcp:
      enabled: false
    lldp:
      enabled: false
    netbios:
      enabled: false
    llmnr:
      enabled: false
    ssdp:
      names: false
    wsd:
      names: false
```

The web report and `-live` show a host's names under its MAC. Each name lists what said it, with two times for each: how long that report has left, and how long it has been saying the name. `/status.json` has them as the host's `names`, with each report under `said`.

Names are useful in two ways:

- When you write a filter, they tell you which host a MAC belongs to.
- A task can name its hosts by them, with a [template](hostnames.md) such as `{hostname}` among its `endpoints`.

## Local IPv4 addresses

A device's local IPv4 address, such as `192.168.1.10`, comes with its MAC. So once `discovery.ipv4.enabled` is on, discovery finds it just as it finds IPv6 addresses.

A filter takes IPv4 addresses only when its `ip.family` says so. Turning IPv4 on therefore doesn't send a device's private IPv4 to a public DNS:

```yaml
discovery:
  ipv4:
    enabled: true
tasks:
  nas:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
        ip:
          family:
            - 4
          type:
            - private
    endpoints:
      home-dns:
        - nas
credentials:
  home-dns:
    provider: technitium
    settings:
      address: http://127.0.0.1:5380
      token: ${TECHNITIUM_TOKEN}
      zone: home.example.com
      ttl: 5m
```

The network's public IPv4 has no MAC, so discovery can't find it. It comes from a [source](sources.md).

## Solicitation

Some addresses are never seen unless you ask for them. Solicitation asks for the hosts your filters want.

`discovery.solicit` has a switch for each family, `ipv6` and `ipv4`. Both are off by default. When a switch is on, ipv6ddns asks once a minute. It also asks on a network's /64 as soon as it starts listening on it, for example at the start.

```yaml
discovery:
  solicit:
    ipv6: true
```

- **IPv6:** a host sends from its temporary addresses, so its stable address may never be seen, and routers don't list it. For each filter that names a `mac.address` and the `eui64` type, ipv6ddns works out that address on each /64 of the network, and asks for it with a neighbor solicitation.
- **IPv4:** a quiet host may be in no ARP table. For each filter that names a `mac.address` with `ip.family` 4, ipv6ddns sends ARP requests to that MAC alone.
  - It asks for each address of the local subnets that is within the filter's `ip.prefix`, up to 4096 addresses. Without a prefix, it asks for the addresses the sweep would ask.
  - Nothing is broadcast. But a switch that no longer knows where the MAC is floods the requests, as it would any frame for that MAC.
  - It needs Linux and `CAP_NET_RAW`.

An address that answers is discovered like any other. An address that doesn't answer is never published.

IPv4 solicitation reads its own answers, so it also works with `ipv4.listen` off, even when there is nothing else to discover. The log then says there's no discovery, and the solicited hosts are found anyway. It does need `ipv4.enabled`, like everything IPv4. A family that is off isn't solicited, and the log warns about it at start.

Solicitation belongs to ipv6ddns, unlike the rest of the block, which belongs to ipv6disc. Only ipv6ddns has filters to take the hosts from.

## Interfaces

Local discovery runs on every interface that is up, isn't a loopback, and has a MAC. Two keys change that:

- `interfaces` limits discovery to the interfaces you name.
- `exclude_interfaces` leaves some out, by name or by pattern, such as `docker*`.

On a machine that runs containers, leave their bridges out. Otherwise the containers count as hosts, and the probes go onto their networks:

```yaml
discovery:
  exclude_interfaces:
    - docker*
    - br-*
    - veth*
```

Interfaces without a MAC are left out, along with their own addresses. PPP links, WireGuard and other tunnels are such interfaces. A host is identified by its MAC, and there isn't one there. To publish this machine's address on such an interface, use a [source](sources.md).

For IPv6, an interface that has only a link-local address isn't listened on either.

None of this affects plugins, which read other hosts' tables.

## Lifetimes

An address stays for its lifetime after it was last seen. Then it goes, and its records are updated without it. The lifetime is `discovery.lifetime`, one hour by default, unless the family has its own:

```yaml
discovery:
  lifetime: 1h
  ipv4:
    enabled: true
    lifetime: 3m        # a device that leaves loses its A record within minutes
```

This machine's own addresses, the ones a [`self`](filtering.md) filter takes, are the exception. The interfaces are checked every minute. When an interface has lost an address, for example because a prefix went away or a temporary address was replaced, the address goes at that check.

A name's records are not touched before its first address is found. After a start, they stay as they are until then. Once the name has had addresses and the last one goes, its records are removed.

### After a start

After a start, ipv6ddns knows nothing of what it found before. It publishes only what it has found since.

This matters for a host with several addresses. A host answers the multicast ping from one address, its preferred one, and sends nothing from the others. So an address the host keeps beside the one it uses, such as a stable address beside temporary ones, is found only when the host sends from it. Until then, that address's record is removed, and the name has only the addresses found so far.

Probing more often, or sooner, doesn't help, because every ping is answered from the same address. These do help:

- **A router [plugin](#plugins).** The router's neighbor table has every address in use on the link, quiet ones included. The plugin finds them at its next read.
- **[Solicitation](#solicitation) of an EUI-64 address.** A filter that names the host's `mac.address` and the `eui64` type has that address asked for at once.
- **A written name**, for a host that must keep its address through restarts, with a filter that finds the address in one of these two ways.

Two things keep the addresses of hosts that are still there:

- An IPv6 address found by local discovery is pinged before it expires, so a host that is still there keeps it.
- Active discovery probes every host again every `rediscover`. The default is a third of the shortest lifetime among the families that probe.

## Plugins

A plugin reads the neighbor table of a router, or of another host, every `interval`. Use one to find the hosts of networks that local discovery doesn't reach, such as other VLANs. A plugin can also find every host on its own, without raw sockets.

| Type | Reads | Over |
|---|---|---|
| `linux` | `ip neigh` | SSH |
| `freebsd` | `ndp -an`, `arp -an`: pfSense, OPNsense | SSH |
| `mikrotik` | `/ipv6/neighbor`, `/ip/arp` | The API: see [MikroTik](mikrotik.md#discovery-plugin) |

```yaml
discovery:
  plugins:
    router:
      type: linux
      interval: 60s
      address: 192.168.1.1
      username: root
      identity_file: /secrets/router_key
      host_key: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

Each type's keys are in the [reference](reference/configuration.md#discovery-plugins). Give an SSH plugin its `host_key`. [ipv6disc's docs](https://github.com/miguelangel-nubla/ipv6disc/blob/main/docs/plugins.md#ssh-host-keys) say how to get it.

Plugins read the tables of the families that are on. They take only the entries that were confirmed recently, so the addresses of hosts that left do expire.
