# Discovery

Discovery finds the addresses of the hosts of the network, each with its MAC, for the [filters](filtering.md) of the tasks. It is the [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc) library, and the `discovery` block is its configuration: the keys its own command takes in its file, read the same and with the same errors, so that a file of one is the block of the other. [Its documentation](https://github.com/miguelangel-nubla/ipv6disc/blob/main/docs/discovery.md) has the details of each protocol. Every key is in the [configuration reference](reference/configuration.md#discovery). Two things are ipv6ddns's own: the lifetime is an hour by default, where ipv6disc's is four, and [`solicit`](#solicitation), whose hosts are the filters'.

## Families and ways

IPv6 is discovered by default, IPv4 when asked. Each family has its switches, under `ipv6` and `ipv4`:

| | `ipv6` | `ipv4` |
|---|---|---|
| `enabled` | On by default | Off by default |
| **Plugins** | The routers' IPv6 neighbor tables | Their ARP tables |
| `listen` (default on): the local discovery | Listening to NDP, and to the answers of the probes | Reading the kernel's neighbor table: netlink on Linux, `arp -an` on macOS and the BSDs. On Linux, the ARP the hosts send, too |
| `active` (default on): probing every host | Multicast ping, SSDP and WS-Discovery, on each link | A sweep: a UDP packet to each address of the local subnets (a /22 at most, or the /24 of the address), so the kernel resolves the hosts. It broadcasts an ARP request for each address |
| `lifetime` | How long the family's addresses stay after they were last seen | The same |

A family is a mapping of its switches, never `true` or `false` alone: `ipv4: true` is an error that says how it is written: `enabled: true` under `ipv4`.

```yaml
discovery:
  ipv4:
    enabled: true
    active: false       # no broadcast sweep
  solicit:
    ipv4: true          # the hosts the filters name are asked
```

Active probing and IPv6 solicitation need `listen`, which reads their answers: without it, they do nothing.

## Protocols

The switches of a family are those of all its protocols at once. Under `protocols`, each has its own, `enabled`, and its options beside it: always a mapping, as the families. A protocol runs when it is enabled, and its family is, and listens, or for the sweep is active.

| Protocol | Default | Family | |
|---|---|---|---|
| `ndp` | on | IPv6 | The neighbor discovery of each link, which tells an address and its MAC |
| `ping` | on | IPv6 | An address is pinged before it expires; with `active`, every host is, by multicast |
| `ssdp`, `wsd` | on | IPv6 | With `active`, a search for the UPnP devices, and a WS-Discovery probe, whose answers are heard |
| `arp` | on | IPv4 | The kernel's neighbor table, read every minute |
| `arp-sweep` | on | IPv4 | The sweep, with `active`, of the subnets no larger than its `max_prefix` |
| `arp-listen` | on, on Linux | IPv4 | The ARP the hosts send, heard. Linux only |
| `mdns` | off | Either | Whatever sends to the groups of mDNS is a host, and what it announces its [name](#names) |
| `dhcp`, `lldp` | off | Either | What DHCP clients and LLDP neighbors say, heard. Linux only |
| `netbios`, `llmnr`, `dns` | off | | A host is asked its name, or the `servers` of `dns` are: [names](#names) only |

By default those that find hosts are on, and those that tell names off. One that is off sends nothing, joins no group and opens no socket:

```yaml
discovery:
  protocols:
    ssdp:
      enabled: false
    wsd:
      enabled: false
    mdns:
      enabled: true
```

What can't run is an error at start, not a protocol left out without a word: one there is none of, `ping`, `ssdp` or `wsd` without `ndp`, which tells them the MAC of what they hear, `arp-listen`, `dhcp` or `lldp` anywhere but on Linux, `dns` without `servers`, and one that only learns names without `hostnames`. The log says at start which run, the web report and `-live` show them under `Protocols`, and `/status.json` has them as `protocols`. Each, with its options and defaults, is in the [reference](reference/configuration.md#discovery-protocols).

## Names

With `hostnames.enabled`, discovery keeps the names the hosts go by: what a protocol enabled learns, as mDNS, and what the plugins read in their routers' DHCP leases. A name is whatever the device claims, cleaned to one DNS label: nothing proves it, and two hosts can claim the same.

```yaml
discovery:
  hostnames:
    enabled: true
  protocols:
    mdns:
      enabled: true
```

The web report and `-live` show a host's names after its MAC, each with what said it, and `/status.json` has them as the host's `names`. They tell which host a MAC is, when writing a filter; and a task can name its hosts by them, with a [template](hostnames.md) among its `endpoints`, as `{hostname}`.

## Local IPv4 addresses

A device's local IPv4 address, as `192.168.1.10`, has its MAC, so discovery finds it as it finds IPv6 ones, once `discovery.ipv4.enabled` is on. A filter takes IPv4 addresses only when its `ip.family` says, so turning IPv4 on doesn't take a device's private IPv4 to a public DNS:

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

The network's public IPv4, which has no MAC, comes from a [source](sources.md).

## Solicitation

Some addresses are never seen without asking. With `discovery.solicit`, which has a switch for each family, `ipv6` and `ipv4`, both off by default, the hosts the filters want are asked once a minute, and on a network's /64 as soon as it is listened on, as at the start:

```yaml
discovery:
  solicit:
    ipv6: true
```

- **IPv6**: a host sends from its temporary addresses, so its stable one may never be seen, and routers don't list it. For each filter that names a `mac.address` and the `eui64` type, `ipv6ddns` works out that address on each /64 of the network and asks for it with a neighbor solicitation.
- **IPv4**: a quiet host may be in no ARP table. For each filter that names a `mac.address` with `ip.family` 4, `ipv6ddns` asks that MAC, with ARP requests sent to it alone, for each address of the local subnets within the filter's `ip.prefix`, up to 4096, or without one those the sweep would ask. Nothing is broadcast, though a switch that no longer knows where the MAC is floods the requests, as any frame to it. It needs Linux and `CAP_NET_RAW`.

An address that answers is discovered as any other; one that doesn't is never published.

IPv4 solicitation reads its own answers, so it works with `ipv4.listen` off too, and with nothing else to discover: the log then says there is no discovery, and the hosts asked are found all the same. It needs `ipv4.enabled`, as all of IPv4: a family that is off is not asked for, which the log warns of at start.

The solicitation is ipv6ddns's, not ipv6disc's, whose keys the rest of the block are: only ipv6ddns has filters to take the hosts from.

## Interfaces

The local discovery runs on every interface that is up, not a loopback and has a MAC, unless `interfaces` names those it runs on, and `exclude_interfaces` those it doesn't: names, or patterns as `docker*`. On a host running containers, leave their bridges out, so that the containers don't count as hosts, and the probes stay off their networks:

```yaml
discovery:
  exclude_interfaces:
    - docker*
    - br-*
    - veth*
```

The interfaces without a MAC, as PPP links, WireGuard and other tunnels, are left out, and their own addresses with them: a host is its MAC, and there is none there. An address of this machine on such an interface comes from a [source](sources.md). For IPv6, an interface with only a link-local address is not listened on either.

The plugins aren't concerned: they read other hosts' tables.

## Lifetimes

An address stays for its lifetime after it was last seen, and goes then: its records are updated without it. The lifetime is `discovery.lifetime`, an hour by default, unless the family has its own:

```yaml
discovery:
  lifetime: 1h
  ipv4:
    enabled: true
    lifetime: 3m        # a device that leaves loses its A record within minutes
```

This machine's own addresses, those of [`self`](filtering.md), are the exception: one its interface loses, as a prefix that went or a temporary address replaced, goes when the interfaces are next looked at, every minute.

Nothing is updated before a name's first address is found: after a start, its records stay as they are until then. Once it had addresses and the last one goes, its records are removed.

### After a start

A start knows nothing of what was found before it: what it publishes is what it has found since. A host answers the multicast ping from one address, its preferred, and sends nothing from the others, so an address it keeps beside the one it uses, as a stable address beside temporary ones, is found only when the host speaks from it. Until then, its record is taken off: the name has the addresses found so far.

Probing more, or sooner, doesn't find it: every ping is answered from the same address. What does:

- A router's [plugin](#plugins): the router's neighbor table has every address in use on the link, the quiet ones too, at its next read.
- The [solicitation](#solicitation) of an EUI-64 address: a filter that names the host's `mac.address` and the `eui64` type has it asked, at once.
- A name written for a host that has to keep its address through restarts, with the filter that finds it in one of these ways.

Before an IPv6 address the local discovery found expires, it is pinged, so a host still there keeps it. The active discovery probes every host again every `rediscover`, by default a third of the shortest lifetime of the families that probe.

## Plugins

A plugin reads the neighbor table of a router, or of a host, every `interval`: it finds the hosts of networks the local discovery doesn't reach, as other VLANs, or all of them without raw sockets.

| Type | Reads | Over |
|---|---|---|
| `linux` | `ip neigh` | SSH |
| `freebsd` | `ndp -an`, `arp -an`: pfSense, OPNsense | SSH |
| `mikrotik` | `/ipv6/neighbor`, `/ip/arp` | The API: see [Mikrotik](mikrotik.md#discovery-plugin) |

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

Each type's keys are in the [reference](reference/configuration.md#discovery-plugins). Give an SSH plugin its `host_key`: [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc/blob/main/docs/plugins.md#ssh-host-keys) says how to get it. The plugins read the tables of the families on, and only the entries confirmed recently, so that the addresses of hosts that left expire.
