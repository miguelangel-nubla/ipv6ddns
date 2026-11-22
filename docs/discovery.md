# Discovery

Discovery finds the hosts of the network and their addresses, each with its MAC, for the tasks' [filters](filtering.md) to choose from.

It's the [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc) library, and the `discovery` block is its configuration: the same keys its own command takes, read the same way, with the same errors. A file for one works as the block of the other. [Its documentation](https://github.com/miguelangel-nubla/ipv6disc/blob/main/docs/discovery.md) has the details of each protocol, and every key is in the [configuration reference](reference/configuration.md#discovery).

Two things are ipv6ddns's own: the lifetime is an hour by default, where ipv6disc's is four, and [`solicit`](#solicitation), which asks for the hosts the filters name.

## Families and ways

IPv6 is discovered by default, IPv4 only when you turn it on. Each family has its own switches, under `ipv6` and `ipv4`:

| | `ipv6` | `ipv4` |
|---|---|---|
| `enabled` | On by default | Off by default |
| **Plugins** | The routers' IPv6 neighbor tables | Their ARP tables |
| `listen` (default on): the local discovery | Listening to NDP, and to the answers of the probes | Reading the kernel's neighbor table: netlink on Linux, `arp -an` on macOS and the BSDs. On Linux, the ARP the hosts send, too |
| `active` (default on): probing every host | Multicast ping, SSDP and WS-Discovery, on each link | A sweep: a UDP packet to each address of the local subnets (a /22 at most, or the /24 of the address), so the kernel resolves the hosts. It broadcasts an ARP request for each address |
| `lifetime` | How long the family's addresses stay after they were last seen | The same |

A family is always a mapping of its switches, never `true` or `false` on its own. `ipv4: true` is an error, which says to write `enabled: true` under `ipv4` instead.

```yaml
discovery:
  ipv4:
    enabled: true
    active: false       # no broadcast sweep
  solicit:
    ipv4: true          # the hosts the filters name are asked
```

Active probing and IPv6 solicitation need `listen`, which reads their answers. Without it, they do nothing.

## Protocols

A family's switches turn all of its protocols on or off at once. Under `protocols`, each protocol also has its own `enabled`, with its options beside it, again always as a mapping. A protocol runs when it's enabled, its family is enabled, and its family listens (or, for the sweep, is active).

| Protocol | Default | Family | |
|---|---|---|---|
| `ndp` | on | IPv6 | The neighbor discovery of each link, which tells an address and its MAC |
| `ping` | on | IPv6 | An address is pinged before it expires; with `active`, every host is, by multicast |
| `ssdp`, `wsd` | on | IPv6 | With `active`, a search for the UPnP devices, and a WS-Discovery probe, whose answers are heard |
| `arp` | on | IPv4 | The kernel's neighbor table, read every minute |
| `arp-sweep` | on | IPv4 | The sweep, with `active`, of the subnets no larger than its `max_prefix` |
| `arp-listen` | on, on Linux | IPv4 | The ARP the hosts send, heard. Linux only |
| `mdns` | on | Either | Whatever sends to the groups of mDNS is a host, and what it announces its [name](#names) |
| `dhcp`, `lldp` | on, on Linux | Either | What DHCP clients and LLDP neighbors say, heard. Linux only |
| `netbios`, `llmnr`, `dns` | on | | A host is asked its name, or the `servers` of `dns` are, once it has some: [names](#names) only |

By default every protocol is on, with its options on too: `ssdp` and `wsd` fetch names, and `mdns` asks. The protocols that listen for raw frames are on where they can run, on Linux. Without the privilege they need, `CAP_NET_RAW`, the log says so once and everything else runs. A protocol that is off sends nothing, joins no group and opens no socket:

```yaml
discovery:
  protocols:
    ssdp:
      enabled: false
    wsd:
      enabled: false
    llmnr:                    # its questions go to every host of the link
      enabled: false
```

A protocol that can't run is an error at start, rather than being silently left out:

- a protocol that doesn't exist;
- `ping`, `ssdp` or `wsd` without `ndp`, which tells them the MAC of what they hear;
- `arp-listen`, `dhcp` or `lldp` anywhere but Linux.

At start, the log says which protocols run. The web report and `-live` show them under `Protocols`, and `/status.json` has them as `protocols`. Each protocol, with its options and defaults, is in the [reference](reference/configuration.md#discovery-protocols).

## Names

Discovery keeps the names the hosts go by: what a protocol learns, as mDNS, and what the plugins read in their routers' DHCP leases. A name is whatever the device claims, cleaned into one DNS label. Nothing proves it, and two hosts can claim the same name.

To learn no names, turn off the protocols that learn them. `hostnames` only has their `lifetime`:

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

The web report and `-live` show a host's names under its MAC, each with what said it and when: how long each source has left, and how long it has been saying it. `/status.json` has them as the host's `names`, with each source under `said`.

Names help you tell which host a MAC belongs to when writing a filter. A task can also name its hosts by them, with a [template](hostnames.md) among its `endpoints`, as `{hostname}`.

## Local IPv4 addresses

A device's local IPv4 address, as `192.168.1.10`, comes with its MAC, so discovery finds it just as it finds IPv6 ones, once `discovery.ipv4.enabled` is on. A filter only takes IPv4 addresses when its `ip.family` says so, so turning IPv4 on doesn't send a device's private IPv4 to a public DNS:

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

Some addresses are never seen unless you ask for them. `discovery.solicit` has a switch for each family, `ipv6` and `ipv4`, both off by default. When on, ipv6ddns asks for the hosts the filters want once a minute, and on a network's /64 as soon as it starts listening on it, as at the start:

```yaml
discovery:
  solicit:
    ipv6: true
```

- **IPv6:** a host sends from its temporary addresses, so its stable address may never be seen, and routers don't list it. For each filter that names a `mac.address` and the `eui64` type, ipv6ddns works out that address on each /64 of the network, and asks for it with a neighbor solicitation.
- **IPv4:** a quiet host may be in no ARP table. For each filter that names a `mac.address` with `ip.family` 4, ipv6ddns sends ARP requests to that MAC alone. It asks for each address of the local subnets within the filter's `ip.prefix`, up to 4096; without a prefix, the addresses the sweep would ask. Nothing is broadcast, though a switch that no longer knows where the MAC is floods the requests, as it would any frame for it. This needs Linux and `CAP_NET_RAW`.

An address that answers is discovered like any other. One that doesn't is never published.

IPv4 solicitation reads its own answers. So it works with `ipv4.listen` off too, even with nothing else to discover: the log then says there's no discovery, and the hosts asked are found anyway. It does need `ipv4.enabled`, like everything IPv4: a family that is off isn't asked for, and the log warns about it at start.

Solicitation is ipv6ddns's own, unlike the rest of the block, which is ipv6disc's: only ipv6ddns has filters to take the hosts from.

## Interfaces

Local discovery runs on every interface that is up, isn't a loopback, and has a MAC. `interfaces` limits it to the ones you name, and `exclude_interfaces` leaves some out, by name or pattern, as `docker*`. On a machine running containers, leave their bridges out, so the containers don't count as hosts and the probes stay off their networks:

```yaml
discovery:
  exclude_interfaces:
    - docker*
    - br-*
    - veth*
```

Interfaces without a MAC, as PPP links, WireGuard and other tunnels, are left out, along with their own addresses: a host is identified by its MAC, and there isn't one there. To publish this machine's address on such an interface, use a [source](sources.md). For IPv6, an interface with only a link-local address isn't listened on either.

None of this affects plugins, which read other hosts' tables.

## Lifetimes

An address stays for its lifetime after it was last seen, and then goes: its records are updated without it. The lifetime is `discovery.lifetime`, an hour by default, unless the family has its own:

```yaml
discovery:
  lifetime: 1h
  ipv4:
    enabled: true
    lifetime: 3m        # a device that leaves loses its A record within minutes
```

This machine's own addresses, those of [`self`](filtering.md), are the exception. When its interface loses one, as when a prefix goes or a temporary address is replaced, it goes at the next check of the interfaces, every minute.

Nothing is updated before a name's first address is found: after a start, its records stay as they are until then. Once it has had addresses and the last one goes, its records are removed.

### After a start

After a start, ipv6ddns knows nothing of what it found before: it publishes only what it has found since. A host answers the multicast ping from one address, its preferred one, and sends nothing from the others. So an address it keeps beside the one it uses, as a stable address beside temporary ones, is only found when the host sends from it. Until then its record is removed, and the name has only the addresses found so far.

Probing more often, or sooner, doesn't help, because every ping is answered from the same address. These do:

- **A router [plugin](#plugins):** the router's neighbor table has every address in use on the link, quiet ones included, at its next read.
- **[Solicitation](#solicitation) of an EUI-64 address:** a filter that names the host's `mac.address` and the `eui64` type has it asked for at once.
- **A written name** for a host that must keep its address through restarts, with a filter that finds it in one of these ways.

Before an IPv6 address found by local discovery expires, it's pinged, so a host that is still there keeps it. Active discovery probes every host again every `rediscover`, by default a third of the shortest lifetime among the families that probe.

## Plugins

A plugin reads the neighbor table of a router, or of another host, every `interval`. It finds the hosts of networks local discovery doesn't reach, such as other VLANs, or all of them without needing raw sockets.

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

Each type's keys are in the [reference](reference/configuration.md#discovery-plugins). Give an SSH plugin its `host_key`; [ipv6disc's docs](https://github.com/miguelangel-nubla/ipv6disc/blob/main/docs/plugins.md#ssh-host-keys) say how to get it. Plugins read the tables of the families that are on, and only entries confirmed recently, so the addresses of hosts that left do expire.
