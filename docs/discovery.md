# Discovery

Discovery finds the addresses of the hosts of the network, each with its MAC, for the [filters](filtering.md) of the tasks. It is the [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc) library: its documentation has the details of each protocol. All its keys are under `discovery`, in the [configuration reference](reference/configuration.md#discovery).

## Families and ways

IPv6 is discovered by default, IPv4 when asked. Each family is discovered the same ways:

| | `ipv6` (default on) | `ipv4` (default off) |
|---|---|---|
| **Plugins** | The routers' IPv6 neighbor tables | Their ARP tables |
| `listen` (default on) | Listening to NDP, and to the answers of the probes | Reading the kernel's neighbor table: netlink on Linux, `arp -an` on macOS and the BSDs |
| `active` (default on): probing every host | Multicast ping, SSDP and WS-Discovery, on each link | A sweep: a UDP packet to each address of the local subnets (a /22 at most, or the /24 of the address), so the kernel resolves the hosts. It broadcasts an ARP request for each address |
| `solicit` (default off): asking the hosts the filters want | [Below](#solicitation) | [Below](#solicitation) |
| `lifetime` | How long the family's addresses stay after they were last seen | The same |

`true` turns a family on with its defaults, `false` off, and an object gives the ways, each defaulting as `true` sets it:

```yaml
discovery:
  ipv6: true            # the default
  ipv4:
    active: false       # no broadcast sweep
    solicit: true       # the hosts the filters name are asked
```

Active probing and IPv6 solicitation need `listen`, which reads their answers: without it, they do nothing.

## Local IPv4 addresses

A device's local IPv4 address, as `192.168.1.10`, has its MAC, so discovery finds it as it finds IPv6 ones, once `discovery.ipv4` is on. A filter takes IPv4 addresses only when its `ip.family` says, so turning IPv4 on doesn't take a device's private IPv4 to a public DNS:

```yaml
discovery:
  ipv4: true
tasks:
  nas:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
        ip:
          family: [4]
          type: [private]
    endpoints:
      home-dns: [nas]
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

Some addresses are never seen without asking. With `solicit`, the hosts the filters want are asked once a minute:

- **IPv6**: a host sends from its temporary addresses, so its stable one may never be seen, and routers don't list it. For each filter that names a `mac.address` and the `eui64` type, `ipv6ddns` works out that address on each /64 of the network and asks for it with a neighbor solicitation.
- **IPv4**: a quiet host may be in no ARP table. For each filter that names a `mac.address` with `ip.family` 4, `ipv6ddns` asks that MAC, with ARP requests sent to it alone, for each address of the local subnets within the filter's `ip.prefix`, up to 4096, or without one those the sweep would ask. Nothing is broadcast, though a switch that no longer knows where the MAC is floods the requests, as any frame to it. It needs Linux and `CAP_NET_RAW`.

An address that answers is discovered as any other; one that doesn't is never published.

## Interfaces

The local discovery runs on every interface, unless `interfaces` names those it runs on, and `exclude_interfaces` those it doesn't: names, or patterns as `docker*`. On a host running containers, leave their bridges out, so that the containers don't count as hosts, and the probes stay off their networks:

```yaml
discovery:
  exclude_interfaces: [docker*, br-*, veth*]
```

The plugins aren't concerned: they read other hosts' tables.

## Lifetimes

An address stays for its lifetime after it was last seen, and goes then: its records are updated without it. The lifetime is the top-level `lifetime`, an hour by default, unless the family has its own:

```yaml
lifetime: 1h
discovery:
  ipv4:
    lifetime: 3m        # a device that leaves loses its A record within minutes
```

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
