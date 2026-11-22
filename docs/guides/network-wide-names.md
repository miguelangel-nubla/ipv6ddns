# Every machine on the network by name

Reach every device on your network by its own name, as `nas.home.arpa`, `printer.home.arpa` or `laptop.home.arpa`, from every other device. You don't give anything a static address, and you don't add or maintain a record for each host. ipv6ddns finds the hosts on the network, learns what each one is called, and answers DNS for them itself. A new device has its name as soon as it shows up, and a name follows its device when its addresses change: a new IPv6 prefix from the ISP, a new DHCP lease, a laptop moving from Wi-Fi to cable.

It works the same on a homelab server, a Raspberry Pi, or a Home Assistant machine. Running it as the Home Assistant add-on? Start with [its side of this guide](home-assistant/network-wide-names.md), which comes back here.

## What you need

- A machine that is always on, on the LAN, to run ipv6ddns: [installed](../installation.md) as a binary, in Docker on the host's network, or as the Home Assistant add-on. It answers DNS on port 53, so nothing else on that machine may hold port 53 on its LAN address, such as Pi-hole or AdGuard Home.
- Access to your router's DHCP settings, to give the devices that machine as their DNS server.

The examples use `192.168.1.0/24` for the LAN, `192.168.1.1` for the router, and `192.168.1.2` for the machine that runs ipv6ddns. Use your own.

## The configuration

```yaml
discovery:
  ipv4:
    enabled: true          # the IPv4 addresses too: IPv6 alone by default

resolvers:
  lan:
    listen: 192.168.1.0/24 # this machine's address on the LAN, port 53
    upstream:
      - 192.168.1.1        # the rest of the world's names: your router, or 1.1.1.1

credentials:
  home:
    provider: resolver     # a zone ipv6ddns answers itself
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

webserver:
  listen:
    - 8053                 # the web report: http://192.168.1.2:8053
```

What each part does:

- **`discovery`** finds the hosts. IPv6 is on by default. `ipv4: enabled: true` adds the IPv4 addresses, so a name works for devices and clients without IPv6.
- **`resolvers.lan`** is ipv6ddns as a DNS server, answering on its LAN address. A name it doesn't have itself, as `github.com`, it asks of `upstream`, and keeps the answer in a cache.
- **`credentials.home`** is the zone it answers: `home.arpa`, the zone [set aside for home networks](https://www.rfc-editor.org/rfc/rfc8375), which no one on the internet answers for.
- **`tasks.lan`** gives every host a name. The filter takes every address of every host but the link-local ones, which only work on one link. `{hostname}` is the name the host says it has.
- **`webserver`** serves the [web report](../installation.md#the-web-report): the hosts found, their names, and what the resolver answers. It has no password, so give a LAN address, as `192.168.1.2:8053`, if the machine also faces the internet.

A host is named by what it says it is called. Most say it over mDNS, which discovery listens to by default: computers, phones, printers, Home Assistant, most smart devices. ipv6ddns also hears the names hosts send in their DHCP requests, on Linux, and NetBIOS, LLMNR, SSDP and WS-Discovery names. A device that says its name to none of those, as some IoT devices, can be named from your router's DHCP leases with a [plugin](../discovery.md#plugins), or by its MAC, [below](#a-name-that-matters).

## Point the network at it

Give the devices `192.168.1.2` as their DNS server, in your router's DHCP settings: the DNS server option, DHCP option 6. Leave the router's own address out of that list. A client given both uses either, and the router knows none of these names.

So that a bare `nas` works too, not only `nas.home.arpa`, set the router's local domain, or DHCP's domain search option, to `home.arpa`.

Devices can also take a DNS server over IPv6, from the router's advertisements (RDNSS) or DHCPv6, and then ask the router there. The resolver above answers on IPv4 only, so turn the router's IPv6 DNS advertisement off, and the devices use the IPv4 one. To answer over IPv6 too, add the machine's IPv6 network to `listen`, as a stable ULA one like `fd00::/64` (a global prefix changes with the ISP), and advertise the machine's address in it instead of the router's.

The devices take the new settings when they renew their lease: reconnect one to check now.

## Check that it works

The web report, at `http://192.168.1.2:8053`, lists under `Resolvers` the zone and how many names it has, and under `DNS` each name with its addresses. From any device on the network:

```
dig printer.home.arpa
dig printer.home.arpa AAAA
dig -x 192.168.1.20
```

The first two give the printer's addresses, the third the printer's name back. Before the devices use the new DNS server, ask it directly: `dig @192.168.1.2 printer.home.arpa`. On Windows, `nslookup printer.home.arpa 192.168.1.2`.

## A name that matters

A host is called what it says it is called, and anything on the network can say it is `nas`. For a name that other things depend on, write it, with the host's MAC: a name written in the configuration is never a template's, whatever another host says.

```yaml
# Added to the configuration above: a task beside lan.
tasks:
  nas:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
        ip:
          family:
            - 4
            - 6
          type:
            - "!link_local"
    endpoints:
      home:
        - nas
```

This also names a device that says no name at all. The MAC addresses are in the web report, under each host found.

## Common problems

- **`address already in use` at the start.** Another DNS server has port 53 on this machine: Pi-hole, AdGuard Home, dnsmasq. systemd-resolved doesn't get in the way, since it listens on `127.0.0.53` only. See [port 53](../resolver.md#port-53).
- **A device has no name.** It says none, or none that discovery hears. The web report lists every host found, with the names it has: a host with no name there needs a [plugin](../discovery.md#plugins) reading the router's leases, or a [name written](#a-name-that-matters).
- **The names answer with `dig @192.168.1.2` but not without.** The device still uses the router for DNS: check its DNS servers (`resolvectl status`, `ipconfig /all`, or the network settings), and renew its lease.
- **Two devices called the same.** Both are under `printer`, and each has its own under `1.printer` and `2.printer`, in the order of their MACs. Rename one of them, or [write](#a-name-that-matters) the one that matters.
- **A device's old name still answers for a while.** A name stays until discovery lets the host go, after its [lifetime](../discovery.md#lifetimes), an hour by default: discovery can't tell a host that left from one that is quiet.

## Your router's DNS instead

The names can go to your router's own DNS in place of ipv6ddns answering them: MikroTik, OpenWrt, OPNsense or pfSense, among the [providers](../reference/providers.md). Then there's no new DNS server to give the devices, and nothing to [point the network at](#point-the-network-at-it). The task is the same, with the router's credential in place of the resolver's, and no `resolvers` block. For MikroTik, with the password in a file `mikrotik_password` beside the configuration:

```yaml
discovery:
  ipv4:
    enabled: true

credentials:
  home:
    provider: mikrotik
    settings:
      address: 192.168.1.1
      username: ipv6ddns
      password: ${file:mikrotik_password}
      zone: home.arpa
      ttl: 5m

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
        - "{hostname}"
        - "{n}.{hostname}"

webserver:
  listen:
    - 8053
```

The user it needs on the router is in [MikroTik as a DNS provider](../mikrotik.md#dns-provider), and the other routers' settings in the [providers reference](../reference/providers.md). One difference: the router keeps the records ipv6ddns made, so a host that left while ipv6ddns wasn't running keeps its name there until you remove it ([when a host leaves](../hostnames.md#when-a-host-leaves)). The resolver keeps its names in memory, and has no such leftovers.

## More

- [Names by the hosts' names](../hostnames.md): the placeholders, and what happens when hosts share a name.
- [The resolver](../resolver.md): more zones, records of your own (`files CNAME nas`), encrypted upstream servers, the cache.
- [Discovery](../discovery.md): how hosts and their names are found.
