# Every machine on the network by name

Reach every device on your network by its own name, such as `nas.lan.example.com`, `printer.lan.example.com` or `laptop.lan.example.com`, from every other device. You don't give anything a static address, and you don't add or maintain a record for each host.

ipv6ddns finds the hosts on the network, learns what each one is called, and answers DNS for them itself. A new device has its name as soon as it shows up. A name follows its device when the device's addresses change: a new IPv6 prefix from the ISP, a new DHCP lease, a laptop moving from Wi-Fi to cable.

The setup is the same on a homelab server, a Raspberry Pi, or a Home Assistant machine. Running ipv6ddns as the Home Assistant app? Start with [the app's side of this guide](home-assistant/network-wide-names.md), which sends you back here.

## What you need

- **A machine on the LAN that is always on**, to run ipv6ddns. [Install it](../installation.md) as a binary, in Docker on the host's network, or as the Home Assistant app. ipv6ddns answers DNS on port 53, so nothing else on that machine may hold port 53 on its LAN address. Pi-hole and AdGuard Home do: with one of them, have ipv6ddns write the names into it instead, as the guides for [AdGuard Home](adguard-home.md) and [Pi-hole](pi-hole.md) show.
- **Access to your router's DHCP settings**, to give the devices that machine as their DNS server.

The examples use `192.168.1.0/24` for the LAN, `192.168.1.1` for the router, and `192.168.1.2` for the machine that runs ipv6ddns. Use your own.

## The configuration

```yaml
discovery:
  ipv4:
    enabled: true          # find IPv4 addresses too; the default is IPv6 only

resolvers:
  lan:
    listen: 192.168.1.0/24 # this machine's address on the LAN, port 53
    upstream:
      - 192.168.1.1        # answers every other name: your router, or 1.1.1.1

credentials:
  home:
    provider: resolver     # a zone ipv6ddns answers itself
    settings:
      zone: lan.example.com

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
        - "{hostname}"     # printer.lan.example.com
        - "{n}.{hostname}" # 1.printer.lan.example.com, 2.printer.lan.example.com when two say printer

webserver:
  listen:
    - 8053                 # the web report: http://192.168.1.2:8053
```

What each part does:

- **`discovery`** finds the hosts. IPv6 is on by default. `ipv4: enabled: true` adds the IPv4 addresses, so that a name also works for devices and clients without IPv6.
- **`resolvers.lan`** makes ipv6ddns a DNS server, which answers on the machine's LAN address. When it's asked a name it doesn't have itself, such as `github.com`, it asks `upstream`, and keeps the answer in a cache.
- **`credentials.home`** is the zone the resolver answers: `lan.example.com`. Write a subdomain of a domain you own there. No domain of your own? Use `home.arpa`, which is [set aside for home networks](https://www.rfc-editor.org/rfc/rfc8375). Don't use `.local`. See [choosing a domain](../resolver.md#choosing-a-domain).
- **`tasks.lan`** gives every host a name. Its filter takes every address of every host, except link-local addresses, which only work on one link. `{hostname}` is the name the host says it has.
- **`webserver`** serves the [web report](../installation.md#the-web-report): the hosts found, their names, and what the resolver answers. The report has no password. If the machine also faces the internet, give a LAN address, such as `192.168.1.2:8053`.

A host is named by what it says it is called:

- Most hosts say their name over mDNS, which discovery listens to by default: computers, phones, printers, Home Assistant, and most smart devices.
- ipv6ddns also hears the names that hosts send in their DHCP requests, on Linux, and their NetBIOS, LLMNR, SSDP and WS-Discovery names.
- Some devices say their name in none of those ways, as some IoT devices do. Name such a device from your router's DHCP leases, with a [plugin](../discovery.md#plugins), or by its MAC, as [below](#a-name-that-matters).

## Point the network at it

Give the devices `192.168.1.2` as their DNS server, in your router's DHCP settings. The setting is the DNS server option, DHCP option 6. Leave the router's own address out of that list: a client that is given both servers uses either, and the router knows none of these names.

To make a bare `nas` work too, and not only `nas.lan.example.com`, set the router's local domain, or DHCP's domain search option, to `lan.example.com`.

Devices can also get a DNS server over IPv6, from the router's advertisements (RDNSS) or from DHCPv6. They then ask the router at its IPv6 address, which doesn't know these names. Choose one of these:

- **Turn the router's IPv6 DNS advertisement off.** The resolver above answers on IPv4 only, and the devices then use the IPv4 DNS server.
- **Answer over IPv6 too.** Add the machine's IPv6 network to `listen`, and advertise the machine's address in that network in place of the router's. Use a stable ULA network, such as `fd00::/64`, because a global prefix changes with the ISP.

The devices take the new settings when they renew their lease. To check now, reconnect one.

## Check that it works

Open the web report, at `http://192.168.1.2:8053`. Under `Resolvers`, it lists the zone and how many names the zone has. Under `DNS`, it lists each name with its addresses.

Then ask from any device on the network:

```
dig printer.lan.example.com
dig printer.lan.example.com AAAA
dig -x 192.168.1.20
```

The first two commands give the printer's addresses. The third gives the printer's name back.

Before the devices use the new DNS server, ask it directly: `dig @192.168.1.2 printer.lan.example.com`. On Windows, use `nslookup printer.lan.example.com 192.168.1.2`.

## A name that matters

A host is called whatever it says it is called, and anything on the network can say it is `nas`. When other things depend on a name, write the name in the configuration, with the host's MAC. A name written in the configuration never goes to a template, whatever another host says.

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

A written name also names a device that says no name at all. The web report shows the MAC address of each host found.

## Common problems

- **`address already in use` at the start.** Another DNS server has port 53 on this machine: Pi-hole, AdGuard Home, or dnsmasq. For the first two, see the guides for [AdGuard Home](adguard-home.md) and [Pi-hole](pi-hole.md). systemd-resolved doesn't get in the way, because it only listens on `127.0.0.53`. See [port 53](../resolver.md#port-53).
- **A device has no name.** The device says no name, or none that discovery hears. The web report lists every host found, with the names it has. A host with no name there needs a [plugin](../discovery.md#plugins) that reads the router's leases, or a [written name](#a-name-that-matters).
- **The names answer with `dig @192.168.1.2` but not without.** The device still uses the router for DNS. Check the device's DNS servers with `resolvectl status`, `ipconfig /all`, or its network settings, and renew its lease.
- **Two devices called the same.** Both are under `printer`. Each also has a name of its own, `1.printer` and `2.printer`, in the order of their MACs. Rename one of the devices, or [write a name](#a-name-that-matters) for the one that matters.
- **A device's old name still answers for a while.** A name stays until discovery lets the host go, after the host's [lifetime](../discovery.md#lifetimes), an hour by default. If another device takes its address meanwhile, the old name loses that address at once. Discovery can't tell a host that left from a host that is quiet.

## Your router's DNS instead

Instead of answering the names itself, ipv6ddns can put them in your router's own DNS: MikroTik, OpenWrt, OPNsense, pfSense or a UniFi gateway, among the [providers](../reference/providers.md). A DNS server that takes dynamic updates, such as BIND, works the same way, with the [`rfc2136`](../reference/providers.md#rfc2136) provider. Then there's no new DNS server to give the devices, and you skip [pointing the network at it](#point-the-network-at-it).

The task is the same. The router's credential replaces the resolver's, and there's no `resolvers` block. This example is for MikroTik, with the password in a file `mikrotik_password` beside the configuration:

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
      zone: lan.example.com
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

[MikroTik as a DNS provider](../mikrotik.md#dns-provider) describes the user ipv6ddns needs on the router. The other routers have pages of their own, [OpenWrt](../openwrt.md#dns-provider), [OPNsense](../opnsense.md#dns-provider), [pfSense](../pfsense.md#dns-provider) and [UniFi](../unifi.md#dns-provider), and their settings are in the [providers reference](../reference/providers.md).

For a UniFi gateway, the names are its DNS Records, which the devices get when they use the gateway as their DNS server, as they do by default. Create an API key in the console, under Settings, Control Plane, Integrations, and put it in a file `unifi_api_key`. The console's certificate is its own, so give its fingerprint, which `openssl s_client -connect 192.168.1.1:443 </dev/null | openssl x509 -outform der | openssl dgst -sha256` shows:

```yaml
credentials:
  home:
    provider: unifi
    settings:
      address: https://192.168.1.1
      api_key: ${file:unifi_api_key}
      tls_fingerprint: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
      zone: lan.example.com
```

A self-hosted UniFi Network Application has no API keys: give `username` and `password` instead, of a local user.

One thing differs from the resolver. The router keeps the records ipv6ddns made. So a host that left while ipv6ddns wasn't running keeps its name on the router until you remove it: see [when a host leaves](../hostnames.md#when-a-host-leaves). The resolver keeps its names in memory, and leaves nothing behind.

## More

- [Names by the hosts' names](../hostnames.md): the placeholders, and what happens when hosts share a name.
- [The resolver](../resolver.md): more zones, records of your own (`files CNAME nas`), encrypted upstream servers, and the cache.
- [Discovery](../discovery.md): how hosts and their names are found.
