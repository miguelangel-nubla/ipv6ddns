# OpenWrt

ipv6ddns works with an OpenWrt router in three ways, which you can use separately or together:

1. **[DNS provider](#dns-provider):** it keeps the hosts it discovers as names of the router's dnsmasq, such as `nas.lan`. Every device that uses the router as its DNS server, as they do by default, can then reach them by name.
2. **[Discovery plugin](#discovery-plugin):** it reads the router's neighbor table and its DHCP leases, with the names the hosts gave.
3. **[The router's updates](#the-routers-updates):** the router sends its public addresses to ipv6ddns, as to a DynDNS service.

Both the provider and the plugin log in over SSH, to the router's Dropbear.

## SSH

- **A key**, rather than a password: generate one for ipv6ddns, and add its public key in *System → Administration → SSH-Keys*. Give the provider its `ssh_key`, and the plugin its `identity_file`.
- **The router's host key.** Give its fingerprint, `host_key`, so that nobody between can pose as the router. Without it, any key is accepted, and the log warns with the one it saw. From a trusted network:

  ```
  ssh-keyscan 192.168.1.1 | ssh-keygen -lf -
  ```

  The router has a key of each kind: the fingerprint of any of them works.
- **The user** is `root`, as OpenWrt has no other by default: the provider changes the router's settings with `uci`, and reloads dnsmasq.

## DNS provider

```yaml
credentials:
  router:
    provider: openwrt
    settings:
      address: 192.168.1.1
      username: root
      ssh_key: /secrets/openwrt_key
      host_key: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      zone: lan
```

The keys are in the [providers reference](reference/providers.md#openwrt). [Every machine on the network by name](guides/network-wide-names.md#your-routers-dns-instead) is the whole setup.

How the names are kept:

- **One `domain` section of `/etc/config/dhcp` for each address**, the sections *Network → DHCP and DNS → Hostnames* lists. ipv6ddns commits them and reloads dnsmasq in the same command.
- **The sections of other names stay**, and so do the host sections of the static leases: only the `domain` sections of the names ipv6ddns keeps change.
- **No TTL.** dnsmasq's names have none of their own: `ttl` is accepted, and not used.
- **A name in another case is the same name.** dnsmasq answers whatever the case, and ipv6ddns finds the sections of the name however they are written.

## Discovery plugin

```yaml
discovery:
  plugins:
    router:
      type: linux
      interval: 60s
      address: 192.168.1.1
      username: root
      identity_file: /secrets/openwrt_key
      host_key: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

The keys are in the [configuration reference](reference/configuration.md#linux-freebsd).

What it reads:

- **The neighbor table**, `ip neigh`, of the families on: the hosts on the router's networks, its other VLANs included.
- **The DHCP leases**: dnsmasq's, `/tmp/dhcp.leases`, and the hosts file odhcpd writes of its DHCPv6 leases, `/tmp/hosts/odhcpd`. Their names become the hosts' [names](discovery.md#names). A lease doesn't register an address by itself: the neighbor table does.

## The router's updates

The router can send its public addresses to a [push source](sources.md#a-routers-updates) of ipv6ddns, with ddns-scripts and a custom update URL: the URL is in the [routers' table](sources.md#a-routers-updates).

On a router with several ISPs, see [multi-WAN](guides/multi-wan.md): with mwan3, each ISP's prefix must leave through its own interface.
