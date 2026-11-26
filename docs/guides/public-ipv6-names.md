# A public name for any device, over IPv6

Reach a device on your network from the internet by a name of your own, such as `nas.example.com`, over IPv6. The name keeps working when your ISP changes your prefix, and nothing is installed on the device.

With IPv6, each device has a public address of its own. On most home connections the ISP changes the prefix now and then, and the address of every device changes with it. A usual DDNS client only updates the name of the machine it runs on. ipv6ddns runs on one machine, finds the other devices on the network, and keeps the DNS record of each device you name at your DNS provider.

Running ipv6ddns as the Home Assistant app? Start with [the app's side of this guide](home-assistant/public-ipv6-names.md), which sends you back here.

## What you need

- **IPv6 from your ISP**, with the devices on your LAN having global addresses. A device has one if `ip -6 addr`, or its network settings, shows an address that starts with `2` or `3`.
- **A machine on the same LAN that is always on**, to run ipv6ddns. [Install it](../installation.md) as a binary, in Docker on the host's network, or as the Home Assistant app.
- **A domain at a DNS provider ipv6ddns can write to.** The examples use Cloudflare, with an API token that may edit the zone's DNS. [Other providers](#another-dns-provider) work the same way.
- **The device's MAC address.** The web report lists every host found, with its MAC.
- **Access to your router's firewall.** ipv6ddns only writes DNS records. The router decides what the internet may reach.

The examples use `example.com` for the domain, and `00:11:22:33:44:55` for the device's MAC. Use your own.

## The configuration

Put the Cloudflare token in a file `cloudflare_token`, beside the configuration.

```yaml
credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: ${file:cloudflare_token}
      zone: example.com
      ttl: 5m
      proxied: false

tasks:
  nas:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
        ip:
          type:
            - global
    endpoints:
      cloudflare:
        - nas              # nas.example.com

listeners:
  web:
    listen:
      - http://8053          # the web report: http://192.168.1.2:8053

webservers:
  main:
    listeners:
      - web
```

What each part does:

- **`credentials.cloudflare`** is where the names are kept: the zone `example.com` at Cloudflare. `proxied: false` makes the name answer with the device's own address. `ttl` is how long others keep an answer, so a short one makes a new prefix take effect sooner.
- **`tasks.nas`** gives the name `nas` the addresses of one device. Its filter takes the addresses found at this MAC that are `global`, which leaves out the link-local and private ones. A filter takes IPv6 addresses only, unless you say otherwise.
- **`webservers`** serves the [web report](../installation.md#the-web-report), on the listener `web`: the hosts found, the names, and the state of their updates. The report has no password. If the machine also faces the internet, give a LAN address, such as `http://192.168.1.2:8053`.

For another device, add another task with its MAC and its name. A task can have several names: write them all under the endpoint.

## Which of the device's addresses

A device often has more than one global address: a stable one, and temporary ones it makes for privacy and changes every day or so. With the configuration above, the name gets every global address found, so it may answer with several.

That works, since each of them reaches the device. For a server, you may want the stable address alone. Which filter gives it depends on the device:

- **The stable address is made from the MAC.** Many NAS units, cameras and other appliances do this. Add `eui64` to the filter's types. To have ipv6ddns ask for that address when the device never uses it by itself, turn on [solicitation](../discovery.md#solicitation).

  ```yaml
  # Added to the configuration above: the stable address of the NAS alone.
  tasks:
    nas:
      filter:
        - mac:
            address: "00:11:22:33:44:55"
          ip:
            type:
              - global
              - eui64
  discovery:
    solicit:
      ipv6: true
  ```

- **You gave the device a fixed end of the address**, such as `::5`. Match it with a [mask](../filtering.md#5-advanced-prefix--mask), under whatever prefix the ISP gives.
- **Neither.** Most computers and phones make a stable address that isn't from the MAC, and nothing outside the device can tell it from a temporary one. [What the host announced over mDNS](../filtering.md#what-the-host-announced-over-mdns) gives the stable addresses of Apple devices. Otherwise keep `global` alone.

The web report shows each address of the device and how it was seen, so you can see which ones a filter would take.

## Open the firewall

A home router lets nothing in over IPv6 until you allow it. Allow the port you need to the device, in the router's IPv6 firewall. There is no port forwarding to set: the rule only lets traffic through to the device's own address.

The device's address changes with the prefix, so a rule written for the whole address stops working when the prefix does. Where the router has it, use a rule that names the device, or one that matches only the end of the address, which stays the same.

Open only what you mean to publish. A device reached from the internet needs the same care as any server.

## Check that it works

Open the web report, at `http://192.168.1.2:8053`. Under `DNS`, it lists `nas.example.com` with its addresses and its last update. A name whose update fails is in red, with the provider's error.

Then ask a public DNS server:

```
dig AAAA nas.example.com @1.1.1.1
```

It gives the device's global address. To check from outside, use a connection that has IPv6 and isn't your own network, such as a phone on mobile data.

## Common problems

- **The name has no address.** The web report says so under `DNS`. Look for the device under `Discovery`: its MAC must be the one in the filter, and it must have a global address there. A stable address the device never uses may not be found until you turn on [solicitation](../discovery.md#solicitation).
- **The name is right, and the device doesn't answer.** The router's firewall doesn't let the port in, or the device's own firewall doesn't. From inside the network the same name works, because nothing crosses the router's firewall.
- **It works from some places only.** The place you connect from has no IPv6. The name has only an IPv6 address, so such a client can't reach it. [IPv4 too](#ipv4-too) adds an address for those.
- **The update fails.** The web report and the log give the provider's answer. With Cloudflare, check that the token may edit DNS in this zone, and that `zone` is the zone's own name, not a subdomain of it.
- **The name answers with an old address for a while.** Others keep an answer for the record's `ttl`. Lower it.

## IPv4 too

A client without IPv6 needs an IPv4 address to connect to. Your network has one public IPv4 address, at the router, which every device shares. A [source](../sources.md) finds it, and a task adds it to its names. On the router, forward the port to the device.

```yaml
# Added to the configuration above: the network's public IPv4 for the same name.
sources:
  wan:
    type: dns
tasks:
  nas:
    sources:
      - wan
```

This doesn't work behind carrier-grade NAT, where the router has no public IPv4 address of its own.

## Another DNS provider

The task stays the same. Only the credential changes, and the endpoint's name with it. This one is for DuckDNS, where the name is `mynas.duckdns.org`:

```yaml
credentials:
  duck:
    provider: duckdns
    settings:
      api_token: ${file:duckdns_token}

tasks:
  nas:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
        ip:
          type:
            - global
    endpoints:
      duck:
        - mynas            # mynas.duckdns.org

listeners:
  web:
    listen:
      - http://8053

webservers:
  main:
    listeners:
      - web
```

The settings of Route 53 and of every other provider are in the [providers reference](../reference/providers.md).

## More

- [Filtering](../filtering.md): every way to choose a device's addresses.
- [Sources](../sources.md): addresses that have no MAC, such as the network's public IPv4.
- [Every machine on the network by name](network-wide-names.md): names inside the network, for every device, with nothing set per host.
