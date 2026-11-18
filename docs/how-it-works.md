# How it works

## The problem

Pointing `my-web.example.com` at your application is both simpler and harder with IPv6 than with IPv4.

With IPv4, the traffic goes to the one public address, your router's, and NAT forwards it. With IPv6, that is neither a good idea nor needed: addresses are globally routable. But each machine, each container, even each application, has its own public address, a GUA, and you need the exact one: DNS names become almost mandatory, as nobody types `https://[2001:db8:85a3::8a2e:370:7334]`.

Those addresses change. IPv6 hosts rotate temporary addresses, and many ISPs change the network's prefix when the router restarts, or periodically, so every address of the network changes at once.

## Why not a DDNS client on each host

A DDNS client on the server only knows the server's addresses, and which of them the name should get is not obvious. Each container or application may have its own: the client would have to run in each, which means custom images. Many devices can't run one at all, as an appliance, a printer, or an IP camera.

## The design

`ipv6ddns` runs once, anywhere on the network, and watches it:

1. [Discovery](discovery.md) finds every address on the network with the MAC that has it: by listening, by probing, and by reading the neighbor tables of the routers. A MAC address doesn't change when the addresses do, so it identifies the device.
2. Each task's [filters](filtering.md) choose the addresses of its names: of this MAC, global, stable.
3. When they change, the names' records at the [DNS providers](reference/providers.md) are updated, after a short debounce that gathers a prefix change into one update.

The configuration and the credentials are in one place, for the whole network, and nothing is installed on the devices.

## Other uses

### Several ISPs at once

You can have the addresses of several ISPs at once, as a fiber connection, a backup LTE one and Starlink: the AAAA records hold the addresses of every connection that is up, so inbound connections fail over by themselves.

### IPv4 too

The same names can get A records: the network's public IPv4 from a [source](sources.md), for a server behind NAT, and the devices' local IPv4 addresses from [discovery](discovery.md#local-ipv4-addresses), for a local DNS.
