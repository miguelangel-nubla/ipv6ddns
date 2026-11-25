# How it works

## The problem

Pointing `my-web.example.com` at your application is both simpler and harder with IPv6 than with IPv4.

With IPv4, all traffic goes to one public address, your router's, and NAT forwards it to the right machine. With IPv6, NAT is neither needed nor a good idea, because every address is globally routable. Instead, each machine, each container, and even each application has its own public address (a GUA), and a client must connect to exactly that one. DNS names become almost mandatory, since nobody types `https://[2001:db8:85a3::8a2e:370:7334]`.

And those addresses change. IPv6 hosts rotate their temporary addresses. Many ISPs also change the network's prefix when the router restarts, or periodically, and then every address on the network changes at once.

## Why not a DDNS client on each host

A DDNS client on a server has three problems:

- It only knows that server's addresses, and it isn't obvious which of them the name should get.
- Each container or application may have an address of its own. The client would have to run inside each one, which means custom images.
- Many devices can't run a client at all: an appliance, a printer, an IP camera.

## The design

`ipv6ddns` runs once, anywhere on the network, and watches the whole network:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/architecture-dark.svg">
  <img src="images/architecture-light.svg" alt="ipv6ddns, a single instance anywhere on the LAN, finds the devices on your network, such as a server, a camera, a laptop or a printer, with no software on them, and keeps a DNS name pointing at each: at your DNS provider, in your router, or in its own DNS server. When a device's address changes, its name follows: server.mydomain.com has its AAAA record move from 2001:db8:1::a to 2001:db8:2::a, and its A record from 203.0.113.7 to 203.0.113.9; and a name on the LAN too: printer.mydomain.com has its A record move from 192.168.1.20 to 192.168.1.35.">
</picture>

1. [Discovery](discovery.md) finds every address on the network, together with the MAC that holds it. It listens, it probes, and it reads the routers' neighbor tables. A MAC address doesn't change when the IP addresses do, so it identifies the device.
2. Each task's [filters](filtering.md) choose which addresses its names get: those of this MAC, only global ones, only the stable one. A task's name can also be a [template](hostnames.md), such as `{hostname}`, which makes a name for every host the task matches.
3. When the addresses change, ipv6ddns updates the names' records at the [DNS providers](reference/providers.md). It waits a short debounce first, so that a prefix change becomes a single update. Alternatively, ipv6ddns answers the names itself, as the network's [resolver](resolver.md).

The configuration and the credentials for the whole network are in one place, and nothing is installed on the devices.

## Other uses

### Several ISPs at once

A network can have addresses from several ISPs at once, for example a fiber connection, a backup LTE connection and Starlink. The AAAA records hold the addresses of every connection that is up, so inbound connections fail over by themselves.

### IPv4 too

The same names can get A records too:

- the network's public IPv4, from a [source](sources.md), for a server behind NAT;
- the devices' local IPv4 addresses, from [discovery](discovery.md#local-ipv4-addresses), for a local DNS.
