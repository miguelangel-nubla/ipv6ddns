# Multi-WAN: a public name on a network with several ISPs

Reach a device from the internet by one name, such as `nas.example.com`, on a network that has more than one internet connection: fiber and a backup LTE link, two ISPs, or Starlink beside either. Over IPv6 each connection gives the network a prefix of its own, so each device has a public address from every ISP. The name gets all of them, and when a connection goes down, its addresses leave the name.

This guide adds to [a public name for any device, over IPv6](public-ipv6-names.md). Set that up first: the credential, the task and the firewall are the same here.

## How it works

Your router gets a prefix from each ISP and announces all of them on the LAN. A device makes an address in each, so with two ISPs the NAS has two global addresses, say `2001:db8:a123::5` from ISP A and `2001:db8:b456::5` from ISP B. ipv6ddns finds both, and the name gets both AAAA records.

- **A client connects to one of them.** Each address arrives over its own ISP. A browser tries the addresses together and takes whichever answers first, so it uses whichever connection is up within a second or so. Other clients try them in order, and may wait for a timeout on an address that doesn't answer before trying the next one.
- **When an ISP goes down, its addresses leave the name**, once the devices have dropped them. Your router has to make them, as [below](#make-the-devices-drop-a-dead-isps-addresses): while a device keeps an address, it still answers for it, and ipv6ddns keeps it in the name.
- **When the ISP is back,** the devices make their addresses in its prefix again, a new one if the ISP gave a new prefix, and the name gets them.

## What you need

- **Everything in [a public name for any device](public-ipv6-names.md#what-you-need)**, working with one ISP.
- **A router that announces a prefix from each ISP on the LAN.** Check on a device: `ip -6 addr`, or its network settings, shows a global address in each prefix. A router that gives the LAN one prefix, or private addresses translated per ISP (NPTv6), leaves the devices one public address, or none: this guide doesn't apply.
- **Access to your router's settings for the prefixes' lifetimes and for routing**, as [below](#make-replies-leave-through-the-isp-they-came-from).

## The configuration

The one of [the public name guide](public-ipv6-names.md#the-configuration), with shorter times:

```yaml
credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: ${file:cloudflare_token}
      zone: example.com
      ttl: 2m              # clients ask again soon after a connection goes down
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
        - nas              # nas.example.com: every global address, of every ISP

discovery:
  ipv6:
    lifetime: 10m          # an address the devices dropped leaves the name within 10 minutes

webserver:
  listen:
    - 8053
```

- **`discovery.ipv6.lifetime`** is how long an address stays after it was last seen. Once the devices drop a dead ISP's addresses, they leave the name within this time. The default is an hour. A shorter one has ipv6ddns probe the devices more often: every third of it.
- **`ttl`** is how long others keep an answer. A client that asked before the change may use the dead address until then.
- The two add up: in the worst case, a client may try the dead address for `lifetime` plus `ttl` after the devices dropped it, and the debounce of the credential, 10 seconds by default.

## Make the devices drop a dead ISP's addresses

This is the part ipv6ddns can't do for you. A device keeps an address until the prefix's lifetime that the router announced ends, and keeps answering for it meanwhile. ipv6ddns pings an IPv6 address before it expires, so an address the device still has stays in the name.

What the router does when an ISP goes down varies:

- **It withdraws the prefix**, announcing it with a lifetime of 0. The devices drop their addresses in it at once, and the name follows within `lifetime`. This is what you want.
- **It deprecates the prefix**, announcing it with a preferred lifetime of 0. The devices stop using those addresses for new connections, but keep them, and keep answering for them, until the valid lifetime ends. That can be days.
- **It does nothing**, and the devices keep the prefix until its valid lifetime ends.

To find out, unplug one ISP and run `ip -6 addr` on a Linux device after a minute. An address listed as `deprecated`, or still there, is in the name. Then, in the router's settings for router advertisements or DHCPv6:

- Have it withdraw the prefix of an interface that goes down, if it has the option.
- Otherwise, lower the valid lifetime it announces, for example to 30 minutes. The router announces again every few minutes while the ISP is up, so the devices keep their addresses; when it stops, they drop them within that time.

## Make replies leave through the ISP they came from

A connection that arrives at `2001:db8:b456::5`, ISP B's address, must be answered through ISP B. ISP A drops traffic from an address that isn't its own. So the router must route by source address: what comes from ISP B's prefix leaves through ISP B.

- **pfSense and OPNsense** do this for traffic that a firewall rule on a WAN interface lets in, with `reply-to`, unless it is turned off.
- **OpenWrt with mwan3** needs a rule that sends traffic from each ISP's prefix out its own interface.
- **A Linux router of your own** needs a routing rule per prefix, such as `ip -6 rule add from 2001:db8:b456::/48 table isp-b`, with a default route through ISP B in that table.

Without it, the name works through the ISP that the router's default route uses, and every connection to the other ISP's addresses fails: some clients then fall back to the address that works, after a timeout.

## A name for each ISP

To reach a device through one ISP on purpose, give it a name per ISP. Each name takes the addresses of the device that are in that ISP's range. The prefix an ISP delegates can change, but it stays within the range the ISP has, so match the range: look up one of your addresses with `whois` to find it.

```yaml
# Added to the configuration above: nas-a over ISP A, and nas-b over ISP B.
tasks:
  nas-a:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
        ip:
          type:
            - global
          prefix: "2001:db8:a000::/36"   # ISP A's range
    endpoints:
      cloudflare:
        - nas-a            # nas-a.example.com
  nas-b:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
        ip:
          type:
            - global
          prefix: "2001:db8:b000::/36"   # ISP B's range
    endpoints:
      cloudflare:
        - nas-b            # nas-b.example.com
```

`nas.example.com` keeps every address, and fails over; `nas-a` and `nas-b` don't, and are for testing each connection, or for a client that must use one of them.

## IPv4

IPv4 is shared through NAT, one public address per ISP at the router. A [source](../sources.md) of type `dns` finds the public IPv4 that your outgoing traffic uses, which is one ISP's at a time: the name gets that one, and it changes when the router's outgoing traffic moves to the other ISP. The ports must be forwarded on both ISPs' interfaces.

## Check that it works

1. With both ISPs up, open the [web report](../installation.md#the-web-report). Under `DNS`, `nas.example.com` has an address from each prefix. `dig AAAA nas.example.com @1.1.1.1` gives both.
2. From a machine on another network that has IPv6, connect to the port at each address: `nc -6 -zv 2001:db8:a123::5 443`, and the same for ISP B's. Both must connect. If one doesn't, the routing [above](#make-replies-leave-through-the-isp-they-came-from), or the firewall of that ISP's interface, is missing.
3. Unplug ISP B. Within a minute, on a Linux device, `ip -6 addr` must no longer list ISP B's address, or the router's prefix lifetime is the [next thing to set](#make-the-devices-drop-a-dead-isps-addresses).
4. Within `lifetime`, the web report shows the name without ISP B's address, and its update. `dig` gives ISP A's alone once the `ttl` has passed.
5. Plug ISP B back in. The address comes back, in the old prefix or a new one.

## Common problems

- **Connections to one ISP's address fail, from everywhere.** Replies leave through the other ISP: set up the [routing by source](#make-replies-leave-through-the-isp-they-came-from). Or that interface's firewall doesn't let the port in.
- **A dead ISP's address stays in the name for hours.** The devices still have it. See [what the router announces](#make-the-devices-drop-a-dead-isps-addresses).
- **A client takes long to connect while an ISP is down.** It tried the dead address first, as an address it got before the change, within the `ttl`. Lower the `ttl`, and `lifetime`.
- **The name has one ISP's addresses only, with both up.** The router announces only one prefix on the LAN. Check on a device with `ip -6 addr`.

## More

- [A public name for any device, over IPv6](public-ipv6-names.md): the setup this guide adds to.
- [Filtering](../filtering.md): matching by prefix, by type, and more.
- [Discovery: lifetimes](../discovery.md#lifetimes): how long an address stays, and what keeps it.
