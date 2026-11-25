# Names from your DHCP server

Your DHCP server knows the name each device asks for with its lease. With its dynamic DNS, it can send those names to ipv6ddns, signed with a key. ipv6ddns gives each name to the device that discovery found at that address. From there, the name is like one the device said itself: a task's `{hostname}` publishes it, with every address of the device, IPv6 included, wherever the task writes.

That's more than the DHCP server's own DNS updates give: the server knows the IPv4 address it leased, and ipv6ddns adds the device's IPv6 addresses, which it got without DHCP.

## What you need

- ipv6ddns running with a [resolver](../resolver.md), here on `192.168.1.2`, and discovery of IPv4 on, which finds the devices at their leased addresses.
- A DHCP server with RFC 2136 dynamic DNS signed with TSIG: Kea, with its DHCP-DDNS daemon, or ISC dhcpd. Kea is the one tested.

## The configuration

Make a key for the DHCP server: `tsig-keygen -a hmac-sha256 kea`, and put its secret, the base64 after `secret`, in a file beside the configuration, `tsig_kea`.

```yaml
discovery:
  ipv4:
    enabled: true

credentials:
  home:
    provider: resolver
    settings:
      zone: lan.example.com

resolvers:
  lan:
    listen:
      - 192.168.1.2
    upstream:
      - 1.1.1.1
    updates:
      keys:
        kea:
          secret: ${file:tsig_kea}
          permissions:
            - names:
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
        - "{hostname}"
```

- **`names`** takes the names of `lan.example.com` that the server sends, with their addresses. It may change nothing else: no other zone, and no record but A, AAAA and the DHCID records of the conflict checks.
- **The task** is the one of [every machine on the network by name](network-wide-names.md): the names from the DHCP server are some of the `{hostname}` it publishes. Any other task's endpoints work, a DNS server of yours or a public zone.

## Kea

In `kea-dhcp4.conf`, or `kea-dhcp6.conf`, the names go to the DHCP-DDNS daemon:

```json
"dhcp-ddns": {
  "enable-updates": true
},
"ddns-send-updates": true,
"ddns-qualifying-suffix": "lan.example.com.",
"ddns-conflict-resolution-mode": "check-with-dhcid"
```

In `kea-dhcp-ddns.conf`, the daemon sends them to ipv6ddns:

```json
{
  "DhcpDdns": {
    "tsig-keys": [
      {
        "name": "kea",
        "algorithm": "HMAC-SHA256",
        "secret": "<the secret of tsig_kea>"
      }
    ],
    "forward-ddns": {
      "ddns-domains": [
        {
          "name": "lan.example.com.",
          "key-name": "kea",
          "dns-servers": [
            {
              "ip-address": "192.168.1.2",
              "port": 53
            }
          ]
        }
      ]
    },
    "reverse-ddns": {
      "ddns-domains": []
    }
  }
}
```

Leave `reverse-ddns` empty: the resolver answers the [reverse names](../resolver.md#reverse-names) of the names it has, and refuses an update of a reverse zone.

## ISC dhcpd

```
ddns-update-style standard;
ddns-domainname "lan.example.com.";

key kea {
	algorithm hmac-sha256;
	secret "<the secret of tsig_kea>";
};

zone lan.example.com. {
	primary 192.168.1.2;
	key kea;
}
```

## Check that it works

Renew a device's lease, or reconnect it. ipv6ddns logs the update:

```
resolver lan: key kea: updated names: printer.lan.example.com
```

The web report lists the name under the device, said by `updates.kea`, and the resolver answers it: `dig printer.lan.example.com`, with every address of the device.

## How names are kept

- **A name goes to the device at its address.** Discovery finds the device at the address it leased, as it talks, and the name is given to it. A name whose address discovery hasn't seen yet waits, and is given within a minute once it has.
- **Conflicts are the DHCP server's**, as RFC 4703 has them: a DHCID record of each name says which client it is of. Another client that asks for the name is refused, and the first keeps it. With `ddns-conflict-resolution-mode: no-check-without-dhcid`, Kea sends no checks, and the last client to ask gets it.
- **The checks see the names the DHCP server sent alone.** A name a device says itself, over mDNS, or a record of the resolver's own, is not "in use" to them: two devices with one name are told apart as discovery tells any, as `1.printer` and `2.printer`.
- **Names are one label below the zone**, as `printer.lan.example.com`: an update of `a.b.lan.example.com`, or of a wildcard, is refused.
- **A name the server removes**, when the lease is released or expires, isn't given again, and goes when discovery's [names lifetime](../reference/configuration.md#discovery-hostnames) is over, an hour by default, unless the device says it otherwise.
- **A restart keeps the names**, in `names-lan.example.com.json` beside the configuration: Kea doesn't send them again when a lease is renewed.
- **The TTLs the server sends are ignored**: the endpoint's credential sets its own.
- **Names written in the configuration win**, as always: a task that names a device by its MAC keeps that name.

## Common problems

- **Nothing in the log.** The server's updates don't reach ipv6ddns: check the address in `dns-servers`, and that the DHCP server is in the resolver's `allow`.
- **`NOTAUTH`, with `BADSIG` or `BADKEY`.** The secret, the key's name or its algorithm differ: they must be the same on both sides.
- **`REFUSED`.** The log says why, as a zone other than the permission's, or a reverse zone.
- **A name that never reaches a device.** Discovery hasn't found the device at its address: check that discovery of IPv4 is on, and that the device is in the web report.

## More

- [Dynamic updates](../resolver.md#dynamic-updates): the keys, the permissions, and the answers.
- [Names by the hosts' names](../hostnames.md): how a name becomes a name of a task, and when two devices share one.
- [The configuration reference](../reference/configuration.md#updates): every key.
