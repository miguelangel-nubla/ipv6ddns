# Every device by name, in AdGuard Home

You already run AdGuard Home as the DNS server of your network. ipv6ddns can write the name of every device into it, such as `nas.lan.example.com` and `printer.lan.example.com`, and keep each name's addresses right as they change. Nothing changes on your router or your devices: they ask AdGuard Home as before.

ipv6ddns finds the hosts on the network and learns what each one is called. It keeps each name in AdGuard Home as DNS rewrites, the list under *Filters → DNS rewrites*, through AdGuard Home's own API. It doesn't answer DNS itself here, so the two don't compete for port 53.

Running both as Home Assistant apps? Start with [the app's side of this guide](home-assistant/adguard-home.md), which sends you back here.

## What you need

- **AdGuard Home, as the DNS server your devices already use.** Any recent version works. Version 0.107.68 or later is needed for ipv6ddns to see which rewrites you disabled.
- **A machine on the same LAN that is always on**, to run ipv6ddns. It can be the machine AdGuard Home runs on. [Install it](../installation.md) as a binary, in Docker on the host's network, or as the Home Assistant app.
- **A user of AdGuard Home's web interface**, with its password.

The examples use `192.168.1.2` for the machine that runs both, and `http://192.168.1.2:3000` for AdGuard Home's web interface. Use the address you open AdGuard Home at.

## The configuration

Put the password in a file `adguard_password`, beside the configuration.

```yaml
discovery:
  ipv4:
    enabled: true          # find IPv4 addresses too; the default is IPv6 only

credentials:
  adguard:
    provider: adguardhome
    settings:
      address: http://192.168.1.2:3000
      username: admin
      password: ${file:adguard_password}
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
      adguard:
        - "{hostname}"     # printer.lan.example.com
        - "{n}.{hostname}" # 1.printer.lan.example.com, 2.printer.lan.example.com when two say printer

webserver:
  listen:
    - 8053                 # the web report: http://192.168.1.2:8053
```

What each part does:

- **`discovery`** finds the hosts. IPv6 is on by default. `ipv4: enabled: true` adds the IPv4 addresses, so that a name also works for devices and clients without IPv6.
- **`credentials.adguard`** is your AdGuard Home. `zone` is the domain the names are under. AdGuard Home has no zones, so any domain works: a subdomain of a domain you own, or `home.arpa`, which is [set aside for home networks](https://www.rfc-editor.org/rfc/rfc8375). Don't use `.local`.
- **`tasks.lan`** gives every host a name. Its filter takes every address of every host, except link-local addresses, which only work on one link. `{hostname}` is the name the host says it has.
- **`webserver`** serves the [web report](../installation.md#the-web-report): the hosts found, their names, and the state of each update. The report has no password. If the machine also faces the internet, give a LAN address, such as `192.168.1.2:8053`.

How a host gets its name, and what to do for one that says no name, is in [every machine on the network by name](network-wide-names.md#the-configuration). To give a device a name of your choice, by its MAC, see [a name that matters](network-wide-names.md#a-name-that-matters): the task there works here, with `adguard` as its endpoint.

## Check that it works

Open the web report, at `http://192.168.1.2:8053`. Under `DNS`, it lists each name with its addresses and its last update. A name whose update fails is in red, with what AdGuard Home answered.

In AdGuard Home, open *Filters → DNS rewrites*. Each name is there, once for each of its addresses.

Then ask from any device on the network:

```
dig printer.lan.example.com
dig printer.lan.example.com AAAA
```

To make a bare `printer` work too, set your router's local domain, or DHCP's domain search option, to `lan.example.com`.

## What to know

- **One rewrite for each address.** A device with one IPv4 and two IPv6 addresses has three rewrites. With many devices, the list in AdGuard Home gets long.
- **Your own rewrites stay.** ipv6ddns only touches rewrites of the names it keeps, whose answer is an address. A rewrite with another answer, such as an alias to another name, is left alone. So is a rewrite you disabled: its address stays unanswered, and ipv6ddns adds none beside it.
- **A name with a rewrite answers nothing else.** That is how AdGuard Home works: once a name has a rewrite, AdGuard Home no longer asks upstream for it. Choose a domain for these names that has no records of its own elsewhere.
- **No reverse names.** AdGuard Home doesn't answer an address back to its name from a rewrite.
- **The TTL is AdGuard Home's.** It answers a rewrite with its own short TTL, so a change is seen within seconds.
- **A device that left keeps its name for a while.** A name stays until discovery lets the host go, after the host's [lifetime](../discovery.md#lifetimes), an hour by default. A host that leaves while ipv6ddns isn't running keeps its rewrites until you remove them: see [when a host leaves](../hostnames.md#when-a-host-leaves).

## Common problems

- **`the username or the password is refused`.** Check both. AdGuard Home blocks an address that fails to log in several times, for 15 minutes by default, and that includes your own browser when it is on the same machine as ipv6ddns. Fix the password, wait, and restart ipv6ddns.
- **`not an answer of AdGuard Home's API`.** The address isn't AdGuard Home's web interface. Give the address you open in the browser, with its port, and `https://` if it has a certificate. For a certificate of your own, see `tls_fingerprint` in the [providers reference](../reference/providers.md#adguardhome).
- **A device has no name.** The device says no name, or none that discovery hears. The web report lists every host found, with the names it has.
- **The names are in AdGuard Home, and a device doesn't resolve them.** The device asks another DNS server. Check its DNS servers with `resolvectl status`, `ipconfig /all`, or its network settings.

## More

- [Names by the hosts' names](../hostnames.md): the placeholders, and what happens when hosts share a name.
- [A public name for any device, over IPv6](public-ipv6-names.md): the same devices, by name from the internet.
- [Every machine on the network by name](network-wide-names.md): without AdGuard Home, with ipv6ddns answering DNS itself.
