# Every device by name, in Pi-hole

You already run Pi-hole as the DNS server of your network. ipv6ddns can write the name of every device into it, such as `nas.lan.example.com` and `printer.lan.example.com`, and keep each name's addresses right as they change. Nothing changes on your router or your devices: they ask Pi-hole as before.

ipv6ddns finds the hosts on the network and learns what each one is called. It keeps each name in Pi-hole as local DNS records, the list under *Settings → Local DNS Records*, through Pi-hole's own API. It doesn't answer DNS itself here, so the two don't compete for port 53.

## What you need

- **Pi-hole 6 or later, as the DNS server your devices already use.** Earlier versions have no API for these records.
- **A machine on the same LAN that is always on**, to run ipv6ddns. It can be the machine Pi-hole runs on. [Install it](../installation.md) as a binary, or in Docker on the host's network.
- **Pi-hole's password**: the one of its web interface, or an application password, from *Settings → Web interface / API*. With two-factor authentication, only an application password works.

The examples use `192.168.1.2` for the machine that runs both, and `http://192.168.1.2` for Pi-hole's web interface. Use the address you open Pi-hole at, without `/admin`.

## The configuration

Put the password in a file `pihole_password`, beside the configuration.

```yaml
discovery:
  ipv4:
    enabled: true          # find IPv4 addresses too; the default is IPv6 only

credentials:
  pihole:
    provider: pihole
    settings:
      address: http://192.168.1.2
      password: ${file:pihole_password}
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
      pihole:
        - "{hostname}"     # printer.lan.example.com
        - "{n}.{hostname}" # 1.printer.lan.example.com, 2.printer.lan.example.com when two say printer

webserver:
  listen:
    - 8053                 # the web report: http://192.168.1.2:8053
```

What each part does:

- **`discovery`** finds the hosts. IPv6 is on by default. `ipv4: enabled: true` adds the IPv4 addresses, so that a name also works for devices and clients without IPv6.
- **`credentials.pihole`** is your Pi-hole. `zone` is the domain the names are under. Pi-hole has no zones, so any domain works: a subdomain of a domain you own, or `home.arpa`, which is [set aside for home networks](https://www.rfc-editor.org/rfc/rfc8375). Don't use `.local`.
- **`tasks.lan`** gives every host a name. Its filter takes every address of every host, except link-local addresses, which only work on one link. `{hostname}` is the name the host says it has.
- **`webserver`** serves the [web report](../installation.md#the-web-report): the hosts found, their names, and the state of each update. The report has no password. If the machine also faces the internet, give a LAN address, such as `192.168.1.2:8053`.

How a host gets its name, and what to do for one that says no name, is in [every machine on the network by name](network-wide-names.md#the-configuration). To give a device a name of your choice, by its MAC, see [a name that matters](network-wide-names.md#a-name-that-matters): the task there works here, with `pihole` as its endpoint.

## Check that it works

Open the web report, at `http://192.168.1.2:8053`. Under `DNS`, it lists each name with its addresses and its last update. A name whose update fails is in red, with what Pi-hole answered.

In Pi-hole, open *Settings → Local DNS Records*. Each name is there, once for each of its addresses.

Then ask from any device on the network:

```
dig printer.lan.example.com
dig printer.lan.example.com AAAA
dig -x 192.168.1.20
```

The first two commands give the printer's addresses. The third gives the printer's name back.

To make a bare `printer` work too, see [point the network at it](network-wide-names.md#point-the-network-at-it).

## What to know

- **One record for each address.** A device with one IPv4 and two IPv6 addresses has three records. With many devices, the list in Pi-hole gets long.
- **Your own records stay.** ipv6ddns only touches a record of a name it keeps, written as one address and that name. A record you wrote with several names on its line is left alone.
- **Reverse names work.** Pi-hole answers an address back to its name from these records.
- **One session.** ipv6ddns logs in once and keeps the session, so it uses one of the sessions Pi-hole's API allows at a time.
- **A device that left keeps its name for a while**, as any name ipv6ddns keeps: see [common problems](network-wide-names.md#common-problems).

## Common problems

- **`the password is refused`.** Check it. With two-factor authentication on, make an application password and give that one.
- **`not an answer of Pi-hole's API, which is of its version 6 and later`.** The address isn't Pi-hole's web interface, or Pi-hole is older than version 6. Give the address without `/admin`, with its port if it isn't 80, and `https://` if it has a certificate. For Pi-hole's own certificate, see `tls_fingerprint` in the [providers reference](../reference/providers.md#pihole).
- **Pi-hole refuses the change.** A setting given to Pi-hole in its container's environment can't be changed through the API. If your local DNS records are set with `FTLCONF_dns_hosts`, move them to Pi-hole's own settings.
- **A device has no name, or doesn't resolve the names that are in Pi-hole:** see [common problems](network-wide-names.md#common-problems), which are the same with any DNS server.

## More

- [Names by the hosts' names](../hostnames.md): the placeholders, and what happens when hosts share a name.
- [A public name for any device, over IPv6](public-ipv6-names.md): the same devices, by name from the internet.
- [Every machine on the network by name](network-wide-names.md): without Pi-hole, with ipv6ddns answering DNS itself.
