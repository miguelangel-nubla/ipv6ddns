# OPNsense

ipv6ddns works with OPNsense in three ways, which you can use separately or together:

1. **[DNS provider](#dns-provider):** it keeps the hosts it discovers as host overrides of Unbound, OPNsense's DNS resolver, such as `nas.lan.example.com`. Every device that uses OPNsense as its DNS server can then reach them by name.
2. **[Discovery plugin](#discovery-plugin):** it reads the firewall's neighbor tables and its DHCP leases, with the names the hosts gave.
3. **[Its updates](#its-updates):** OPNsense sends its public addresses to ipv6ddns, as to a DynDNS service.

## DNS provider

The provider uses OPNsense's API, with an API key and its secret. Make them for a user of their own, in *System → Access → Users*, under the user's API keys, and give that user only what Unbound's host overrides need: the provider reads, adds and removes them, and reconfigures Unbound to serve them.

```yaml
credentials:
  firewall:
    provider: opnsense_unbound
    settings:
      address: https://192.168.1.1
      key: ${file:opnsense_key}
      secret: ${file:opnsense_secret}
      tls_fingerprint: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
      zone: lan.example.com
      ttl: 5m
```

The keys are in the [providers reference](reference/providers.md#opnsense_unbound). [Every machine on the network by name](guides/network-wide-names.md#your-routers-dns-instead) is the whole setup.

- **The certificate.** OPNsense's web interface has a certificate signed by itself, unless you gave it another. Give its `tls_fingerprint`, which the certificate is then checked by, alone:

  ```
  openssl s_client -connect 192.168.1.1:443 </dev/null 2>/dev/null | openssl x509 -outform der | openssl dgst -sha256
  ```

- **One host override for each address.** A name with an IPv6 and an IPv4 address has two. The overrides of other names stay.
- **An override you disabled is yours.** ipv6ddns leaves it as it is, whatever its address, and adds none beside it: see [disabled records](configuration.md#disabled-records).
- **After a change,** ipv6ddns reconfigures Unbound, so it serves the overrides at once. A change whose reconfigure failed is reconfigured at the next update.

## Discovery plugin

The plugin logs in over SSH. Turn SSH on in *System → Settings → Administration → Secure Shell*, for a user that may log in with a key, and that can read the DHCP leases.

```yaml
discovery:
  plugins:
    firewall:
      type: freebsd
      interval: 60s
      address: 192.168.1.1
      username: root
      identity_file: /secrets/opnsense_key
      host_key: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

The keys are in the [configuration reference](reference/configuration.md#linux-freebsd). Give the plugin the firewall's `host_key`, so that nobody between can pose as it: `ssh-keyscan 192.168.1.1 | ssh-keygen -lf -`, from a trusted network, shows it.

What it reads:

- **The neighbor tables** of the families on: `ndp -an` for IPv6 and `arp -an` for IPv4. They have the hosts of every network OPNsense routes, its VLANs included.
- **The DHCP leases**, of whichever server runs: Kea, `/var/db/kea/kea-leases4.csv` and `kea-leases6.csv`; ISC dhcpd; or dnsmasq. Their names become the hosts' [names](discovery.md#names). A file that isn't there is no error.

## Its updates

OPNsense can send its public addresses to a [push source](sources.md#a-routers-updates) of ipv6ddns, from *Services → Dynamic DNS*: the settings are in the [routers' table](sources.md#a-routers-updates).

With several ISPs, OPNsense sends the replies to connections that came in on a WAN back out of it: see [multi-WAN](guides/multi-wan.md).
