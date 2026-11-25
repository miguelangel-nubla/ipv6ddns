# pfSense

ipv6ddns works with pfSense in three ways, which you can use separately or together:

1. **[DNS provider](#dns-provider):** it keeps the hosts it discovers as host overrides of the DNS Resolver, pfSense's Unbound, such as `nas.lan.example.com`. Every device that uses pfSense as its DNS server can then reach them by name.
2. **[Discovery plugin](#discovery-plugin):** it reads the firewall's neighbor tables and its DHCP leases, with the names the hosts gave.
3. **[Its updates](#its-updates):** pfSense sends its public addresses to ipv6ddns, as to a DynDNS service.

## DNS provider

pfSense has no API of its own: the provider uses the REST API package, `pfSense-pkg-RESTAPI`, of its version 2. Install it as [its documentation](https://github.com/jaredhendrickson13/pfsense-api) says, and make an API key in *System → REST API → Keys*, for a user that may read, change and apply the DNS Resolver's host overrides.

```yaml
credentials:
  firewall:
    provider: pfsense_restapi_unbound
    settings:
      address: https://192.168.1.1
      key: ${file:pfsense_key}
      tls_fingerprint: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
      zone: lan.example.com
```

The keys are in the [providers reference](reference/providers.md#pfsense_restapi_unbound). [Every machine on the network by name](guides/network-wide-names.md#your-routers-dns-instead) is the whole setup.

- **The certificate.** pfSense's web interface has a certificate signed by itself, unless you gave it another. Give its `tls_fingerprint`, which the certificate is then checked by, alone:

  ```
  openssl s_client -connect 192.168.1.1:443 </dev/null 2>/dev/null | openssl x509 -outform der | openssl dgst -sha256
  ```

- **One host override for each name,** with all its addresses: pfSense keeps one for each host and domain. When the name has none left, its override is removed. The overrides of other names stay.
- **After a change,** ipv6ddns applies the DNS Resolver's changes, so it serves them at once. A change that wasn't applied is applied at the next update.
- **No TTL.** pfSense's host overrides have none of their own: `ttl` is accepted, and not used.
- **No wildcard names,** such as `*.lan.example.com`: pfSense has none. A task that gives one fails with that error.

## Discovery plugin

The plugin logs in over SSH. Turn SSH on in *System → Advanced → Admin Access → Secure Shell*, for a user that may log in with a key, run commands, and read the DHCP leases.

```yaml
discovery:
  plugins:
    firewall:
      type: freebsd
      interval: 60s
      address: 192.168.1.1
      username: admin
      identity_file: /secrets/pfsense_key
      host_key: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

The keys are in the [configuration reference](reference/configuration.md#linux-freebsd). Give the plugin the firewall's `host_key`, so that nobody between can pose as it: `ssh-keyscan 192.168.1.1 | ssh-keygen -lf -`, from a trusted network, shows it.

What it reads:

- **The neighbor tables** of the families on: `ndp -an` for IPv6 and `arp -an` for IPv4. They have the hosts of every network pfSense routes, its VLANs included.
- **The DHCP leases**, of whichever server runs: Kea, `/var/lib/kea/dhcp4.leases` and `dhcp6.leases`; ISC dhcpd, `/var/dhcpd/var/db/dhcpd.leases`; or dnsmasq. Their names become the hosts' [names](discovery.md#names). A file that isn't there is no error.

## Its updates

pfSense can send its public addresses to a [push source](sources.md#a-routers-updates) of ipv6ddns, from *Services → Dynamic DNS*, with a custom type: the update URL is in the [routers' table](sources.md#a-routers-updates).

With several ISPs, pfSense sends the replies to connections that came in on a WAN back out of it: see [multi-WAN](guides/multi-wan.md).
