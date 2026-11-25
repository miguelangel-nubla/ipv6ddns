# UniFi

ipv6ddns works with a UniFi gateway in three ways, which you can use separately or together:

1. **[DNS provider](#dns-provider):** it keeps the gateway's local DNS records, its *DNS Records*, for the hosts it discovers, such as `nas.lan.example.com`. Every device that uses the gateway as its DNS server, as they do by default, can then reach them by name.
2. **[Discovery plugin](#discovery-plugin):** it reads the clients the gateway has connected now, with their addresses and their names.
3. **[The gateway's updates](#the-gateways-updates):** the gateway sends its public addresses to ipv6ddns, as to a DynDNS service.

It talks to the UniFi Network API of a UniFi OS console, such as a UDM, UDR, UCG or UXG, of UniFi OS Server, or of a self-hosted UniFi Network Application.

## Logging in

| Where UniFi Network runs | How ipv6ddns logs in |
|---|---|
| A UniFi OS console, or UniFi OS Server | An API key: in the console, *Settings → Control Plane → Integrations → Create API Key*. Or a username and password |
| A self-hosted UniFi Network Application | A username and password: it has no API keys |

- **A local user.** A user with two-factor authentication can't log in: use an API key, or a local user without it.
- **What it may do.** The discovery plugin only reads. The DNS provider changes the network's settings, so its key's user, or its user, must be allowed to. Give each its own, so the plugin's can't change anything.
- **The certificate.** A console's certificate is its own, signed by itself, so give its fingerprint, `tls_fingerprint`. The certificate is then checked by it alone:

  ```
  openssl s_client -connect 192.168.1.1:443 </dev/null 2>/dev/null | openssl x509 -outform der | openssl dgst -sha256
  ```

- **The site** is `default` unless you made others.

## DNS provider

```yaml
credentials:
  gateway:
    provider: unifi
    settings:
      address: https://192.168.1.1
      api_key: ${file:unifi_api_key}
      tls_fingerprint: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
      zone: lan.example.com
      ttl: 5m

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
      gateway:
        - "{hostname}"
```

The keys are in the [providers reference](reference/providers.md#unifi). [Every machine on the network by name](guides/network-wide-names.md#your-routers-dns-instead) is the whole setup.

### Requirements

- **UniFi Network 8.2.93 or later**, the first with DNS Records.
- **The devices ask the gateway.** The names are the gateway's: a device that uses another DNS server doesn't get them.

### How the records are kept

- **One record for each address.** A name with an IPv6 and an IPv4 address has an AAAA record and an A record.
- **A record you disabled is yours.** ipv6ddns leaves it as it is, whatever its address, and adds none beside it: see [disabled records](configuration.md#disabled-records). So is a record of the name of another type, such as a CNAME.
- **The TTL** is a day at most. Without one, the gateway answers with its own.
- **`zone`** is only what a name written alone, such as `nas`, is completed with: UniFi has no zones.

## Discovery plugin

```yaml
discovery:
  plugins:
    gateway:
      type: unifi
      interval: 60s
      address: https://192.168.1.1
      api_key: ${file:unifi_api_key_read}
      tls_fingerprint: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The keys are in the [configuration reference](reference/configuration.md#unifi).

What it registers, of each client the gateway has connected now, UniFi's own devices included:

- **Its IPv4 address**, with [IPv4](discovery.md#local-ipv4-addresses) on, **and its IPv6 addresses**, where UniFi has them.
- **Two names**, when [names](discovery.md#names) are on: the host name the client gave the gateway's DHCP server, and the name you gave it in UniFi. A space in a name becomes a hyphen, as `living-room-tv`. A name with a character no host name has, such as an apostrophe, is left out.

UniFi doesn't always know a client's IPv6 addresses, the privacy ones in particular. Keep local discovery on to find those: the plugin adds what UniFi knows, and the names.

## The gateway's updates

The gateway can send its public addresses to a [push source](sources.md#a-routers-updates) of ipv6ddns, which gives them to names: the public IPv4 of the network, for an A record beside a device's IPv6. In *Settings → Internet → Dynamic DNS*, add a *custom* service: the server and path are in the [routers' table](sources.md#a-routers-updates).
