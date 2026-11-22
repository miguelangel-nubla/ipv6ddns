# DNS providers

<!-- Generated from the schemas by `go test ./internal/docgen -update`: edit them, not this page. -->

A credential's `provider` is one of these, and its `settings` are those of the provider. An unknown setting is an error. A `ttl` is a duration string, as `5m`. Adding a provider: see [CONTRIBUTING](../../CONTRIBUTING.md).

- [`cloudflare`](#cloudflare)
- [`duckdns`](#duckdns)
- [`gravity`](#gravity)
- [`mikrotik`](#mikrotik)
- [`openwrt`](#openwrt)
- [`opnsense_unbound`](#opnsense_unbound)
- [`pfsense_restapi_unbound`](#pfsense_restapi_unbound)
- [`resolver`](#resolver)
- [`route53`](#route53)
- [`technitium`](#technitium)
- [`windows`](#windows)

## cloudflare

Cloudflare DNS, through its API. The free plan works.

| Key | Takes | |
|---|---|---|
| `api_token` | string | **Required.** An API token with Zone.DNS edit permission on the zone. |
| `zone` | string | **Required.** The zone, as example.com. |
| `ttl` | string | **Required.** The records' TTL, as 5m or 1h. 1s means Cloudflare's automatic TTL. |
| `proxied` | boolean | **Required.** Whether traffic to the records goes through Cloudflare's proxy. |

## duckdns

DuckDNS: one A and one AAAA record per name, under duckdns.org.

| Key | Takes | |
|---|---|---|
| `api_token` | string | **Required.** The account's token. |

## gravity

Gravity, a DNS server for home networks, through its API. The zone itself is the record @. A zone made with the web interface's Gravity-hosted preset answers from memory first, and Gravity v0.34.0 and later then gives one record of each type: a host with several IPv6 addresses resolves to just one of them. To have all of them answered, leave the zone only its etcd handler.

| Key | Takes | |
|---|---|---|
| `server` | string | **Required.** Its address, as http://gravity.lan. |
| `api_key` | string | **Required.** An API key. |
| `zone` | string | **Required.** The zone, ending in a dot, as home.lan. |
| `ttl` | string | The records' TTL, as 5m or 1h. Default: 5m. Gravity v0.32 and later keeps a TTL per record, and requires it. |

## mikrotik

MikroTik RouterOS static DNS, /ip/dns/static, through its API. RouterOS matches a name's records by its exact spelling, capitals included: when a hostname's capitals change in the configuration, the old records stay, and must be removed by hand. See docs/mikrotik.md.

| Key | Takes | |
|---|---|---|
| `address` | string | **Required.** The router, with a port unless it's the default: 8728, or 8729 with TLS. |
| `use_tls` | boolean | Whether to use the API over TLS, the api-ssl service. Without it, the password crosses the network unencrypted. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the router's certificate, in hex. With it, only that certificate is accepted, valid or not. Without it, the certificate must be valid. It needs use_tls: true. |
| `username` | string | **Required.** A user with the read, write and api policies. |
| `password` | string | **Required.** Its password. |
| `zone` | string | **Required.** The zone of the names, as lan. |
| `ttl` | string | **Required.** The records' TTL, as 5m or 1h. |

## openwrt

OpenWrt's dnsmasq, over SSH and UCI.

| Key | Takes | |
|---|---|---|
| `address` | string | **Required.** The router, with a port unless it's 22. |
| `username` | string | **Required.** The SSH user. |
| `password` | string | Its password, or use ssh_key. |
| `ssh_key` | string | The SSH private key file. |
| `host_key` | string | The fingerprint of the host's SSH key, as ssh-keygen -l shows it: SHA256:.... Any of its keys works. Recommended: without it, any key is accepted, and the log warns with the fingerprint it saw. |
| `zone` | string | **Required.** The zone of the names, as lan. |
| `ttl` | string | Not used: dnsmasq's records have no TTL of their own. Accepted so that configurations that set it still load. |

## opnsense_unbound

OPNsense's Unbound host overrides, through its API.

| Key | Takes | |
|---|---|---|
| `address` | string | **Required.** Its address, as https://opnsense.lan. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the server's certificate, in hex, for when it can't be verified otherwise. Without it, the certificate must be valid. |
| `key` | string | **Required.** An API key. |
| `secret` | string | **Required.** Its secret. |
| `zone` | string | **Required.** The zone of the names. |
| `ttl` | string | **Required.** The records' TTL, as 5m or 1h. |

## pfsense_restapi_unbound

pfSense's Unbound host overrides, through the REST API package.

| Key | Takes | |
|---|---|---|
| `address` | string | **Required.** Its address, as https://pfsense.lan. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the server's certificate, in hex, for when it can't be verified otherwise. Without it, the certificate must be valid. |
| `key` | string | **Required.** An API key. |
| `zone` | string | **Required.** The zone of the names. |
| `ttl` | string | Not used: pfSense's host overrides have no TTL of their own. Accepted so that configurations that set it still load. |

## resolver

A zone that one of ipv6ddns's resolvers answers from memory, for the clients on its network: see the [resolver](../resolver.md). Its debounce defaults to none, since nothing is sent anywhere.

| Key | Takes | |
|---|---|---|
| `resolver` | string | Which of the resolvers answers the zone. Needed only when there's more than one. |
| `zone` | string | **Required.** The zone: a subdomain of a domain you own, such as lan.example.com, or home.arpa. |
| `records` | list of string | Records of names in the zone that no task publishes, one per entry, in zone file syntax, relative to the zone or absolute within it: printer A 192.168.1.20, files CNAME nas, _ipp._tcp SRV 0 0 631 printer. A record without a TTL gets the zone's. |
| `ttl` | string | The TTL of the names' addresses, and of the records that give none, as 5m or 1h. Default: 1m. |

## route53

AWS Route 53, through its API. ipv6ddns learns the hosted zone's name from AWS at the first update. Until then, a name written relative, as nas, and the same name written in full are two names, each writing the records with its own addresses alone, and the start warns of them. Write each name one way.

| Key | Takes | |
|---|---|---|
| `access_key_id` | string | **Required.** An access key allowed route53:GetHostedZone, ListResourceRecordSets and ChangeResourceRecordSets on the zone. |
| `secret_access_key` | string | **Required.** Its secret. |
| `region` | string | **Required.** The API's region, as us-east-1. |
| `hosted_zone_id` | string | **Required.** The hosted zone's ID, as Z123.... |
| `ttl` | string | **Required.** The records' TTL, as 5m or 1h. |

## technitium

Technitium DNS Server, through its HTTP API.

| Key | Takes | |
|---|---|---|
| `address` | string | **Required.** Its address, as http://127.0.0.1:5380. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the server's certificate, in hex, for when it can't be verified otherwise. Without it, the certificate must be valid. |
| `token` | string | **Required.** An API token. |
| `zone` | string | **Required.** The zone. |
| `ttl` | string | **Required.** The records' TTL, as 5m or 1h. |

## windows

Windows DNS Server, through PowerShell: on the server itself, or over SSH.

| Key | Takes | |
|---|---|---|
| `zone` | string | **Required.** The zone. |
| `address` | string | The server, reached over SSH. Empty when ipv6ddns runs on it. |
| `username` | string | The SSH user. |
| `password` | string | Its password, or use ssh_key. |
| `ssh_key` | string | The SSH private key file. |
| `host_key` | string | The fingerprint of the host's SSH key, as ssh-keygen -l shows it: SHA256:.... Any of its keys works. Recommended: without it, any key is accepted, and the log warns with the fingerprint it saw. |
| `ttl` | string | The records' TTL, as 5m or 1h. Default: the zone's. |
