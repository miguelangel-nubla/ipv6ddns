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
- [`route53`](#route53)
- [`technitium`](#technitium)
- [`windows`](#windows)

## cloudflare

Cloudflare DNS, over its API: the free plan works.

| Key | Takes | |
|---|---|---|
| `api_token` | string | **Required.** An API token with Zone.DNS edit on the zone. |
| `zone` | string | **Required.** The zone: example.com. |
| `ttl` | string | **Required.** The records' TTL: 5m, 1h. 1s is Cloudflare's automatic. |
| `proxied` | boolean | **Required.** Whether the records go through Cloudflare's proxy. |

## duckdns

DuckDNS: one A and one AAAA record per name, under duckdns.org.

| Key | Takes | |
|---|---|---|
| `api_token` | string | **Required.** The account's token. |

## gravity

Gravity, a DNS server for the home network, over its API. The zone itself is the record @. A zone made with the web interface's Gravity-hosted preset answers from memory first, and Gravity, v0.34.0 at least, then answers with one record of each type: a host with several IPv6 addresses resolves to one of them. Leave the zone its etcd handler alone for all of them to be answered.

| Key | Takes | |
|---|---|---|
| `server` | string | **Required.** Its address: http://gravity.lan. |
| `api_key` | string | **Required.** An API key. |
| `zone` | string | **Required.** The zone, with its final dot: home.lan. |
| `ttl` | string | The records' TTL: 5m, 1h. Default: 5m. Gravity has it per record since v0.32, and needs it there. |

## mikrotik

Mikrotik RouterOS static DNS, /ip/dns/static, over its API. RouterOS finds a name's records by its exact letters, capitals too: those of a hostname whose capitals change in the configuration stay, to be removed by hand. See docs/mikrotik.md.

| Key | Takes | |
|---|---|---|
| `address` | string | **Required.** The router, with a port unless the default: 8728, or 8729 with TLS. |
| `use_tls` | boolean | The API over TLS, the api-ssl service. Without it, the password crosses the network in the clear. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the router's certificate, in hex: with it, that certificate and no other is accepted, valid or not. Without it, the certificate must be valid. It needs use_tls: true. |
| `username` | string | **Required.** A user with the read, write and api policies. |
| `password` | string | **Required.** Its password. |
| `zone` | string | **Required.** The zone of the names: lan. |
| `ttl` | string | **Required.** The records' TTL: 5m, 1h. |

## openwrt

OpenWrt's dnsmasq, over SSH and UCI.

| Key | Takes | |
|---|---|---|
| `address` | string | **Required.** The router, with a port unless 22. |
| `username` | string | **Required.** The SSH user. |
| `password` | string | Its password, or an ssh_key. |
| `ssh_key` | string | The SSH private key file. |
| `host_key` | string | The fingerprint of the host's SSH key, any of them when it has several, SHA256:..., as ssh-keygen -l shows it. Recommended: without it, any key is accepted and the log warns with the fingerprint seen. |
| `zone` | string | **Required.** The zone of the names: lan. |
| `ttl` | string | Unused: dnsmasq's records have no TTL of their own. Kept so that the configurations giving it load. |

## opnsense_unbound

OPNsense's Unbound host overrides, over its API.

| Key | Takes | |
|---|---|---|
| `address` | string | **Required.** Its address: https://opnsense.lan. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the server's certificate, in hex, when it can't be verified otherwise. Without it, the certificate must be valid. |
| `key` | string | **Required.** An API key. |
| `secret` | string | **Required.** Its secret. |
| `zone` | string | **Required.** The zone of the names. |
| `ttl` | string | **Required.** The records' TTL: 5m, 1h. |

## pfsense_restapi_unbound

pfSense's Unbound host overrides, over the REST API package.

| Key | Takes | |
|---|---|---|
| `address` | string | **Required.** Its address: https://pfsense.lan. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the server's certificate, in hex, when it can't be verified otherwise. Without it, the certificate must be valid. |
| `key` | string | **Required.** An API key. |
| `zone` | string | **Required.** The zone of the names. |
| `ttl` | string | Unused: pfSense's host overrides have no TTL of their own. Kept so that the configurations giving it load. |

## route53

AWS Route 53, over its API.

| Key | Takes | |
|---|---|---|
| `access_key_id` | string | **Required.** An access key allowed route53:GetHostedZone, ListResourceRecordSets and ChangeResourceRecordSets on the zone. |
| `secret_access_key` | string | **Required.** Its secret. |
| `region` | string | **Required.** The API's region: us-east-1. |
| `hosted_zone_id` | string | **Required.** The hosted zone's ID: Z123.... |
| `ttl` | string | **Required.** The records' TTL: 5m, 1h. |

## technitium

Technitium DNS Server, over its HTTP API.

| Key | Takes | |
|---|---|---|
| `address` | string | **Required.** Its address: http://127.0.0.1:5380. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the server's certificate, in hex, when it can't be verified otherwise. Without it, the certificate must be valid. |
| `token` | string | **Required.** An API token. |
| `zone` | string | **Required.** The zone. |
| `ttl` | string | **Required.** The records' TTL: 5m, 1h. |

## windows

Windows DNS Server, with PowerShell: on the server itself, or over SSH.

| Key | Takes | |
|---|---|---|
| `zone` | string | **Required.** The zone. |
| `address` | string | The server over SSH. Empty: ipv6ddns runs on it. |
| `username` | string | The SSH user. |
| `password` | string | Its password, or an ssh_key. |
| `ssh_key` | string | The SSH private key file. |
| `host_key` | string | The fingerprint of the host's SSH key, any of them when it has several, SHA256:..., as ssh-keygen -l shows it. Recommended: without it, any key is accepted and the log warns with the fingerprint seen. |
| `ttl` | string | The records' TTL: 5m, 1h. Default: the zone's. |
