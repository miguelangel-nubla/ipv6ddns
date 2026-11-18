# Configuration reference

<!-- Generated from the schemas by `go test ./internal/docgen -update`: edit them, not this page. -->

The configuration file is YAML, or JSON. Every string takes `${NAME}`, an environment variable, and `${file:PATH}`, a file's content: see [secrets](../configuration.md#secrets). A duration is `90s`, `1m30s`, `1h`, or a number of seconds. A key the schema doesn't have is an error.

## Top level

| Key | Takes | |
|---|---|---|
| `tasks` | object | **Required.** The host names to keep, by task name: the addresses its filters match, and those of the sources it names, go to the host names of its endpoints. |
| `credentials` | object | **Required.** The DNS providers to update, by credential name, which tasks' endpoints name. |
| `discovery` | object | How hosts are discovered: on the local links, and by plugins reading routers' tables. |
| `sources` | object | Sources of addresses without a MAC, as the network's public IPv4, by name, which tasks name in their sources. |
| `lifetime` | duration | How long a discovered address stays after it was last seen, unless its family says. Default: 1h. The -lifetime flag, given, wins. |
| `log_level` | `debug`, `info`, `warn`, `error`, `dpanic`, `panic`, `fatal` | The logging level. Default: info. The -log_level flag, given, wins. |
| `webserver_listen` | list, or comma separated | Serve the report, /status.json and /metrics on these addresses, host names and ports: 8053, 192.0.2.1:8053, [2001:db8::1]:8053, myhost. The -webserver_listen flag, given, wins. |

## Tasks

`tasks.<name>`

The host names to keep, by task name: the addresses its filters match, and those of the sources it names, go to the host names of its endpoints.

| Key | Takes | |
|---|---|---|
| `filter` | list of object | Filter sets: an address any of them matches is the task's. Within a set, every rule must match. |
| `endpoints` | object | **Required.** The host names to update, by credential: a name in the credential's zone, "" for the zone itself, "*.name" for a wildcard. |
| `ipv4` | object | Deprecated, and goes in v1.0: a command source, in sources, does the same. |
| `sources` | list of string | The sources whose addresses the task's names get too. |

## Task filters

`tasks.<name>.filter[]`

Each filter set: an address that every rule of one set matches is the task's. See [filtering](../filtering.md).

| Key | Takes | |
|---|---|---|
| `self` | boolean | The addresses of the machine ipv6ddns runs on, on the interfaces discovery runs on, rather than of a MAC: a Home Assistant host, a server. With the family's listen. |
| `mac` | object | Rules on the MAC address of the host. |
| `ip` | object | Rules on the address. |
| `source` | list of string | Names of what must all have seen the address: discovery plugins, or local interfaces. |

## Filter mac

`tasks.<name>.filter[].mac`

Rules on the MAC address of the host.

| Key | Takes | |
|---|---|---|
| `address` | string | The MAC address, exactly: 00:11:22:33:44:55. |
| `mask` | list of string | VALUE/MASK pairs, all of which the MAC must match: 00:11:22:00:00:00/ff:ff:ff:00:00:00 for a vendor's. |
| `type` | list of `local`, `global`, `unicast`, `multicast`, `!local`, `!global`, `!unicast`, `!multicast` | MAC types, all of which must apply: global, local, unicast, multicast. "!type": not of the type. |

## Filter ip

`tasks.<name>.filter[].ip`

Rules on the address.

| Key | Takes | |
|---|---|---|
| `type` | list of `global`, `private`, `ula`, `cgnat`, `link_local`, `eui64`, `random`, `temporary`, `!global`, `!private`, `!ula`, `!cgnat`, `!link_local`, `!eui64`, `!random`, `!temporary` | Address types, all of which must apply: global, private, ula, cgnat, link_local, eui64 (IPv6 from the MAC, stable), random (IPv6, not from the MAC), temporary (an IPv6 privacy address of this machine's, which changes every day or so). "!type": not of the type, as "!temporary". |
| `prefix` | string | A prefix the address must be in: 2001:db8::/32, 192.168.1.0/24. |
| `suffix` | string | The end of the address, in its canonical lower case form: ::1, dead:beef. |
| `mask` | list of string | VALUE/MASK pairs, all of which the address must match. |
| `family` | list of `4`, `6` | 4, 6 or both. Default: 6. |

## Task ipv4, deprecated

`tasks.<name>.ipv4`

Deprecated, and goes in v1.0: a command source, in sources, does the same.

| Key | Takes | |
|---|---|---|
| `interval` | duration | **Required.** How often the command runs. |
| `command` | string | **Required.** The command, printing the addresses one per line. |
| `args` | list of string | Its arguments. |
| `lifetime` | duration | **Required.** How long an address stays after the last run that gave it. |

## Credentials

`credentials.<name>`

The DNS providers to update, by credential name, which tasks' endpoints name. The settings of each provider are in the [providers reference](providers.md).

| Key | Takes | |
|---|---|---|
| `provider` | string | **Required.** The DNS provider: see the providers reference. |
| `settings` | object | **Required.** The provider's settings: see the providers reference. An unknown one is an error. |
| `debounce_time` | duration | How long to wait for more changes before updating. Default: 10s. |
| `retry_time` | duration | How long to wait before retrying a failed update. Default: 1m. |

## Sources

`sources.<name>`

Sources of addresses without a MAC, as the network's public IPv4, by name, which tasks name in their sources. See [sources](../sources.md).

| Key | Takes | |
|---|---|---|
| `type` | `http`, `dns`, `command`, `static` | **Required.** dns: the public address, as OpenDNS's or Google's resolvers see it. http: from echo services over HTTPS, or urls. command: the addresses a command prints, one per line. static: the addresses listed. |
| `family` | list of `4`, `6` | http and dns: the families to find. Default: 4. |
| `interval` | duration | How often it runs. Default: 5m. |
| `lifetime` | duration | How long an address stays after the last run that gave it. Default: 3 intervals. |
| `urls` | list of string | http: the echo services to ask, in order. |
| `command` | string | command: the program to run, from the configuration's directory. |
| `args` | list of string | command: its arguments. |
| `addresses` | list of string | static: the addresses. |

## Discovery

`discovery`

How hosts are discovered: on the local links, and by plugins reading routers' tables. See [discovery](../discovery.md).

| Key | Takes | |
|---|---|---|
| `ipv6` | true, false, or [ways](#discovery-families) | IPv6 discovery: true, false, or the ways. Default: listen and active. |
| `ipv4` | true, false, or [ways](#discovery-families) | IPv4 discovery: true, false, or the ways. Default: off. Filters take IPv4 addresses only with ip.family 4. |
| `plugins` | object | Plugins reading the neighbor tables of routers and hosts, by name. |
| `listen` | boolean | Deprecated, and goes in v1.0: discovery.ipv6.listen, and ipv4.listen unless ipv4 has its ways. |
| `active` | boolean | Deprecated, and goes in v1.0: discovery.ipv6.active, and ipv4.active unless ipv4 has its ways. |
| `solicit_eui64` | boolean | Deprecated, and goes in v1.0: discovery.ipv6.solicit. |
| `interfaces` | list, or comma separated | The interfaces the local discovery of both families runs on: names, or patterns as en*. Default: all. |
| `exclude_interfaces` | list, or comma separated | The interfaces the local discovery doesn't run on: names, or patterns as docker*, veth*. |
| `rediscover` | duration | How often the active discovery probes every host. Default: a third of the shortest lifetime of the families that probe. |

## Discovery families

`discovery.ipv6`, `discovery.ipv4`

`true` turns the family on with its default ways, `false` off, and an object gives the ways, each defaulting as `true` sets it.

| Key | Takes | |
|---|---|---|
| `enabled` | boolean | Whether the family is discovered at all. Default: true in an object. |
| `listen` | boolean | Passive local discovery: NDP for IPv6, the kernel's neighbor table for IPv4. Active probing and IPv6 solicitation need it. Default: true. |
| `active` | boolean | Probing every host: multicast for IPv6, a broadcast ARP sweep for IPv4. Default: true. |
| `solicit` | boolean | Asking the hosts the filters want: their EUI-64 address for IPv6, ARP to their MAC alone for IPv4. Default: false. |
| `lifetime` | duration | How long the family's addresses stay after they were last seen, whatever found them. Default: the top-level lifetime. |

## Discovery plugins

`discovery.plugins.<name>`

Plugins reading the neighbor tables of routers and hosts, by name. Each type takes its own keys only.

### `linux`, `freebsd`

A plugin over SSH, linux or freebsd: with a password, an identity file, or both.

| Key | Takes | |
|---|---|---|
| `type` | string | **Required.** The plugin type. |
| `params` | string | Deprecated, and goes in v1.0: the params in one string, as for ipv6disc. Give the fields instead. |
| `interval` | duration string | **Required**, without `params`. How often the table is read: 60s, 5m. |
| `address` | string | **Required**, without `params`. The host, with its port unless 22: 192.168.1.1, [2001:db8::1]:2222. |
| `username` | string | **Required**, without `params`. The SSH user. |
| `password` | string | Its password. Or an identity_file, or both. |
| `identity_file` | string | The SSH private key file. |
| `host_key` | string | The fingerprint of the host's SSH key, SHA256:..., as ssh-keygen -l shows it. Recommended: without it, any key is accepted, and the log warns with the fingerprint seen. |

### `mikrotik`

A plugin over the Mikrotik API.

| Key | Takes | |
|---|---|---|
| `type` | string | **Required.** The plugin type. |
| `params` | string | Deprecated, and goes in v1.0: the params in one string, as for ipv6disc. Give the fields instead. |
| `interval` | duration string | **Required**, without `params`. How often the tables are read: 60s, 5m. |
| `address` | string | **Required**, without `params`. The router, with its port unless the default: 8728, or 8729 with TLS. |
| `username` | string | **Required**, without `params`. An API user: the read and api policies are enough. |
| `password` | string | Its password. |
| `use_tls` | boolean | true: the API over TLS, the api-ssl service. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the router's certificate, in hex, when it can't be verified otherwise. |
