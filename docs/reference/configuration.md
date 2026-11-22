# Configuration reference

<!-- Generated from the schemas by `go test ./internal/docgen -update`: edit them, not this page. -->

The configuration file is YAML, or JSON. Every string takes `${NAME}`, an environment variable, and `${file:PATH}`, a file's content: see [secrets](../configuration.md#secrets). A duration is `90s`, `1m30s`, `1h`, or a number of seconds. A key the schema doesn't have is an error. The schema is [`config/schema.json`](../../config/schema.json).

## Top level

| Key | Takes | |
|---|---|---|
| `tasks` | object | **Required.** The DNS names to keep up to date, by task name. Each task takes the addresses its filters match, and those of the sources it lists, and gives them to the names under its endpoints. |
| `credentials` | object | **Required.** The DNS providers to update, by credential name. Tasks name them under endpoints. |
| `resolvers` | object | DNS servers for the clients on a network, by name. Each answers the zones of its resolver credentials, with the addresses the tasks give their names and with its own records, and asks its upstream servers everything else. See the [resolver](../resolver.md). |
| `discovery` | object | How hosts are discovered: on the local links, by the protocols enabled, and by plugins reading the tables of routers. Every key is optional: what is left out is its default. |
| `sources` | object | Sources of addresses that have no MAC, such as the network's public IPv4, by name. Tasks list them under sources. |
| `log_level` | `debug`, `info`, `warn`, `error`, `dpanic`, `panic`, `fatal` | How much the log says. Default: info. |
| `webserver` | object | The web server, with the status page, /status.json and /metrics. |
| `homeassistant` | object | Makes ipv6ddns a device of Home Assistant's ESPHome integration. Home Assistant finds it, and shows each name's addresses, last update and problems, and the hosts discovered, with a button to update now. It also gives the states that homeassistant sources read. See docs/home-assistant-integration.md. |

## Tasks

`tasks.<name>`

The DNS names to keep up to date, by task name. Each task takes the addresses its filters match, and those of the sources it lists, and gives them to the names under its endpoints.

| Key | Takes | |
|---|---|---|
| `filter` | list of object | Which addresses the task takes. It's a list of sets: an address that matches any set is taken. Within a set, every rule must match. |
| `endpoints` | object | **Required.** The names to update, by credential. A name is in the credential's zone: "" is the zone itself, and "*.name" a wildcard. A name can also be a template, which makes a name for each host the filters match, from what the host calls itself. "{hostname}" is one name for every host called that, with all their addresses; "{n}.{hostname}" is one name per host, numbered from 1 in MAC order among those present; "{mac}" is the host's MAC, as twelve digits. {hostname} needs a discovery protocol or plugin that learns names. A name written out beats a template's. |
| `sources` | list of string | The sources whose addresses the task's names also get. |

## Task filters

`tasks.<name>.filter[]`

Each filter set: an address that every rule of one set matches is the task's. See [filtering](../filtering.md).

| Key | Takes | |
|---|---|---|
| `self` | boolean | The addresses of the machine ipv6ddns runs on, on the interfaces discovery uses, instead of a host's: for a Home Assistant host or a server. It needs the family's discovery listen on. Interfaces with no MAC, such as a PPP link or a tunnel, aren't included: a source gives those. |
| `mac` | object | Rules on the host's MAC address. |
| `ip` | object | Rules on the address itself. |

## Filter mac

`tasks.<name>.filter[].mac`

Rules on the host's MAC address.

| Key | Takes | |
|---|---|---|
| `address` | string | The MAC address, as 00:11:22:33:44:55. 00-11-22-33-44-55 and 0011.2233.4455 work too. |
| `mask` | list of string | VALUE/MASK pairs, all of which the MAC must match. For one vendor's devices: 00:11:22:00:00:00/ff:ff:ff:00:00:00. |
| `type` | list of `local`, `global`, `unicast`, `multicast`, `!local`, `!global`, `!unicast`, `!multicast` | MAC types, all of which must apply: global, local, unicast, multicast. A ! in front excludes the type, as "!local". |

## Filter ip

`tasks.<name>.filter[].ip`

Rules on the address itself.

| Key | Takes | |
|---|---|---|
| `type` | list of `global`, `private`, `ula`, `cgnat`, `link_local`, `eui64`, `random`, `temporary`, `!global`, `!private`, `!ula`, `!cgnat`, `!link_local`, `!eui64`, `!random`, `!temporary` | Address types, all of which must apply: global, private, ula, cgnat, link_local; eui64, an IPv6 address made from the MAC, which doesn't change; random, an IPv6 address not made from the MAC; temporary, an IPv6 privacy address of this machine, which changes about once a day. A ! in front excludes the type, as "!temporary". |
| `prefix` | string | A prefix the address must be in, as 2001:db8::/32 or 192.168.1.0/24. |
| `mask` | list of string | VALUE/MASK pairs, all of which the address must match in the bits the mask sets: ::1/::ffff:ffff:ffff:ffff matches the IPv6 addresses ending in ::1, and 0.0.0.5/0.0.0.255 the IPv4 ones ending in .5. The mask is an address, not a prefix length: prefix takes those. A pair only matches addresses of its own family. |
| `family` | list of `4`, `6` | 4, 6 or both. Default: 6. |
| `seen` | list of  | How the address must have been seen: a list of records, all of which it must have, each still current. A record is a protocol and how it saw the address, as protocol: mdns with way: announced; or reported, from a table of a plugin or of the kernel. |
| `not_seen` | list of  | Records the address must have none of, written as for seen. For example, not_seen with reported: {} keeps the addresses the host showed itself, and never one that only a table reports. |

## Credentials

`credentials.<name>`

The DNS providers to update, by credential name. Tasks name them under endpoints. The settings of each provider are in the [providers reference](providers.md).

| Key | Takes | |
|---|---|---|
| `provider` | string | **Required.** The DNS provider: see the providers reference. |
| `settings` | object | **Required.** The provider's settings: see the providers reference. An unknown setting is an error. |
| `debounce` | duration | How long to wait for more changes before an update. Default: 10s. A resolver credential doesn't wait, since its updates only change memory. |
| `retry` | duration | How long to wait before retrying a failed update. Changes that come meanwhile wait for the retry too. At least 1s. Default: 1m. |

## Resolvers

`resolvers.<name>`

DNS servers for the clients on a network, by name. Each answers the zones of its resolver credentials, with the addresses the tasks give their names and with its own records, and asks its upstream servers everything else. See the [resolver](../resolver.md).

| Key | Takes | Default | |
|---|---|---|---|
| `listen` | list, or comma separated | - | **Required.** Where it answers, over UDP and TCP: networks of the machine's addresses, addresses, host names or ports, as 192.168.1.0/24, 192.168.1.2 or [fd00::2]:5353. Without a port, 53. A port alone means every address of the machine, including a public one on a router: give the clients' network instead. Two resolvers can't share an address and port, however each writes it. |
| `allow` | list, or comma separated | - | The networks or addresses of the clients it answers, as 192.168.1.0/24 or fd00::/64. Any other client gets REFUSED. Default: the networks of the addresses it listens on. |
| `upstream` | list, or comma separated | - | **Required.** The servers it asks about names that aren't its own, in order, giving each 2s. Plain DNS, over UDP, and over TCP when the answer doesn't fit: 192.168.1.1, 1.1.1.1:53, [2606:4700:4700::1111] or dns.example.net, port 53 by default. DNS over TLS: tls://1.1.1.1 or tls://dns.example.net, port 853 by default. DNS over HTTPS: https://dns.example.net/dns-query, port 443 by default. An encrypted server's certificate is checked against the system's certificate authorities, for the host given, and its connections are reused. A host name needs bootstrap. When none answers, the client gets SERVFAIL. |
| `bootstrap` | list, or comma separated | - | Only for upstream servers given by host name, plain or encrypted: the servers that look up their addresses, and nothing else. Addresses, with or without a port, asked in order over plain DNS. The system's resolver isn't used, since it may be this one. The addresses found are kept for their TTL, between a minute and an hour, and for as long as these servers don't answer. |
| `records` | list of string | - | Records of names outside its zones, one per entry, in zone file syntax, with every name absolute and ending in a dot: www.example.com. CNAME nas.home.arpa. A record without a TTL gets 1m. |
| `cache_size` | number | - | How many answers of the upstream servers it keeps, each for its TTL: a day at most, and an hour for a name that doesn't exist or has no data. When full, the one asked longest ago goes first. Default: 10000. 0 keeps none, and every query goes upstream. Local names are never kept: they follow discovery at once. |
| `forward_unknown_private_reverse_queries` | boolean | `false` | Whether to ask the upstream servers for the reverse name of a private address the resolver has no name for: for an upstream server that knows more names, as a router does for its DHCP clients. By default, as RFC 6303 says, the resolver answers that there's no such name, and the question never leaves it. The private ranges are 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, the loopback, link-local and documentation ones, fd00::/8, fe80::/10, ::1 and 2001:db8::/32. |

## Sources

`sources.<name>`

Sources of addresses that have no MAC, such as the network's public IPv4, by name. Tasks list them under sources. See [sources](../sources.md).

| Key | Takes | |
|---|---|---|
| `type` | `http`, `dns`, `command`, `static`, `homeassistant` | **Required.** Where the addresses come from. dns: the public address, as OpenDNS's or Google's resolvers see it. http: echo services over HTTPS, or the urls given. command: the addresses a command prints, one per line. static: the addresses listed. homeassistant: the addresses in a Home Assistant entity's state, which needs the homeassistant block. |
| `family` | list of `4`, `6` | For http and dns: the families to find. Default: 4. |
| `interval` | duration | How often it runs. Default: 5m. |
| `lifetime` | duration | How long an address stays after the last run that gave it. Default: 3 intervals. |
| `urls` | list of string | For http: the echo services to ask, in order. |
| `command` | string | For command: the program to run, from the configuration's folder. |
| `args` | list of string | For command: its arguments. |
| `addresses` | list of string | For static: the addresses. |
| `entity` | string | For homeassistant: the entity, as sensor.wan_ip. |
| `attribute` | string | For homeassistant: an attribute of the entity to read instead of its state. |

## Web server

`webserver`

The web server, with the status page, /status.json and /metrics. See [the web report](../installation.md#the-web-report).

| Key | Takes | |
|---|---|---|
| `listen` | list, or comma separated | Where to serve: ports, addresses, networks of the machine's addresses or host names, as 8053, 192.0.2.1:8053, [2001:db8::1]:8053, 10.2.3.0/24 or myhost. Without a port, 8053. A host name listens on each address it resolves to at start; a network, on each of the machine's addresses in it. |

## Home Assistant

`homeassistant`

Makes ipv6ddns a device of Home Assistant's ESPHome integration. Home Assistant finds it, and shows each name's addresses, last update and problems, and the hosts discovered, with a button to update now. It also gives the states that homeassistant sources read. See docs/home-assistant-integration.md. See [the Home Assistant integration](../home-assistant-integration.md).

| Key | Takes | |
|---|---|---|
| `key` | string | **Required**, without `key_provisioning`. The encryption key: base64 of 32 bytes. Home Assistant asks for it when adding the device, and can't replace it later, since ipv6ddns stores nothing. Make one with openssl rand -base64 32. Give this, or key_provisioning: true. |
| `key_provisioning` | boolean | Whether Home Assistant makes the key and hands it over when adding the device, as it does for ESPHome devices. The key is kept in key_provisioning_state_file. Default: false, and then the block needs a key. |
| `key_provisioning_state_file` | string | Only with key_provisioning: true. Where the device keeps the key Home Assistant gave, and its identity, by which Home Assistant knows it. A file ipv6ddns can write; a relative path is from the configuration's folder. Default: homeassistant.state. Each instance needs its own: one whose state file is in use by another doesn't start. Deleting it makes the device a new one, with no key. |
| `name` | string | The device's name on the network: lower-case letters, digits and hyphens. Default: ipv6ddns. Each instance on the network needs its own: a second one, whose name is announced already, doesn't announce itself. |
| `friendly_name` | string | The name Home Assistant shows. Default: the name. |
| `port` | number | The port Home Assistant connects to, which the device announces. Default: 6053, ESPHome's. |
| `announce` | boolean | Whether the device announces itself over mDNS, so that Home Assistant finds it. Without it, add the device by its address. Default: true. |
| `listen` | list, or comma separated | **Required.** Required. Where Home Assistant can connect to the device: networks, addresses, host names or ports, as 192.168.1.0/24, 192.168.1.10, [fd00::1]:7000, myhost or 6053. A network means this machine's addresses in it. Without a port, port (6053). A port alone means every address of this machine, including a public one on a router: prefer the network Home Assistant is on. The device announces itself over mDNS only on these addresses' interfaces, and with one port, so entries with different ports need announce: false. |

## Discovery

`discovery`

How hosts are discovered: on the local links, by the protocols enabled, and by plugins reading the tables of routers. Every key is optional: what is left out is its default. The keys are those of [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc), whose discovery it is, but `solicit`, which is of ipv6ddns: a file of its command's keys is this block. See [discovery](../discovery.md).

| Key | Takes | Default | |
|---|---|---|---|
| `lifetime` | duration | `1h` | How long an address stays after it was last seen, unless its family says. |
| `rediscover` | duration | - | How often the active discovery probes every host. Default: a third of the shortest lifetime of the families that probe, so that a quiet host is probed before it expires. |
| `interfaces` | list, or comma separated | - | The interfaces the local discovery of both families runs on: names, or patterns as en*. Default: all. The plugins aren't concerned. |
| `exclude_interfaces` | list, or comma separated | - | The interfaces the local discovery doesn't run on: names, or patterns as docker*, veth*. |
| `ipv6` | object | - | IPv6: the switches of all its protocols at once. A protocol runs only when it is enabled, under protocols, and its family, and the way it works, are on here. |
| `ipv4` | object | - | IPv4: the switches of all its protocols at once. A protocol runs only when it is enabled, under protocols, and its family, and the way it works, are on here. |
| `hostnames` | object | - | The names of the hosts: always kept, of what learns them, each protocol under protocols that does, and the plugins, of their routers' DHCP leases. To learn none, disable those protocols, and the names of ssdp and wsd. |
| `protocols` | object | - | The protocols of the local discovery, each with its switch, enabled, and its options: always a mapping, never true or false alone. One runs when it is enabled, its family is, and the family listens, or for what probes is active. |
| `plugins` | object | - | The plugins, by name: each reads the neighbor tables of a router or another host, and its DHCP leases: their names, and that an address found otherwise is leased. The name is the source of what it finds. |
| `solicit` | object | - | Asks for the hosts the filters name by MAC, once a minute, when nothing else finds them. Part of ipv6ddns, not of ipv6disc. |

## Discovery IPv6

`discovery.ipv6`

IPv6: the switches of all its protocols at once. A protocol runs only when it is enabled, under protocols, and its family, and the way it works, are on here.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the family's addresses are kept, and the plugins read them. Without it, the rest of the family is off. |
| `listen` | boolean | `true` | The local discovery of IPv6: its protocols hear, and ask one host of what they heard of it. Without it, only the plugins find IPv6 addresses. |
| `active` | boolean | `true` | Probing every host of the links, at every rediscover: the multicast ping, the search of SSDP, the probe of WS-Discovery, and the query of mDNS. Only with listen, which reads the answers. |
| `lifetime` | duration | - | How long the family's addresses stay after they were last seen, whatever found them, the plugins too. Default: lifetime. |

## Discovery IPv4

`discovery.ipv4`

IPv4: the switches of all its protocols at once. A protocol runs only when it is enabled, under protocols, and its family, and the way it works, are on here.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `false` | Whether the family's addresses are kept, and the plugins read them. Without it, the rest of the family is off. |
| `listen` | boolean | `true` | The local discovery of IPv4: the neighbor table is read, and the ARP of the hosts heard. Without it, only the plugins find IPv4 addresses. |
| `active` | boolean | `true` | Probing every host of the subnets, at every rediscover: the sweep, which broadcasts an ARP request for each address, and the query of mDNS. Only with listen, which reads the answers. |
| `lifetime` | duration | - | How long the family's addresses stay after they were last seen, whatever found them, the plugins too. Default: lifetime. |

## Discovery hostnames

`discovery.hostnames`

The names of the hosts: always kept, of what learns them, each protocol under protocols that does, and the plugins, of their routers' DHCP leases. To learn none, disable those protocols, and the names of ssdp and wsd.

| Key | Takes | |
|---|---|---|
| `lifetime` | duration | How long a name stays after it was last said, whatever said it, the plugins too. Default: lifetime. |

## Discovery solicit

`discovery.solicit`

Asks for the hosts the filters name by MAC, once a minute, when nothing else finds them. Part of ipv6ddns, not of ipv6disc.

| Key | Takes | Default | |
|---|---|---|---|
| `ipv6` | boolean | `false` | For each filter with a mac.address and the eui64 type: a neighbor solicitation for that MAC's EUI-64 address, on each /64 discovery listens on. It needs ipv6.listen, which reads the answers. |
| `ipv4` | boolean | `false` | For each filter with a mac.address and ip.family 4: ARP requests to that MAC alone, for the local subnets' addresses inside the filter's ip.prefix. It needs ipv4.enabled, Linux and CAP_NET_RAW. |

## Discovery protocols

`discovery.protocols`

The protocols of the local discovery, each with its switch, enabled, and its options: always a mapping, never true or false alone. One runs when it is enabled, its family is, and the family listens, or for what probes is active.

```yaml
discovery:
  protocols:
    mdns:
      enabled: true
      ask: false
    arp-sweep:
      enabled: false
```

### ndp

`discovery.protocols.ndp`

IPv6, listening. The neighbor discovery of each link: every advertisement and solicitation heard tells an address and its MAC, and the MAC of whatever the others of IPv6 hear is asked by it, with a neighbor solicitation. Without it ping, ssdp and wsd find nothing, and are an error to enable. It needs root or CAP_NET_RAW.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### ping

`discovery.protocols.ping`

IPv6. Listening, an address is pinged before it expires, so that a host still there keeps it. Active, every host is, by a ping to the group of all nodes. It needs root or CAP_NET_RAW.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### ssdp

`discovery.protocols.ssdp`

IPv6. SSDP, of the UPnP devices: active, a search goes to its group, and listening hears the answers, at the port it left from. No group is joined.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `names` | boolean | `true` | Whether a device that answers the search is asked its description, over HTTP, for its friendly name. |

### wsd

`discovery.protocols.wsd`

IPv6. WS-Discovery, of Windows and Samba: active, a probe goes to its group, and listening hears the answers, at the port it left from. No group is joined.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `names` | boolean | `true` | Whether a computer that answers the probe is asked its metadata, over HTTP, for its name. |

### mdns

`discovery.protocols.mdns`

Either family, listening. mDNS: its groups are joined, on port 5353, and whatever sends there is a host of the link, whose address is found as any other, and what it announces is its name. Active, a query for the services goes to the group.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `ask` | boolean | `true` | Whether questions are sent: the query to the group, at every rediscover, and to each host for its name. Without it mDNS only listens. |

### arp

`discovery.protocols.arp`

IPv4, listening. The kernel's neighbor table, read every minute, and after each sweep.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### arp-sweep

`discovery.protocols.arp-sweep`

IPv4, active. A sweep of the local subnets: a UDP packet to the discard port of each address, so that the kernel resolves it, which broadcasts an ARP request for each. arp or arp-listen tells the hosts that answer: without both it is an error to enable.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `max_prefix` | number | `22` | The largest subnet swept whole, by the length of its prefix: 22 is a /22, of 1022 addresses. A larger one is swept in the /24 of the interface's address only, or in the prefix of this length there when that is smaller. |

### arp-listen

`discovery.protocols.arp-listen`

IPv4, listening. The ARP the hosts send, heard by a packet socket that only listens: each is found at once, not at the next reading of the table. It needs Linux, and root or CAP_NET_RAW: without the privilege it is said once in the log, and the rest runs.

| Key | Takes | |
|---|---|---|
| `enabled` | boolean | Whether the protocol runs. Default: true on Linux, where alone it can; elsewhere false, and true is an error. |

### dhcp

`discovery.protocols.dhcp`

Either family, listening. What the DHCP clients say to all as they ask for an address, heard by packet sockets that only listen: the address a client asks for is found as any other, and the name it gives its server is its name. It needs Linux, and root or CAP_NET_RAW: without the privilege it is said once in the log, and the rest runs.

| Key | Takes | |
|---|---|---|
| `enabled` | boolean | Whether the protocol runs. Default: true on Linux, where alone it can; elsewhere false, and true is an error. |

### lldp

`discovery.protocols.lldp`

Either family, listening. What the LLDP neighbor of an interface says of itself, heard by a packet socket that only listens: the addresses it is managed at are found as any other, and its system name is its name. It needs Linux, and root or CAP_NET_RAW: without the privilege it is said once in the log, and the rest runs.

| Key | Takes | |
|---|---|---|
| `enabled` | boolean | Whether the protocol runs. Default: true on Linux, where alone it can; elsewhere false, and true is an error. |

### netbios

`discovery.protocols.netbios`

IPv4, listening. A host is asked its node status, by a question sent to it alone: Windows answers, and Samba, with the machine's name. Names only.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### llmnr

`discovery.protocols.llmnr`

Either family, listening. A host is asked the name of one of its addresses, by a question to the group of LLMNR, which every host of the link hears: Windows answers, and systemd-resolved. Names only.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### dns

`discovery.protocols.dns`

Of no family: DNS servers are asked the name of each address, its PTR record, of the hosts the plugins found too. Names only.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs: once it has servers, which it asks alone. |
| `servers` | list, or comma separated | - | The servers asked: without, dns asks nobody. each an address, alone or with its port, as 192.168.1.1, 192.168.1.1:5353 or [fd00::1]:53. Only these are asked, never the system's resolver. |

## Discovery plugins

`discovery.plugins.<name>`

The plugins, by name: each reads the neighbor tables of a router or another host, and its DHCP leases: their names, and that an address found otherwise is leased. The name is the source of what it finds. Each type takes its own keys only.

### `linux`, `freebsd`

A plugin over SSH, linux or freebsd: with a password, an identity file, or both.

| Key | Takes | |
|---|---|---|
| `type` | string | **Required.** The type of the plugin. |
| `interval` | duration | **Required.** How often the table is read: 60s, 5m. |
| `address` | string | **Required.** The host, with its port unless 22: 192.168.1.1, [2001:db8::1]:2222. |
| `username` | string | **Required.** The SSH user. |
| `password` | string | Its password. Or an identity_file, or both. |
| `identity_file` | string | The SSH private key file. |
| `host_key` | string | The fingerprint of the host's SSH key, any of them when it has several, SHA256:..., as ssh-keygen -l shows it. Recommended: without it, any key is accepted, and the log warns with the fingerprint seen. |

### `mikrotik`

A plugin over the Mikrotik API.

| Key | Takes | |
|---|---|---|
| `type` | string | **Required.** The type of the plugin. |
| `interval` | duration | **Required.** How often the tables are read: 60s, 5m. |
| `address` | string | **Required.** The router, with its port unless the default: 8728, or 8729 with TLS. |
| `username` | string | **Required.** An API user: the read and api policies are enough. |
| `password` | string | Its password. |
| `use_tls` | boolean | true or false: the API over TLS, the api-ssl service. Without it, the password crosses the network in the clear. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the router's certificate, 64 hex digits, colons allowed, when the system's CAs can't verify it, as the self-signed one RouterOS makes. It needs use_tls. |
