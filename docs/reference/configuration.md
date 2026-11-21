# Configuration reference

<!-- Generated from the schemas by `go test ./internal/docgen -update`: edit them, not this page. -->

The configuration file is YAML, or JSON. Every string takes `${NAME}`, an environment variable, and `${file:PATH}`, a file's content: see [secrets](../configuration.md#secrets). A duration is `90s`, `1m30s`, `1h`, or a number of seconds. A key the schema doesn't have is an error. The schema is [`config/schema.json`](../../config/schema.json).

## Top level

| Key | Takes | |
|---|---|---|
| `tasks` | object | **Required.** The host names to keep, by task name: the addresses its filters match, and those of the sources it names, go to the host names of its endpoints. |
| `credentials` | object | **Required.** The DNS providers to update, by credential name, which tasks' endpoints name. |
| `resolvers` | object | DNS servers for the clients of a network, by name: each answers the zones of its resolver credentials, with the addresses the tasks give their names, and records of its own, and asks its upstream servers the rest. See the [resolver](../resolver.md). |
| `discovery` | object | How hosts are discovered: on the local links, by the protocols enabled, and by plugins reading the tables of routers. Every key is optional: what is left out is its default. |
| `sources` | object | Sources of addresses without a MAC, as the network's public IPv4, by name, which tasks name in their sources. |
| `log_level` | `debug`, `info`, `warn`, `error`, `dpanic`, `panic`, `fatal` | The level of the log. Default: info. |
| `webserver` | object | The web server: the report, /status.json and /metrics. |
| `homeassistant` | object | Makes ipv6ddns a device of Home Assistant's ESPHome integration: Home Assistant discovers it, and shows each name's addresses, last update and problems, and the hosts discovered, with a button to update now; and it sends the states homeassistant sources read. See docs/home-assistant-integration.md. |

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
| `self` | boolean | The addresses of the machine ipv6ddns runs on, on the interfaces discovery runs on, rather than of a MAC: a Home Assistant host, a server. With the family's listen. Not those of an interface without a MAC, as a PPP link or a tunnel: a source gives them. |
| `mac` | object | Rules on the MAC address of the host. |
| `ip` | object | Rules on the address. |
| `source` | list of string | Names of what must all have seen the address: discovery plugins, or local interfaces. |

## Filter mac

`tasks.<name>.filter[].mac`

Rules on the MAC address of the host.

| Key | Takes | |
|---|---|---|
| `address` | string | The MAC address: 00:11:22:33:44:55. Also read as 00-11-22-33-44-55 or 0011.2233.4455. |
| `mask` | list of string | VALUE/MASK pairs of MACs, all of which the MAC must match: 00:11:22:00:00:00/ff:ff:ff:00:00:00 for a vendor's. |
| `type` | list of `local`, `global`, `unicast`, `multicast`, `!local`, `!global`, `!unicast`, `!multicast` | MAC types, all of which must apply: global, local, unicast, multicast. "!type": not of the type. |

## Filter ip

`tasks.<name>.filter[].ip`

Rules on the address.

| Key | Takes | |
|---|---|---|
| `type` | list of `global`, `private`, `ula`, `cgnat`, `link_local`, `eui64`, `random`, `temporary`, `!global`, `!private`, `!ula`, `!cgnat`, `!link_local`, `!eui64`, `!random`, `!temporary` | Address types, all of which must apply: global, private, ula, cgnat, link_local, eui64 (IPv6 from the MAC, stable), random (IPv6, not from the MAC), temporary (an IPv6 privacy address of this machine's, which changes every day or so). "!type": not of the type, as "!temporary". |
| `prefix` | string | A prefix the address must be in: 2001:db8::/32, 192.168.1.0/24. |
| `suffix` | string | The end of the address, in its canonical lower case form: ::1, dead:beef. |
| `mask` | list of string | VALUE/MASK pairs of addresses of one family, all of which the address must match in the bits the mask sets: ::1/::ffff:ffff:ffff:ffff for the IPv6 addresses ending in ::1, 0.0.0.5/0.0.0.255 for the IPv4 ones ending in .5. The mask is an address, not a prefix length: prefix takes those. A pair matches the addresses of its family only. |
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
| `debounce` | duration | How long to wait for more changes before updating. Default: 10s. A resolver credential's: none, as its updates are kept in memory, at once. |
| `retry` | duration | How long to wait before retrying a failed update: addresses that change meanwhile wait for it too. At least 1s. Default: 1m. |
| `debounce_time` | duration | Deprecated, and goes in v1.0: debounce. |
| `retry_time` | duration | Deprecated, and goes in v1.0: retry. |

## Resolvers

`resolvers.<name>`

DNS servers for the clients of a network, by name: each answers the zones of its resolver credentials, with the addresses the tasks give their names, and records of its own, and asks its upstream servers the rest. See the [resolver](../resolver.md).

| Key | Takes | |
|---|---|---|
| `listen` | list, or comma separated | **Required.** Where it answers, over UDP and TCP: networks of the machine's addresses, addresses, host names or ports: 192.168.1.0/24, 192.168.1.2, [fd00::2]:5353; without a port, 53. A port alone is every address of the machine, a public one on a router too: give the network of the clients. An address and port is one resolver's, however two spell it. |
| `allow` | list, or comma separated | The networks of the clients it answers, or their addresses: 192.168.1.0/24, fd00::/64. A query from any other is REFUSED. Default: the networks of the machine's addresses it listens on. |
| `upstream` | list, or comma separated | **Required.** The servers it asks what isn't its own, in order, each for 2s: plain DNS, over UDP, and over TCP when the answer doesn't fit, as 192.168.1.1, 1.1.1.1:53, [2606:4700:4700::1111] or dns.example.net, without a port 53; DNS over TLS, as tls://1.1.1.1 or tls://dns.example.net, without a port 853; or DNS over HTTPS, as https://dns.example.net/dns-query, without a port 443. An encrypted server's certificate is verified, against the system's certificate authorities, for the host given, and its connections are kept for the next queries. A host name needs bootstrap. None answering is SERVFAIL. |
| `bootstrap` | list, or comma separated | With an upstream given by host name, plain or encrypted, and only then: the servers asked its addresses, and nothing else, in order, over plain DNS: addresses, with a port or not. Not the system's resolver, which can be this one. The addresses found are kept for their TTL, a minute at least, an hour at most, and while these servers don't answer. |
| `records` | list of string | Records of names of none of its zones, one per entry, in the syntax of a zone file, every name absolute, with its trailing dot: www.example.com. CNAME nas.home.arpa. A record without a TTL has 1m. |
| `cache_size` | number | How many answers of the upstream servers it keeps, each for its TTL, a day at most, an hour for a name that doesn't exist or has no data: beyond it, the one asked the longest ago goes first. Default: 10000; 0, none, and every query is asked. The local names are never kept: they follow discovery at once. |

## Sources

`sources.<name>`

Sources of addresses without a MAC, as the network's public IPv4, by name, which tasks name in their sources. See [sources](../sources.md).

| Key | Takes | |
|---|---|---|
| `type` | `http`, `dns`, `command`, `static`, `homeassistant` | **Required.** dns: the public address, as OpenDNS's or Google's resolvers see it. http: from echo services over HTTPS, or urls. command: the addresses a command prints, one per line. static: the addresses listed. homeassistant: the addresses in a Home Assistant entity's state, which needs the homeassistant block. |
| `family` | list of `4`, `6` | http and dns: the families to find. Default: 4. |
| `interval` | duration | How often it runs. Default: 5m. |
| `lifetime` | duration | How long an address stays after the last run that gave it. Default: 3 intervals. |
| `urls` | list of string | http: the echo services to ask, in order. |
| `command` | string | command: the program to run, from the configuration's directory. |
| `args` | list of string | command: its arguments. |
| `addresses` | list of string | static: the addresses. |
| `entity` | string | homeassistant: the entity, as sensor.wan_ip. |
| `attribute` | string | homeassistant: the attribute of the entity to read, rather than its state. |

## Web server

`webserver`

The web server: the report, /status.json and /metrics. See [the web report](../installation.md#the-web-report).

| Key | Takes | |
|---|---|---|
| `listen` | list, or comma separated | Where to serve: ports, addresses, networks of the machine's addresses and host names: 8053, 192.0.2.1:8053, [2001:db8::1]:8053, 10.2.3.0/24, myhost; without a port, 8053. A host name listens on each address it resolves to, at start; a network, on each address of the machine in it. |

## Home Assistant

`homeassistant`

Makes ipv6ddns a device of Home Assistant's ESPHome integration: Home Assistant discovers it, and shows each name's addresses, last update and problems, and the hosts discovered, with a button to update now; and it sends the states homeassistant sources read. See docs/home-assistant-integration.md. See [the Home Assistant integration](../home-assistant-integration.md).

| Key | Takes | |
|---|---|---|
| `key` | string | **Required**, without `key_provisioning`. The encryption key: the base64 of 32 bytes, which Home Assistant asks when adding the device, and can't change: nothing is written. Make one with openssl rand -base64 32. This, or key_provisioning: true. |
| `key_provisioning` | boolean | Whether Home Assistant makes the key and gives it when adding the device, as to ESPHome's devices: it is kept in key_provisioning_state_file. Default: false, and the block needs a key. |
| `key_provisioning_state_file` | string | With key_provisioning: true, and only then: where the device keeps its identity, by which Home Assistant knows it, and the key Home Assistant gave. A file ipv6ddns can write; relative, from the configuration's folder. Default: homeassistant.state. One for each instance: another with a state file that is in use doesn't start. Deleting it makes the device a new one, without a key. |
| `name` | string | The device's name in the network: lower case letters, digits and hyphens. Default: ipv6ddns. One for each instance on the network: a second with a name that is announced already doesn't announce itself. |
| `friendly_name` | string | The name Home Assistant shows. Default: the name. |
| `port` | number | The port Home Assistant connects to, which the device announces. Default: 6053, ESPHome's. |
| `announce` | boolean | Whether the device announces itself by mDNS, for Home Assistant to find it. Without, add it by its address. Default: true. |
| `listen` | list, or comma separated | **Required.** Required. Where Home Assistant can connect to the device: a list of networks, addresses, host names or ports, as 192.168.1.0/24, 192.168.1.10, [fd00::1]:7000, myhost or 6053. A network means this machine's addresses in it; an entry without a port uses port (6053). A port alone means every address of this machine, including a public one on a router: prefer the network Home Assistant is on. The device announces itself by mDNS only on the interfaces of these addresses, and announces one port, so entries with different ports need announce: false. |

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
| `hostnames` | object | - | The names of the hosts: whether they are kept. What learns them is each protocol's to say, under protocols, and the plugins'. |
| `protocols` | object | - | The protocols of the local discovery, each with its switch, enabled, and its options: always a mapping, never true or false alone. One runs when it is enabled, its family is, and the family listens, or for what probes is active. |
| `plugins` | object | - | The plugins, by name: each reads the neighbor tables of a router or another host, and with hostnames the names of its DHCP leases. The name is the source of what it finds. |
| `solicit` | object | - | Asking the hosts the filters want, which aren't otherwise found, once a minute. Of ipv6ddns, not of ipv6disc: the hosts are those the filters name by their MAC. |

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

The names of the hosts: whether they are kept. What learns them is each protocol's to say, under protocols, and the plugins'.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `false` | Whether names are kept, and the plugins read those of their routers' DHCP leases. Without it a protocol that also finds hosts, as mdns, dhcp and lldp, still finds them, and takes no name; one that only learns names, netbios, llmnr, dns, and the names of wsd and ssdp, is then an error to enable. |
| `lifetime` | duration | - | How long a name stays after it was last said, whatever said it, the plugins too. Default: lifetime. |

## Discovery solicit

`discovery.solicit`

Asking the hosts the filters want, which aren't otherwise found, once a minute. Of ipv6ddns, not of ipv6disc: the hosts are those the filters name by their MAC.

| Key | Takes | Default | |
|---|---|---|---|
| `ipv6` | boolean | `false` | For each filter that names a mac.address and the eui64 type, a neighbor solicitation for the EUI-64 address of that MAC, on each /64 listened on. It needs ipv6.listen, which reads the answers. |
| `ipv4` | boolean | `false` | For each filter that names a mac.address with ip.family 4, ARP requests to that MAC alone, for the addresses of the local subnets within the filter's ip.prefix. It needs ipv4.enabled, Linux and CAP_NET_RAW. |

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
| `names` | boolean | `false` | Whether a device that answers the search is asked its description, over HTTP, for its friendly name. It needs hostnames. |

### wsd

`discovery.protocols.wsd`

IPv6. WS-Discovery, of Windows and Samba: active, a probe goes to its group, and listening hears the answers, at the port it left from. No group is joined.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `names` | boolean | `false` | Whether a computer that answers the probe is asked its metadata, over HTTP, for its name. It needs hostnames. |

### mdns

`discovery.protocols.mdns`

Either family, listening. mDNS: its groups are joined, on port 5353, and whatever sends there is a host of the link, whose address is found as any other, and with hostnames what it announces is its name. Active, a query for the services goes to the group.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `false` | Whether the protocol runs. |
| `ask` | boolean | `true` | Whether questions are sent: the query to the group, at every rediscover, and with hostnames to each host for its name. Without it mDNS only listens. |

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

Either family, listening. What the DHCP clients say to all as they ask for an address, heard by packet sockets that only listen: the address a client asks for is found as any other, and with hostnames the name it gives its server is its name. It needs Linux, and root or CAP_NET_RAW: without the privilege it is said once in the log, and the rest runs. Elsewhere it is an error to enable.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `false` | Whether the protocol runs. |

### lldp

`discovery.protocols.lldp`

Either family, listening. What the LLDP neighbor of an interface says of itself, heard by a packet socket that only listens: the addresses it is managed at are found as any other, and with hostnames its system name is its name. It needs Linux, and root or CAP_NET_RAW: without the privilege it is said once in the log, and the rest runs. Elsewhere it is an error to enable.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `false` | Whether the protocol runs. |

### netbios

`discovery.protocols.netbios`

IPv4, listening. A host is asked its node status, by a question sent to it alone: Windows answers, and Samba, with the machine's name. Names only: it needs hostnames.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `false` | Whether the protocol runs. |

### llmnr

`discovery.protocols.llmnr`

Either family, listening. A host is asked the name of one of its addresses, by a question to the group of LLMNR, which every host of the link hears: Windows answers, and systemd-resolved. Names only: it needs hostnames.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `false` | Whether the protocol runs. |

### dns

`discovery.protocols.dns`

Of no family: DNS servers are asked the name of each address, its PTR record, of the hosts the plugins found too. Names only: it needs hostnames.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `false` | Whether the protocol runs. |
| `servers` | list, or comma separated | - | The servers asked, needed when dns is enabled: each an address, alone or with its port, as 192.168.1.1, 192.168.1.1:5353 or [fd00::1]:53. Only these are asked, never the system's resolver. |

## Discovery plugins

`discovery.plugins.<name>`

The plugins, by name: each reads the neighbor tables of a router or another host, and with hostnames the names of its DHCP leases. The name is the source of what it finds. Each type takes its own keys only.

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
