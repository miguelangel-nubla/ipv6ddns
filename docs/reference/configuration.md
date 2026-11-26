# Configuration reference

<!-- Generated from the schemas by `go test ./internal/docgen -update`: edit them, not this page. -->

The configuration file is YAML, or JSON. Every string takes `${NAME}`, an environment variable, and `${file:PATH}`, a file's content: see [secrets](../configuration.md#secrets). A duration is `90s`, `1m30s`, `1h`, or a number of seconds. A key the schema doesn't have is an error. The schema is [`config/schema.json`](../../config/schema.json).

## Top level

| Key | Takes | |
|---|---|---|
| `tasks` | object | **Required.** The DNS names to keep up to date, by task name. Each task takes the addresses its filters match, and those of the sources it lists, and gives them to the names under its endpoints. |
| `credentials` | object | **Required.** The DNS providers to update, by credential name. Tasks name them under endpoints. |
| `resolvers` | object | DNS servers for the clients on a network, by name. Each answers the zones of its resolver credentials, with the addresses the tasks give their names and with its own records, and asks its upstream servers everything else. See the [resolver](../resolver.md). |
| `certificates` | object | The certificates the resolvers' encrypted entries and the web server's HTTPS ones show, by name: each server gives one as its tls, and two servers can show one. Each has files of its own, and is shown by at least one server. |
| `discovery` | object | How hosts are found: on the local links, by the protocols turned on, and by plugins that read routers' tables. Every key is optional: a key left out has its default. |
| `sources` | object | Sources of addresses that have no MAC, such as the network's public IPv4, by name. Tasks list them under sources. |
| `state_dir` | string | The folder where ipv6ddns keeps what it writes: the push sources' addresses, the certificates ACME gets, the dynamic updates' challenges and names, and the Home Assistant device's key. Relative to the configuration's folder, unless absolute; made when missing. Default: the configuration's folder. Give it when the configuration is read-only, as a file of Docker's or Kubernetes' secrets is. See [state](../configuration.md#state). |
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
| `prefix_source` | string | A push source: an IPv6 address must be in the IPv6 prefix of the LAN that its router sent last, as a Fritz!Box sends it with ip6lanprefix. When the ISP changes the prefix, the addresses of the one before leave the names as soon as the router sends the new one, rather than when they expire. IPv4 addresses pass, as does every address until the router has sent a prefix. |

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
| `listen` | list, or comma separated | - | **Required.** Where it answers: networks of the machine's addresses, addresses, host names or ports, as 192.168.1.0/24, 192.168.1.2 or [fd00::2]:5353. Plain DNS, over UDP and TCP, port 53 by default. An entry that starts with tls://, https:// or quic:// answers over that encrypted transport instead: DNS over TLS, port 853 by default, as tls://192.168.1.0/24; DNS over HTTPS, port 443, at /dns-query, as https://192.168.1.0/24; DNS over QUIC, UDP port 853, as quic://192.168.1.0/24. The encrypted ones need tls. A port alone means every address of the machine, including a public one on a router: give the clients' network instead. Two resolvers can't share an address and port over the same protocol, however each writes it. |
| `tls` | string | - | The certificate the encrypted entries of listen show: the name of one of certificates, as home. Required with an encrypted entry, and only then. |
| `allow` | list, or comma separated | - | The networks or addresses of the clients it answers, as 192.168.1.0/24 or fd00::/64. Any other client gets REFUSED. Default: the networks of the addresses it listens on. |
| `upstream` | list, or comma separated | - | **Required.** The servers it asks about names that aren't its own, in order, giving each 2s. Plain DNS, over UDP, and over TCP when the answer doesn't fit: 192.168.1.1, 1.1.1.1:53, [2606:4700:4700::1111] or dns.example.net, port 53 by default. DNS over TLS: tls://1.1.1.1 or tls://dns.example.net, port 853 by default. DNS over HTTPS: https://dns.example.net/dns-query, port 443 by default. An encrypted server's certificate is checked against the system's certificate authorities, for the host given, and its connections are reused. A host name needs bootstrap. When none answers, the client gets SERVFAIL. |
| `bootstrap` | list, or comma separated | - | Only for upstream servers given by host name, plain or encrypted: the servers that look up their addresses, and nothing else. Addresses, with or without a port, asked in order over plain DNS. The system's resolver isn't used, since it may be this one. The addresses found are kept for their TTL, between a minute and an hour, and for as long as these servers don't answer. |
| `records` | list of string | - | Records of names outside its zones, one per entry, in zone file syntax, with every name absolute and ending in a dot: www.example.com. CNAME nas.lan.example.com. A record without a TTL gets 1m. |
| `cache_size` | number | - | How many answers of the upstream servers it keeps, each for its TTL: a day at most, and an hour for a name that doesn't exist or has no data. When full, the one asked longest ago goes first. Default: 10000. 0 keeps none, and every query goes upstream. Local names are never kept: they follow discovery at once. |
| `forward_unknown_private_reverse_queries` | boolean | `false` | Whether to ask the upstream servers for the reverse name of a private address the resolver has no name for: for an upstream server that knows more names, as a router does for its DHCP clients. By default, as RFC 6303 says, the resolver answers that there's no such name, and the question never leaves it. The private ranges are 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, the loopback, link-local and documentation ones, fd00::/8, fe80::/10, ::1 and 2001:db8::/32. |
| `updates` | object | - | Dynamic updates, by RFC 2136: the clients that hold one of keys may change records, each within its permissions, over plain DNS or DNS over TLS. A query signed with a key is answered with authority about the names of its permissions, as certbot and nsupdate find their zone; any other query, unsigned or not, as before. An unsigned update is refused. See [dynamic updates](../resolver.md#dynamic-updates). |

### updates

`resolvers.<name>.updates`

Dynamic updates, by RFC 2136: the clients that hold one of keys may change records, each within its permissions, over plain DNS or DNS over TLS. A query signed with a key is answered with authority about the names of its permissions, as certbot and nsupdate find their zone; any other query, unsigned or not, as before. An unsigned update is refused. See [dynamic updates](../resolver.md#dynamic-updates).

| Key | Takes | |
|---|---|---|
| `allow` | list, or comma separated | The networks or addresses the keys may send from, of those that give none, as 192.168.1.0/24. Default: the resolver's allow. |
| `keys` | object | **Required.** The TSIG keys, by their names, as the clients give them: nas, as certbot's dns_rfc2136_name. tsig-keygen -a hmac-sha256 nas makes one. |

### keys

`resolvers.<name>.updates.keys.<name>`

The TSIG keys, by their names, as the clients give them: nas, as certbot's dns_rfc2136_name. tsig-keygen -a hmac-sha256 nas makes one.

| Key | Takes | Default | |
|---|---|---|---|
| `secret` | string | - | **Required.** The key's secret, in base64, as tsig-keygen writes it: 16 bytes at least. Keep it in a file, as ${file:tsig_nas}. |
| `algorithm` | `hmac-sha256`, `hmac-sha384`, `hmac-sha512` | `hmac-sha256` | The algorithm of the key. |
| `allow` | list, or comma separated | - | The networks or addresses this key may send from, as 198.51.100.0/24. Default: the allow of updates. |
| `permissions` | list of object | - | **Required.** What the key may change, each a permission of one kind: challenges, addresses or names. An update goes to the first permission that holds all of it. A name can be changed by one key alone. |

### permissions: challenges

`resolvers.<name>.updates.keys.<name>.permissions[].challenges`

The TXT records of the DNS challenge of ACME, of some names, written through a credential: what certbot, lego or acme.sh on another machine changes to get a certificate. Of each name, _acme-challenge and its name alone.

| Key | Takes | |
|---|---|---|
| `credential` | string | **Required.** The credential of the public zone of the names, which writes the records: of a provider that writes TXT records, as the providers reference marks them. |
| `names` | list, or comma separated | **Required.** The names of the certificates, relative to the zone of the credential, as acme's: nas.lan, or *.apps. A wildcard and its parent have one challenge, so either allows both. None may be a name of a certificate of ipv6ddns's own. |

### permissions: addresses

`resolvers.<name>.updates.keys.<name>.permissions[].addresses`

The A and AAAA records of a name, which go to a push source as its addresses: what a host that updates its own address with nsupdate, or a router's RFC 2136 client, changes.

| Key | Takes | |
|---|---|---|
| `source` | string | **Required.** The push source the addresses go to. |
| `zone` | string | **Required.** The zone of the name, as the client gives it its updates: example.com. |
| `name` | string | The name the client updates, relative to the zone. Default: the source's name. |

### permissions: names

`resolvers.<name>.updates.keys.<name>.permissions[].names`

The names of the hosts of a zone, with their addresses, as a DHCP server's dynamic DNS sends them, signed with the key: Kea's, or ISC dhcpd's. Each name goes to the host discovery found at its address, and is kept in names-<zone>.json beside the configuration. See [names from your DHCP server](../guides/dhcp-server-names.md).

| Key | Takes | |
|---|---|---|
| `zone` | string | **Required.** The zone of the names, as the DHCP server gives it: lan.example.com. |

## Sources

`sources.<name>`

Sources of addresses that have no MAC, such as the network's public IPv4, by name. Tasks list them under sources. See [sources](../sources.md).

| Key | Takes | |
|---|---|---|
| `type` | `http`, `dns`, `command`, `static`, `homeassistant`, `push` | **Required.** Where the addresses come from. dns: the public address, as OpenDNS's or Google's resolvers see it. http: echo services over HTTPS, or the urls given. command: the addresses a command prints, one per line. static: the addresses listed. homeassistant: the addresses in a Home Assistant entity's state, which needs the homeassistant block. push: the addresses a router sends, as to a DynDNS service, through the web server at /nic/update. |
| `family` | list of `4`, `6` | For http and dns: the families to find. Default: 4. |
| `interval` | duration | How often it runs. Default: 5m. |
| `lifetime` | duration | How long an address stays after the last run that gave it. Default: 3 intervals. Of a push source: after the last update that sent it; by default, until the next update, however far. |
| `urls` | list of string | For http: the echo services to ask, in order. |
| `command` | string | For command: the program to run, from the configuration's folder. |
| `args` | list of string | For command: its arguments. |
| `addresses` | list of string | For static: the addresses. |
| `entity` | string | For homeassistant: the entity, as sensor.wan_ip. |
| `attribute` | string | For homeassistant: an attribute of the entity to read instead of its state. |
| `password` | string | push: the password the router sends with its updates, as the HTTP basic password or as password in the URL. Required, unless a key of a resolver's updates sends the addresses, with a permission of addresses: without one, the source takes those alone, and refuses every request of the web server. |
| `state_file` | string | push: the file the addresses sent last are kept in, so that a restart doesn't lose them until the router's next update. Relative to the configuration's folder, unless absolute. Default: push-<source>.json. |

## Web server

`webserver`

The web server, with the status page, /status.json and /metrics. See [the web report](../installation.md#the-web-report).

| Key | Takes | |
|---|---|---|
| `listen` | list, or comma separated | Where to serve: ports, addresses, networks of the machine's addresses or host names, as 8053, 192.0.2.1:8053, [2001:db8::1]:8053, 10.2.3.0/24 or myhost. Without a port, 8053. A host name listens on each address it resolves to at start; a network, on each of the machine's addresses in it. An entry that starts with https:// serves HTTPS there, with the certificate of tls, on port 8443 without one: as https://192.168.1.2. The plain ones stay HTTP, as the Home Assistant app's page needs. |
| `tls` | string | The certificate of the HTTPS entries of listen: the name of one of certificates, as home. Required with one, and only then. |

## Certificates

`certificates.<name>`

The certificates the resolvers' encrypted entries and the web server's HTTPS ones show, by name: each server gives one as its tls, and two servers can show one. Each has files of its own, and is shown by at least one server. A certificate that the resolvers' encrypted entries and the web server's HTTPS ones show, those that give its name as their tls: its files, or acme, for ipv6ddns to get it from an authority, as Let's Encrypt, and renew it. A server shows it whatever names its listen has: for clients to take it, it must be for the names they use. See [encrypted DNS for the clients](../resolver.md#encrypted-dns-for-the-clients).

| Key | Takes | |
|---|---|---|
| `certificate` | string | The file of the certificate, in PEM, with its chain: fullchain.pem, as Let's Encrypt names it. Clients check it is for the name they were given, so most need one a public authority signed, for a name of a domain you own, as dns.lan.example.com. It is read again when it changes, so a renewed certificate is shown without a restart. Relative to the configuration's folder, unless absolute. Required without acme; with it, where ipv6ddns writes the certificate, by default tls/<name>/fullchain.pem. |
| `key` | string | The file of the certificate's private key, in PEM: privkey.pem, as Let's Encrypt names it. Relative to the configuration's folder, unless absolute. Required without acme; with it, where ipv6ddns writes the key, by default tls/<name>/privkey.pem. |
| `acme` | object | A certificate that ipv6ddns gets from an ACME authority, Let's Encrypt by default, by its DNS challenge: it writes the TXT record the authority checks through a credential of the names' public zone, and renews the certificate once two thirds of its lifetime have passed. The names need no address on the internet. It is written to certificate and key, with the account's key, acme-account.key, beside them. Until there is one, the encrypted entries refuse their connections, and the report says why. |

### acme

`certificates.<name>.acme`

A certificate that ipv6ddns gets from an ACME authority, Let's Encrypt by default, by its DNS challenge: it writes the TXT record the authority checks through a credential of the names' public zone, and renews the certificate once two thirds of its lifetime have passed. The names need no address on the internet. It is written to certificate and key, with the account's key, acme-account.key, beside them. Until there is one, the encrypted entries refuse their connections, and the report says why.

| Key | Takes | |
|---|---|---|
| `names` | list, or comma separated | The names the certificate is for, relative to the zone of credential, as an endpoint's names are: dns.lan, of the zone example.com, is dns.lan.example.com. A wildcard, as *.lan, is one too. The clients are given one of them, which must have this machine's address, as a record of the resolver's zone. |
| `credential` | string | The credential of the names' public zone, which writes the TXT record of the challenge: of a provider that writes TXT records, as the providers reference marks them. |
| `email` | string | An address the authority may write to about the account. Let's Encrypt sends no more mail about certificates that end. Default: none. |
| `directory` | string | The authority's directory: Let's Encrypt's, https://acme-v02.api.letsencrypt.org/directory, by default. Its staging one, https://acme-staging-v02.api.letsencrypt.org/directory, signs certificates that no client trusts, without its limits, to try the setup with. |

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

How hosts are found: on the local links, by the protocols turned on, and by plugins that read routers' tables. Every key is optional: a key left out has its default. The keys are those of [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc), whose discovery it is, but `solicit`, which is of ipv6ddns: a file of its command's keys is this block. See [discovery](../discovery.md).

| Key | Takes | Default | |
|---|---|---|---|
| `lifetime` | duration | `1h` | How long an address stays after it was last seen, unless its family sets its own. |
| `rediscover` | duration | - | How often active discovery probes every host. Default: a third of the shortest lifetime among the families that probe, so that a quiet host is probed before it expires. |
| `interfaces` | list, or comma separated | - | The interfaces local discovery runs on, for both families: names, or patterns such as en*. Default: all. Plugins aren't affected. |
| `exclude_interfaces` | list, or comma separated | - | The interfaces local discovery skips: names, or patterns such as docker* or veth*. |
| `ipv6` | object | - | IPv6: switches for all its protocols at once. A protocol runs only when it's enabled under protocols, and its family and the way it works are on here. |
| `ipv4` | object | - | IPv4: switches for all its protocols at once. A protocol runs only when it's enabled under protocols, and its family and the way it works are on here. |
| `hostnames` | object | - | The hosts' names, which are always kept. They come from each protocol under protocols that learns names, and from plugins, which read their routers' DHCP leases. To learn none, turn those protocols off, and the names option of ssdp and wsd. |
| `protocols` | object | - | The local discovery protocols, each with its enabled switch and its options: always a mapping, never true or false on its own. A protocol runs when it's enabled and its family is on and listens, or, for what probes, is active. |
| `plugins` | object | - | The plugins, by name. Each reads the neighbor tables of a router or another host, and its DHCP leases: the names in them, and that an address found otherwise is leased. The plugin's name is the source of what it finds. |
| `solicit` | object | - | Asks for the hosts the filters name by MAC, once a minute, when nothing else finds them. Part of ipv6ddns, not of ipv6disc. |

## Discovery IPv6

`discovery.ipv6`

IPv6: switches for all its protocols at once. A protocol runs only when it's enabled under protocols, and its family and the way it works are on here.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the family's addresses are kept, and the plugins read them. When off, the rest of the family is off too. |
| `listen` | boolean | `true` | Local discovery of IPv6: its protocols listen, and ask each host about what they heard of it. When off, only plugins find IPv6 addresses. |
| `active` | boolean | `true` | Probes every host on the links at each rediscover: the multicast ping, the SSDP search, the WS-Discovery probe and the mDNS query. Needs listen, which reads the answers. |
| `lifetime` | duration | - | How long the family's addresses stay after they were last seen, whatever found them, plugins included. Default: lifetime. |

## Discovery IPv4

`discovery.ipv4`

IPv4: switches for all its protocols at once. A protocol runs only when it's enabled under protocols, and its family and the way it works are on here.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `false` | Whether the family's addresses are kept, and the plugins read them. When off, the rest of the family is off too. |
| `listen` | boolean | `true` | Local discovery of IPv4: the neighbor table is read, and the hosts' ARP is heard. When off, only plugins find IPv4 addresses. |
| `active` | boolean | `true` | Probes every host on the subnets at each rediscover: the sweep, which broadcasts an ARP request for each address, and the mDNS query. Needs listen, which reads the answers. |
| `lifetime` | duration | - | How long the family's addresses stay after they were last seen, whatever found them, plugins included. Default: lifetime. |

## Discovery hostnames

`discovery.hostnames`

The hosts' names, which are always kept. They come from each protocol under protocols that learns names, and from plugins, which read their routers' DHCP leases. To learn none, turn those protocols off, and the names option of ssdp and wsd.

| Key | Takes | |
|---|---|---|
| `lifetime` | duration | How long a name stays after it was last given, whatever gave it, plugins included. Default: lifetime. |

## Discovery solicit

`discovery.solicit`

Asks for the hosts the filters name by MAC, once a minute, when nothing else finds them. Part of ipv6ddns, not of ipv6disc.

| Key | Takes | Default | |
|---|---|---|---|
| `ipv6` | boolean | `false` | For each filter with a mac.address and the eui64 type: a neighbor solicitation for that MAC's EUI-64 address, on each /64 discovery listens on. It needs ipv6.listen, which reads the answers. |
| `ipv4` | boolean | `false` | For each filter with a mac.address and ip.family 4: ARP requests to that MAC alone, for the local subnets' addresses inside the filter's ip.prefix. It needs ipv4.enabled, Linux and CAP_NET_RAW. |

## Discovery protocols

`discovery.protocols`

The local discovery protocols, each with its enabled switch and its options: always a mapping, never true or false on its own. A protocol runs when it's enabled and its family is on and listens, or, for what probes, is active.

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

IPv6, listening. Neighbor discovery on each link: every advertisement and solicitation heard gives an address and its MAC. It also asks, with a neighbor solicitation, the MAC of whatever the other IPv6 protocols hear. Without it, ping, ssdp and wsd find nothing, and enabling them is an error. It needs root or CAP_NET_RAW.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### ping

`discovery.protocols.ping`

IPv6. Listening, an address is pinged before it expires, so that a host still there keeps it. Active, every host is pinged at once, through the all-nodes group. It needs root or CAP_NET_RAW.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### ssdp

`discovery.protocols.ssdp`

IPv6. SSDP, for UPnP devices. Active, a search goes to its group; listening hears the answers, on the port the search left from. No group is joined.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `names` | boolean | `true` | Whether a device that answers the search is asked for its description, over HTTP, to get its friendly name. |

### wsd

`discovery.protocols.wsd`

IPv6. WS-Discovery, for Windows and Samba. Active, a probe goes to its group; listening hears the answers, on the port the probe left from. No group is joined.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `names` | boolean | `true` | Whether a computer that answers the probe is asked for its metadata, over HTTP, to get its name. |

### mdns

`discovery.protocols.mdns`

Either family, listening. mDNS: it joins its groups, on port 5353. Whatever sends there is a host on the link, whose address is found as any other, and the name it announces is its name. Active, a query for services goes to the group.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `ask` | boolean | `true` | Whether to send questions: the query to the group at each rediscover, and to each host for its name. When off, mDNS only listens. |

### arp

`discovery.protocols.arp`

IPv4, listening. Reads the kernel's neighbor table every minute, and after each sweep.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### arp-sweep

`discovery.protocols.arp-sweep`

IPv4, active. Sweeps the local subnets: a UDP packet to the discard port of each address makes the kernel resolve it, which broadcasts an ARP request. arp or arp-listen hears the hosts that answer: enabling it without either is an error.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |
| `max_prefix` | number | `22` | The largest subnet swept whole, by prefix length: 22 is a /22, of 1022 addresses. In a larger one, only the /24 around the interface's address is swept, or the prefix of this length there, when that is smaller. |

### arp-listen

`discovery.protocols.arp-listen`

IPv4, listening. Hears the ARP that hosts send, through a packet socket that only listens, so each host is found at once instead of at the next table read. It needs Linux, and root or CAP_NET_RAW: without the privilege, the log says so once, and the rest runs.

| Key | Takes | |
|---|---|---|
| `enabled` | boolean | Whether the protocol runs. Default: true on Linux, the only system where it can; false elsewhere, where true is an error. |

### dhcp

`discovery.protocols.dhcp`

Either family, listening. Hears what DHCP clients broadcast as they ask for an address, through packet sockets that only listen. The address a client asks for is found as any other, and the name it gives its server is its name. It needs Linux, and root or CAP_NET_RAW: without the privilege, the log says so once, and the rest runs.

| Key | Takes | |
|---|---|---|
| `enabled` | boolean | Whether the protocol runs. Default: true on Linux, the only system where it can; false elsewhere, where true is an error. |

### lldp

`discovery.protocols.lldp`

Either family, listening. Hears what an interface's LLDP neighbor says about itself, through a packet socket that only listens. The addresses it's managed at are found as any other, and its system name is its name. It needs Linux, and root or CAP_NET_RAW: without the privilege, the log says so once, and the rest runs.

| Key | Takes | |
|---|---|---|
| `enabled` | boolean | Whether the protocol runs. Default: true on Linux, the only system where it can; false elsewhere, where true is an error. |

### netbios

`discovery.protocols.netbios`

IPv4, listening. Asks each host for its node status, with a question sent to it alone: Windows and Samba answer with the machine's name. Names only.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### llmnr

`discovery.protocols.llmnr`

Either family, listening. Asks a host for the name of one of its addresses, through the LLMNR group, which every host on the link hears: Windows and systemd-resolved answer. Names only.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs. |

### dns

`discovery.protocols.dns`

Of either family. Asks DNS servers for each address's name, its PTR record, including those of hosts the plugins found. Names only.

| Key | Takes | Default | |
|---|---|---|---|
| `enabled` | boolean | `true` | Whether the protocol runs, once it has servers, the only ones it asks. |
| `servers` | list, or comma separated | - | The servers to ask; without any, dns asks nobody. Each is an address, with or without a port, as 192.168.1.1, 192.168.1.1:5353 or [fd00::1]:53. Only these are asked, never the system's resolver. |

## Discovery plugins

`discovery.plugins.<name>`

The plugins, by name. Each reads the neighbor tables of a router or another host, and its DHCP leases: the names in them, and that an address found otherwise is leased. The plugin's name is the source of what it finds. Each type takes its own keys only.

### `linux`, `freebsd`

A plugin over SSH, linux or freebsd, with a password, an identity file, or both.

| Key | Takes | |
|---|---|---|
| `type` | string | **Required.** The type of the plugin. |
| `interval` | duration | **Required.** How often the table is read, as 60s or 5m. |
| `address` | string | **Required.** The host, with its port unless it's 22, as 192.168.1.1 or [2001:db8::1]:2222. |
| `username` | string | **Required.** The SSH user. |
| `password` | string | Its password. An identity_file works instead, or as well. |
| `identity_file` | string | The SSH private key file. |
| `host_key` | string | The fingerprint of the host's SSH key, as ssh-keygen -l shows it: SHA256:.... Any of its keys works. Recommended: without it, any key is accepted, and the log warns with the fingerprint it saw. |

### `mikrotik`

A plugin over the MikroTik API.

| Key | Takes | |
|---|---|---|
| `type` | string | **Required.** The type of the plugin. |
| `interval` | duration | **Required.** How often the tables are read, as 60s or 5m. |
| `address` | string | **Required.** The router, with its port unless it's the default: 8728, or 8729 with TLS. |
| `username` | string | **Required.** An API user: the read and api policies are enough. |
| `password` | string | Its password. |
| `use_tls` | boolean | Whether to use the API over TLS, the api-ssl service. Without it, the password crosses the network unencrypted. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the router's certificate, as 64 hex digits, colons allowed. For when the system's CAs can't verify it, as with the self-signed one RouterOS makes. It needs use_tls. |

### `unifi`

A plugin over the UniFi Network API.

| Key | Takes | |
|---|---|---|
| `type` | string | **Required.** The type of the plugin. |
| `interval` | duration | **Required.** How often the clients are read, as 60s or 5m. |
| `address` | string | **Required.** The console, as https://192.168.1.1, or the self-hosted Network Application, as https://192.168.1.2:8443. |
| `api_key` | string | An API key of UniFi OS: in the console, Settings, Control Plane, Integrations. A self-hosted Network Application has none: give username and password instead. |
| `username` | string | A local user, instead of api_key, without two-factor authentication. Reading is enough. |
| `password` | string | Its password. |
| `site` | string | The site, by its name in the API: default unless you made others. Default: default. |
| `tls_fingerprint` | string | The SHA-256 fingerprint of the console's certificate, as 64 hex digits, colons allowed. For when the system's CAs can't verify it, as with the one a console makes for itself. |
