# The resolver

ipv6ddns can be the DNS server of your network. A resolver answers the zones of its `resolver` credentials with the addresses your tasks give their names, as soon as discovery finds them, plus any records you write. Everything else it asks of its upstream servers, such as your router or a public resolver.

You give the devices the resolver's address as their DNS server, by DHCP or in the router's advertisements. Then a name on the LAN, as `nas.home.arpa`, follows its host wherever its addresses move, with no other DNS server to update.

Nothing is sent to a provider: an update of a zone happens in memory, at once, and never fails.

```yaml
resolvers:
  lan:                                    # a name: any number of resolvers
    listen: 192.168.1.0/24                # the machine's address in it, port 53
    allow:                                # whom it answers: by default, the networks it listens on
      - 192.168.1.0/24
      - fd00::/64
    upstream:                             # whom it asks the rest, in order
      - 192.168.1.1
      - 1.1.1.1
    cache_size: 10000                     # the answers of theirs it keeps: the default
    records:                              # of names of none of its zones, absolute
      - www.example.com. CNAME nas.home.arpa.

credentials:
  home:
    provider: resolver                    # a zone the resolver answers
    settings:
      resolver: lan                       # needed only with more than one resolver
      zone: home.arpa
      records:                            # relative to the zone, or absolute within it
        - printer A 192.168.1.20
        - files CNAME nas
        - _ipp._tcp SRV 0 0 631 printer

tasks:
  nas:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
    endpoints:
      home:                               # nas.home.arpa
        - nas
```

Every key is in the reference: [`resolvers`](reference/configuration.md#resolvers), and [the provider's settings](reference/providers.md#resolver). For a whole setup, see the guide [every machine on the network by name](guides/network-wide-names.md).

## A resolver

- **`listen`** (required) is where it answers, over UDP and TCP. It takes the same forms as [`webserver.listen`](installation.md#the-web-report):
  - a network, as `192.168.1.0/24`, for each of the machine's addresses in it;
  - an address, as `192.168.1.2` or `[fd00::2]:5353`;
  - a host name;
  - or a port alone, for every address of the machine.

  Without a port, it's 53. On a router, a port alone includes the router's public address too, so give the clients' network instead.
- **`allow`** is the networks or addresses of the clients it answers. Anyone else gets `REFUSED`. By default it's the networks of the machine's addresses it listens on: `192.168.1.0/24` above, as the machine's interface has it. With a port alone, that's every network of the machine.
- **`upstream`** (required) is one or more servers it asks for everything that isn't its own. Each is an address or a host name, with or without a port: `192.168.1.1`, `1.1.1.1:53`, `[2606:4700:4700::1111]` or `dns.example.net`, over plain DNS. They can also be [encrypted](#encrypted-upstream-servers): `tls://1.1.1.1` for DNS over TLS, or `https://dns.example.net/dns-query` for DNS over HTTPS.
- **`bootstrap`** is needed only when an upstream is given by host name. These servers find the upstream's addresses, and are asked nothing else. They're addresses, with or without a port, over plain DNS. The system's resolver isn't used for this, since it may be this very resolver, asking itself.

  The addresses found, IPv4 and IPv6, are tried in turn as one upstream server. They're kept as long as the answer says, between a minute and an hour. While the bootstrap servers don't answer, they're asked again every 10 seconds. An upstream they never found is skipped, as one that is down.

```yaml
resolvers:
  lan:
    listen: 192.168.1.0/24
    upstream:
      - dns.example.net
      - 1.1.1.1
    bootstrap:
      - 9.9.9.9
```

- **`records`** are records for names outside all of its zones, as a public domain's name that the LAN should reach at a local address. Write each name in full, with its trailing dot, and the targets too.
- **`cache_size`** is how many upstream answers it keeps in [its cache](#the-cache): `10000` by default, `0` for none.

## Encrypted upstream servers

An upstream server can be asked over an encrypted connection, so that the network in between, such as your ISP's, can't read the names asked or change the answers.

- **`tls://host[:port]`** is DNS over TLS ([RFC 7858](https://www.rfc-editor.org/rfc/rfc7858)), on port 853 unless you give another. Nothing goes after the host: a path is for `https://`.
- **`https://host[:port]/path`** is DNS over HTTPS ([RFC 8484](https://www.rfc-editor.org/rfc/rfc8484)), on port 443 unless you give another. The path is where the server answers, `/dns-query` for most, and you have to give it. Each query is a `POST` of `application/dns-message`, over HTTP/2 when the server supports it. Redirects aren't followed.

```yaml
resolvers:
  lan:
    listen: 192.168.1.0/24
    upstream:
      - https://dns.quad9.net/dns-query   # found by bootstrap
      - tls://1.1.1.1                     # an address: no bootstrap for it
      - 192.168.1.1                       # the router, when neither answers
    bootstrap:
      - 9.9.9.9
```

The host is either a host name, which `bootstrap` finds as for a plain upstream, or an address.

The server's certificate is always verified, against the system's certificate authorities, for the host as you wrote it:

- For a host name, the certificate must be for that name, which is also the name the connection asks for (its SNI).
- For an address, the certificate must contain that address. `1.1.1.1`'s does, but few others do.

There's no option to turn verification off. A server whose certificate doesn't verify is skipped, as one that is down, and counts in `ipv6ddns_resolver_upstream_failures_total`.

Connections are kept and reused:

- **DNS over TLS:** a connection carries one query at a time, and is kept open for the next for 30 seconds. Queries at the same time each get their own connection, and each closes after 30 seconds without a query. If the server closed a connection in the meantime, it's replaced, and the query is asked again on the new one.
- **DNS over HTTPS:** one client, whose connections HTTP/2 shares among concurrent queries, each closed after 30 seconds without one. It connects only to the addresses `bootstrap` found, or the address you gave. It doesn't use a proxy from the environment either.

Encrypted queries are padded to a multiple of 128 bytes, as [RFC 8467](https://www.rfc-editor.org/rfc/rfc8467) recommends, so their size says less about the name asked. Everything else is as for any upstream: 2 seconds each, then the next one, and `SERVFAIL` when none answers. In the status and the metrics, an encrypted upstream is named as you wrote it.

The certificate authorities are the system's. On Linux, Go reads them from the usual places of each distribution. The environment variables `SSL_CERT_FILE` (a file of PEM certificates) and `SSL_CERT_DIR` (directories of them) name others instead, for a server whose certificate comes from your own authority. The Docker image has Alpine's `ca-certificates`. Another image must have them too, or no certificate verifies: `x509: certificate signed by unknown authority`.

## A zone

A credential with the provider `resolver` is a zone that a resolver answers. It has a `zone`, and a `resolver`, the resolver's name, which you can leave out when there's only one.

The zone's names are those of the tasks' endpoints, as for any provider: `nas` is `nas.home.arpa`, `""` is `home.arpa` itself, and `"*.nas"` is a wildcard. Its `records` are records of the zone's other names, written relative to the zone, or in full within it, as `printer.home.arpa.`.

The addresses of a name have the zone's `ttl`, `1m` by default, and so do its records that don't give their own. The credential's [`debounce`](configuration.md#its-parts) is zero by default for this provider, so a change is answered at once. A zone with no task still serves its records.

Two resolvers can each have a zone of the same name, through two credentials. The same name then has a different answer on each network, a split horizon: `nas.home.arpa` with the LAN's addresses on one, and the VPN's on the other.

## Records

Write each record as a line of a zone file: a name, an optional TTL, an optional class `IN`, a type, and its data.

```yaml
resolvers:
  lan:
    listen: 192.168.1.0/24
    upstream: 192.168.1.1
credentials:
  home:
    provider: resolver
    settings:
      zone: home.arpa
      records:
        - printer A 192.168.1.20
        - printer AAAA fd00::20
        - printer 300 TXT "color"
        - files CNAME nas              # nas.home.arpa
        - "*.dev CNAME nas"            # anything under dev.home.arpa, but what has its own
        - _ipp._tcp SRV 0 0 631 printer
        - "@ MX 10 mail.example.com."  # the zone itself
```

Several records of the same name and type are answered together, as the two addresses of a name. Any type works except an SOA, which the resolver makes itself, and the types that belong to a message, such as OPT.

## How a query is answered

In this order:

1. **A client outside `allow`** gets `REFUSED`, and nothing is asked upstream.
2. **A name in the resolver's own `records`** is answered from them.
3. **A name of a zone** is answered when a task publishes it or a record has it: the task's current addresses, as A and AAAA, or the records of the type asked. The zone is the deepest one that holds the name: `printer.lab.home.arpa` belongs to `lab.home.arpa` before `home.arpa`, while `printer.home.arpa` belongs to `home.arpa`. Answers from a zone are authoritative (`AA`).
   - When the name has nothing of the type asked, or is a task's name with no address yet or any more, the answer is "no data": `NOERROR`, empty, with an SOA of the zone that the resolver makes. Its 10 seconds are how long a client remembers that. A host that shows up has its name a moment later.
   - A wildcard, `*.dev`, answers any name under `dev` that has nothing of its own, provided no name in between has something: it answers `a.dev` and `a.b.dev`, but not `a.b.dev` when `b.dev`, or a name under it, has records. The answer carries the name asked.
4. **The reverse of an address**, a `PTR` query of a name under `in-addr.arpa` or `ip6.arpa`, is answered with the names of steps 2 and 3 that have that address, if any. See [reverse names](#reverse-names).
5. **Anything else**, whether a name no zone has or a name of no zone, is answered from [the cache](#the-cache) if it's there. Otherwise it's forwarded to the upstream servers in order, each given 2 seconds. Over plain DNS, it's asked again over TCP when the UDP answer doesn't fit. The first answer, whatever its code, is relayed as it is, with the client's id. The client's EDNS, its size and its DO bit, went upstream with the query. If none answers, it's `SERVFAIL`.

A name that a zone doesn't have isn't `NXDOMAIN` but whatever upstream answers. That's because a zone can be part of a domain that exists elsewhere, as `home.example.com` of a public `example.com`.

CNAMEs are followed among the local names (the tasks', the zones' records, and the resolver's own), up to 8 of them, and every step is in the answer. A target that isn't local is asked upstream, or taken from the cache, and its answer appended, since the clients' stub resolvers don't follow CNAMEs themselves. A query of type CNAME gets the CNAME alone.

An answer too big for the client's UDP size, 512 bytes or what its EDNS says, has `TC` set, and the client asks again over TCP.

## Reverse names

The address of a host gives its name back. `dig -x 192.168.1.20`, a `PTR` query of `20.1.168.192.in-addr.arpa`, or of the name under `ip6.arpa` for an IPv6 address, is answered with every name the resolver answers with that address:

- **The tasks' names** in its zones that have the address now. When discovery gives a name a new address, the old address's reverse stops answering, and the new one's starts, at once.
- **The names of `A` and `AAAA` records**, of its zones and its own `records`, that give the address.

They come sorted, each once, in an authoritative answer (`AA`), with the zone's `ttl`, or the record's own when it has one; the shortest when they differ. A wildcard isn't a host, and has no reverse. A `PTR` record you wrote in `records` for the reverse name itself is answered as any record, in place of these.

### Private networks

When the resolver has no name for an address of a private network, the reverse is "no such name", `NXDOMAIN`, answered by the resolver itself, as [RFC 6303](https://www.rfc-editor.org/rfc/rfc6303) asks. The question doesn't leave the network for servers that know nothing about it, and the client gets its answer at once. These are the networks that belong to no one on the internet:

| | IPv4 | IPv6 |
|---|---|---|
| Private | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | `fd00::/8`, the unique local addresses |
| Shared by carriers, [RFC 7793](https://www.rfc-editor.org/rfc/rfc7793) | `100.64.0.0/10` | |
| Link-local | `169.254.0.0/16` | `fe80::/10` |
| This host, the loopback | `0.0.0.0/8`, `127.0.0.0/8` | `::`, `::1` |
| The documentation's | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | `2001:db8::/32` |
| Broadcast | `255.255.255.255` | |

Each is a zone of its own, as `168.192.in-addr.arpa`, whose apex has the SOA and NS records RFC 6303 gives it. A name in it that the resolver has an address for, asked for a type other than `PTR`, gets "no data".

This holds whatever the upstream servers are, including a router on the network. A local server may know more of these names than the resolver does: a router knows its DHCP clients, and another server may answer the reverse of another VLAN. To ask it anyway, against RFC 6303, set `forward_unknown_private_reverse_queries`. Then every private reverse the resolver has no name for goes upstream, as any other name it doesn't know. The resolver still answers the names it has itself: only what it can't answer is asked.

```yaml
resolvers:
  lan:
    listen: 192.168.1.0/24
    upstream:
      - 192.168.1.1   # the router, which names its DHCP clients
    forward_unknown_private_reverse_queries: true
```

Only turn it on for upstream servers on your network. A public one knows none of these names, and the questions would leave the network for nothing.

### Other addresses

The reverse of any other address is forwarded, as any other name. A resolver only gives the reverse of names it answers itself: with a split horizon, each of the two resolvers gives an address's name as its own zone has it.

## The cache

The upstream servers' answers are kept, up to `cache_size` of them, `10000` by default. A name asked again while its answer is still valid is answered from the cache, without asking upstream. `cache_size: 0` keeps nothing, and asks every time.

- **An answer with records** is kept for the shortest of their TTLs, a day at most.
- **"No such name" (`NXDOMAIN`) or "no data"** is kept as [RFC 2308](https://www.rfc-editor.org/rfc/rfc2308) says: for the lower of the minimum of the SOA that comes with it and that SOA's TTL, an hour at most.
- **Never kept:** a failure, such as `SERVFAIL` or `REFUSED`; a truncated answer; a "no data" answer without an SOA, which says no time; and an answer whose time is 0.

An answer from the cache gets the client's id, the name as the client spelled it, and the client's EDNS. Its TTLs are what's left of them, less the seconds it was kept, so clients don't keep it longer than the upstream server said. An answer is dropped when its time is up, so a TTL served is always at least 1. One too big for the client's UDP size is truncated, as any answer.

The same name and type asked with the DO or CD bit is a different answer, kept separately. Beyond `cache_size`, the answer asked longest ago makes room.

Local names are never cached: a task's name, a record or a reverse name comes from memory, and follows discovery at once. For a local CNAME to an outside name, the CNAME is always current, and its target's answer comes from the cache as any forwarded one.

Each resolver has its own cache, in memory, empty at the start. Upstream answers are trusted as they arrive, as they were before the cache existed: it adds no validation.

## The rules

The configuration is checked at the start. A mistake stops it, and says where it is.

| The mistake | The error |
|---|---|
| A resolver without `listen` | `resolvers.lan.listen is missing: give where the resolver answers. That's the clients' network, as 192.168.1.0/24, for this machine's address in it, or the address itself. Without a port, 53` |
| A resolver without `upstream` | `resolvers.lan.upstream is missing: give one or more servers to ask about the names that aren't the resolver's own, as 192.168.1.1 or 1.1.1.1:53. Without them, it answers no other name` |
| An upstream by host name, without `bootstrap` | `resolvers.lan.upstream: "dns.google" is a host name, and there's no bootstrap to look it up. Add bootstrap, servers used for that lookup only, as bootstrap: 9.9.9.9. The system's resolver isn't used, as it may be this one` |
| An encrypted upstream at a host name, without `bootstrap` | `resolvers.lan.upstream: "tls://dns.example.net" is at a host name, and there's no bootstrap to look it up. Add bootstrap, servers used for that lookup only, as bootstrap: 9.9.9.9. The system's resolver isn't used, as it may be this one` |
| A scheme that isn't `tls` or `https` | `resolvers.lan.upstream: "quic://dns.example.net": unknown scheme quic: use plain DNS, as 1.1.1.1 or dns.example.net; tls:// for DNS over TLS, as tls://1.1.1.1; or https:// for DNS over HTTPS, as https://dns.example.net/dns-query` |
| DNS over HTTPS without a path | `resolvers.lan.upstream: "https://dns.example.net": DNS over HTTPS needs a path, as https://dns.example.net/dns-query` |
| DNS over HTTPS with a query, a fragment or a user | `resolvers.lan.upstream: "https://dns.example.net/dns-query?dns=x": DNS over HTTPS takes a host, with or without a port, and a path: no user, query or fragment` |
| DNS over TLS with a path | `resolvers.lan.upstream: "tls://1.1.1.1/dns-query": DNS over TLS takes a host, with or without a port, and no path: paths are for https://` |
| DNS over TLS with a query, a fragment or a user | `resolvers.lan.upstream: "tls://1.1.1.1?x=1": DNS over TLS takes a host, with or without a port: no user, query or fragment` |
| An encrypted upstream at port 0, or past 65535 | `resolvers.lan.upstream: "tls://1.1.1.1:0": the port 0 is out of range: ports go from 1 to 65535` |
| An encrypted upstream whose host is neither an address nor a host name | `resolvers.lan.upstream: "tls://:853": the host must be an address or a host name, with or without a port, as tls://1.1.1.1, tls://[2606:4700:4700::1111]:853 or tls://dns.example.net` |
| A `bootstrap` with no upstream by host name | `resolvers.lan.bootstrap only looks up upstream servers given by host name, and every upstream here is an address: leave it out` |
| A `bootstrap` server by host name | `resolvers.lan.bootstrap: "dns.quad9.net" is not an address, with or without a port, as 192.168.1.1, 1.1.1.1:53 or [2001:db8::1]:53` |
| A credential whose `resolver` is no resolver | `credentials.home.settings.resolver: there's no resolver wan: the resolvers are lan` |
| A credential without `resolver`, with two resolvers | `credentials.home.settings.resolver is missing: say which of lab, lan answers the zone` |
| A credential, with no resolver at all | `credentials.home: the resolver provider is a zone that one of the resolvers answers, and there are none: add one under resolvers, with its listen and upstream` |
| Two credentials of one zone on one resolver | `credentials home and office are both the zone home.arpa of resolver lan: a zone can belong to only one credential` |
| Two resolvers with one entry | `resolvers lab and lan both listen on 192.168.1.0/24 port 53: an address and port can belong to only one resolver` |
| Two resolvers on one address and port, spelled two ways | `resolvers lab and lan both listen on 192.168.1.2:53: lab as 192.168.1.0/24, lan as 192.168.1.2: an address and port can belong to only one resolver` |
| A zone's record of a name outside it | `credentials.home.settings.records: "printer.example.com. A 192.168.1.20": printer.example.com. isn't in the zone home.arpa: a zone's records must be for its names, relative to it or absolute within it` |
| A resolver's record without its trailing dot | `resolvers.lan.records: "www.example.com CNAME nas.home.arpa.": the name www.example.com must be absolute, ending in a dot, as www.example.com.: these records belong to no zone` |
| A resolver's record of a name of its zone | `resolvers.lan.records: "tv.home.arpa. A 192.168.1.30": tv.home.arpa. is in the zone home.arpa, of credential home: give it in that credential's records` |
| A record that doesn't read | `credentials.home.settings.records: "printer A 192.168.1.300": bad A A: "192.168.1.300"`, the line quoted, and what the parser says |
| A CNAME beside other records of its name | `credentials.home.settings.records: files.home.arpa. has a CNAME and other records: a name with a CNAME can't have others, since its data is the target's` |
| A record of a name a task publishes | `credentials.home.settings.records: "nas TXT \"x\"": nas.home.arpa. is published by task nas, which gives its addresses: records are for other names` |
| CNAMEs in a loop | `resolvers.lan: the CNAMEs a.home.arpa. -> b.home.arpa. -> a.home.arpa. are a loop` |

Two resolvers with two spellings of the same address and port are caught once the entries are resolved as the machine has them, at the start, before either one listens. That covers a network and the machine's address in it, a host name and the address it resolves to, a port alone (every address) and any address at that port, and `0.0.0.0` and any IPv4 address. The error names both resolvers, the address, and each one's entry as written; for two ports alone, `every address, port 53`. An address taken by another program, or another instance, fails when it tries to listen: `address already in use`.

## At start and stop

The resolvers start before discovery, with the rest. If one can't listen on one of its addresses, the start stops, as for the web server, and nothing of it is left listening.

They stop with the rest, at `SIGINT` or `SIGTERM`. No new query is taken, and those being answered get the time the program gives its stop, 30 seconds, the same as the updates running, with no time of their own. An upstream server has 2 seconds, so they finish well before. A query still waiting upstream when the time is up is given up, and the connections kept to encrypted upstream servers are closed.

The [web report](installation.md#the-web-report) shows each resolver: where it listens, whom it answers, how many queries of each kind it answered, and how many answers its cache holds.

- **`/status.json`** has them under `resolvers`, with `upstream_addresses`, the addresses the bootstrap servers found for each upstream given by host name, and the cache's `cache_entries` of `cache_size`.
- **`/metrics`** has `ipv6ddns_resolver_queries_total` by `kind` (`local`, `nodata`, `forwarded`, `cached`, `refused` and `servfail`), `ipv6ddns_resolver_cache_entries`, `ipv6ddns_resolver_upstream_failures_total` by `upstream` (an encrypted one as written), and `ipv6ddns_resolver_serving`. A query answered from the cache is `cached`, one an upstream server answered is `forwarded`, and a local name whose CNAME leads outside is `local` either way.
- **`/healthz`** fails, with 503, while a resolver isn't serving.

## Port 53

A port under 1024 needs root, or the `CAP_NET_BIND_SERVICE` capability. `sudo setcap 'cap_net_raw,cap_net_bind_service+ep' $(command -v ipv6ddns)` gives a binary run by another user both, along with what discovery needs.

In Docker, the container runs as root, and Docker grants `NET_BIND_SERVICE` by default, as `NET_RAW`. A runtime, or a Kubernetes `securityContext`, that drops capabilities must keep it. The image needs nothing more. On the host's network, the resolver listens on the host's addresses.

The Home Assistant add-on runs as root on the host's network, with Docker's capabilities and `NET_RAW`, so port 53 is open to it with no change to the add-on. Home Assistant's own DNS is on its internal network, not on the host's LAN address, which is the one to give.

Another DNS server on the same machine holds port 53 on its addresses:

- **systemd-resolved**, on most Linux desktops and many servers, listens only on `127.0.0.53:53` and `127.0.0.54:53`. A resolver that listens on the LAN address, as `192.168.1.0/24`, starts beside it. One on a port alone, every address, can't.
- **dnsmasq, Pi-hole, AdGuard Home**, or a router's own DNS on the same machine take every address, and the resolver can't start: `address already in use`.

## Several resolvers

Run two or more instances of ipv6ddns on different machines of the network, with the same resolver configuration, and give the clients all of them as DNS servers: DHCP's option 6, and for IPv6 the RDNSS of the router's advertisements, or DHCPv6. Each one discovers the same hosts and has the same zones and records, so they give the same answers, as two instances that keep [one name](installation.md#several-instances) agree on its addresses. When one is down, the clients ask the other.

The one difference: right after a host shows up, changes its address or leaves, the instances can differ for a few seconds, until each has discovered it. And an address that's gone stays on each for its own lifetime. A client may ask either one meanwhile.

## Security

- **Allow:** a resolver only answers the clients in `allow`, by default the networks it listens on. A resolver that answers anyone, on an address the internet reaches, is an open resolver. It relays any query upstream, and its answers, larger than the queries, can be aimed at a victim whose address the queries fake: an amplification attack. Don't widen `allow` to everyone, and don't listen on a public address. On a router, a port alone is one.
- **DNSSEC:** local answers aren't signed. A name of a publicly signed zone given another answer here, as `www.example.com` of a signed `example.com`, fails on a client that validates DNSSEC itself. Put such names in a zone that isn't signed, as `home.arpa`, or one you don't sign. Forwarded answers are relayed as they are, with their signatures, when the client's DO bit asks for them, and are cached apart from those asked without it.
- **Upstream:** over plain DNS, the names asked and the answers cross the network unencrypted, and anyone on the path can read the questions and change the answers. An [encrypted upstream](#encrypted-upstream-servers) closes that path up to the server, which still sees every name. The clients' own queries to the resolver are plain DNS, on the LAN.
- **Cache:** an upstream answer is served to every client for its TTL, a wrong one too, as with any caching resolver. Nothing is kept past a day, or past a restart. `cache_size: 0` asks every time.
