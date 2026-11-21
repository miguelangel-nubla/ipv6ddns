# The resolver

ipv6ddns can be a DNS server itself, for the clients of a network: a resolver answers the zones of its `resolver` credentials, with the addresses the tasks give their names as soon as discovery finds them, and records written for them, and asks its upstream servers, as the router or a public resolver, everything else. The clients are given its address as their DNS server, by DHCP or by the router's advertisements, and a name of the LAN, as `nas.home.arpa`, follows its host wherever its addresses move, with no DNS server of the network to update.

Nothing is sent to a provider: an update of the zone is in memory, at once, and never fails.

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

The keys are in the reference: [`resolvers`](reference/configuration.md#resolvers), and [the provider's settings](reference/providers.md#resolver).

## A resolver

- **`listen`**, required, is where it answers, over UDP and TCP, as [`webserver.listen`](installation.md#the-web-report) takes it: a network, as `192.168.1.0/24`, for each address of the machine in it; an address, as `192.168.1.2` or `[fd00::2]:5353`; a host name; or a port alone, for every address of the machine. Without a port, 53. A port alone, on a router, is its public address too: give the network of the clients instead.
- **`allow`** is the networks, or addresses, of the clients it answers. A query from any other is `REFUSED`. By default, the networks of the machine's addresses it listens on: `192.168.1.0/24` above, as the machine's interface has it; with a port alone, every network of the machine.
- **`upstream`**, required, one or more, is the servers it asks what isn't its own: addresses or host names, with a port or not, as `192.168.1.1`, `1.1.1.1:53`, `[2606:4700:4700::1111]` or `dns.example.net`, over plain DNS; or, [encrypted](#encrypted-upstream-servers), `tls://` for DNS over TLS, as `tls://1.1.1.1`, and `https://` for DNS over HTTPS, as `https://dns.example.net/dns-query`.
- **`bootstrap`**, with an upstream given by host name, plain or encrypted, and only then, is the servers that find its addresses, and are asked nothing else: addresses, with a port or not, over plain DNS. Not the system's resolver, which may be this very one, asking itself. The addresses found, IPv4 and IPv6, are asked in turn as one upstream server; they are kept for as long as the answer says, a minute at least and an hour at most, and while the bootstrap servers don't answer, asked again every 10 seconds then. An upstream they never found is passed over, as one that is down.

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
- **`records`** are records of names of none of its zones, as a name of a public domain that the LAN reaches at a local address. Each name is absolute, with its trailing dot, its targets too.
- **`cache_size`** is how many answers of the upstream servers it keeps, in [its cache](#the-cache): `10000` by default, and `0` for none.

## Encrypted upstream servers

An upstream server can be asked over an encrypted connection, so that the network between, as the provider's, doesn't read the names asked, nor change the answers:

- **`tls://host[:port]`** is DNS over TLS, of RFC 7858: port 853, unless another is given. Nothing follows the host: a path is of `https://`.
- **`https://host[:port]/path`** is DNS over HTTPS, of RFC 8484: port 443, unless another is given, and the path the server answers at, which is to be given, `/dns-query` for most. Each query is a `POST` of `application/dns-message`, over HTTP/2 when the server has it. A redirect isn't followed.

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

The host is a host name, which `bootstrap` finds as it does that of a plain upstream, and never the system's resolver; or an address. The server's certificate is verified, against the certificate authorities of the system, for the host as given: for the host name, which is also the name the connection asks the server for, its SNI; and with an address, the certificate must hold that address, as that of `1.1.1.1` does, and few others do. No option turns the verification off: a server whose certificate doesn't verify is passed over, as one that is down, and counts in `ipv6ddns_resolver_upstream_failures_total`.

The connections are kept, and used again:

- To a server of DNS over TLS, a connection carries one query at a time, and is kept open for the next for 30 seconds: queries at once each have their own, as many as there are, and each is closed after 30 seconds without a query. A connection that the server closed meanwhile is replaced, and the query asked again on the new one.
- To a server of DNS over HTTPS, one client, whose connections HTTP/2 shares among the queries at once, each closed after 30 seconds without one. It connects to the addresses that `bootstrap` found, or to the address given, and to nothing else: no proxy of the environment either.

The queries that go encrypted are padded, to a multiple of 128 bytes, as RFC 8467 recommends: their size tells less of the name asked. The rest is as for any upstream: 2 seconds each, the next when one fails, `SERVFAIL` when none answers. And an encrypted upstream is named, in the status and the metrics, as written.

The certificate authorities are the system's. On Linux, Go reads them from the usual places of the distributions, and the environment variables `SSL_CERT_FILE`, a file of certificates in PEM, and `SSL_CERT_DIR`, directories of them, name others in their place: for a server whose certificate is of an authority of your own. The Docker image has the authorities of Alpine's `ca-certificates`; another image is to have them, or no certificate verifies: `x509: certificate signed by unknown authority`.

## A zone

A credential of the provider `resolver` is a zone that a resolver answers: `zone`, and `resolver`, the resolver's name, which can be left out when there is one. Its names are those of the tasks' endpoints, as for any provider: `nas` is `nas.home.arpa`, `""` is `home.arpa` itself, `"*.nas"` a wildcard. Its `records` are records of the zone's other names, relative to it, or absolute within it, as `printer.home.arpa.`.

The addresses of a name have the zone's `ttl`, by default `1m`, and so do its records that give none. The credential's [`debounce`](configuration.md#its-parts) is none by default, for this provider: a change is answered at once. A zone with no task serves its records.

Two resolvers can each have a zone of the same name, through two credentials: the same name then has another answer on each network, a split horizon, as `nas.home.arpa` with the addresses of the LAN on one and those of a VPN on the other.

## Records

Each record is an entry, written as in a zone file: a name, a TTL or not, the class `IN` or not, a type, and its data.

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

Several records of a name and a type are answered together, as the two addresses of a name. Any type is taken, but an SOA, which the resolver makes, and those of a message, as OPT.

## How a query is answered

In order:

1. A client outside `allow` is refused: `REFUSED`, and nothing is asked upstream.
2. A name of the resolver's `records` is answered from them.
3. A name of a zone, that of the deepest zone that holds it, the one of the most labels, as `printer.lab.home.arpa` of `lab.home.arpa` before `home.arpa`, while `printer.home.arpa` is of `home.arpa`, is answered when a task publishes it or a record has it: the task's current addresses, as A and AAAA, or the records of its type. Answers of a zone are authoritative, `AA`.
   - Of another type, or of a task's name with no address yet, or no more, the answer is that there is none: `NOERROR`, empty, with an SOA of the zone, which the resolver makes, whose 10 seconds are how long a client keeps it. A host that shows has its name a moment after.
   - A wildcard, `*.dev`, answers any name under `dev` that has nothing of its own, and that has no name in between with something: `a.dev` and `a.b.dev`, but not `a.b.dev` when `b.dev`, or a name under it, has records. The answer has the name asked.
4. The reverse of an address, a `PTR` query of a name of `in-addr.arpa` or `ip6.arpa`, is answered with the names of steps 2 and 3 that have that address, when one does: see [reverse names](#reverse-names).
5. Anything else, a name that a zone doesn't have as well as one of no zone, is answered from [the cache](#the-cache) when the answer is there. Or it is forwarded to the upstream servers in order, each given 2 seconds, and, over plain DNS, over TCP when its answer over UDP doesn't fit; the first answer, whatever its code, is relayed as it is, with the client's id, and the client's EDNS, its size and its DO bit, went up with the query. None answering is `SERVFAIL`.

A name a zone doesn't have isn't `NXDOMAIN`, but upstream's answer: a zone can be a part of a domain that exists elsewhere, as `home.example.com` of a public `example.com`.

A CNAME is followed among the local names, the tasks', the zones' records and the resolver's, up to 8 of them, and every step is in the answer; a target that isn't local is asked upstream, or taken from the cache, and its answer appended, as the stub resolvers of the clients follow no CNAME themselves. A query of the type CNAME has the CNAME alone.

An answer that doesn't fit in the UDP size of the client, 512 bytes or what its EDNS says, has `TC` set, and the client asks again over TCP.

## Reverse names

The address of a host has its name back: `dig -x 192.168.1.20`, a `PTR` query of `20.1.168.192.in-addr.arpa`, or of the name under `ip6.arpa` for an IPv6 address, is answered with every name the resolver answers with that address:

- the names of the tasks, of its zones, that have the address now: when discovery gives a name another address, the reverse of the one it had is no longer answered, and that of the new one is, at once;
- the names of the `A` and `AAAA` records, of its zones and of its own `records`, that give it.

They come sorted, each once, in an authoritative answer, `AA`, with the zone's `ttl`, or the record's own when it gives one; the shortest, when the names differ in it. A wildcard is no host, and has no reverse. A `PTR` record written, in `records`, for the reverse name itself, is answered as any record, in the place of these.

The reverse of any other address is forwarded, as any other name: the router's names for its DHCP clients keep answering. And a resolver gives the reverse of the names it answers itself alone: of two with a zone of one name, a split horizon, each tells an address's name as its own zone has it.

## The cache

The answers of the upstream servers are kept, `cache_size` of them, `10000` by default, and a name asked again within its time is answered from them, without asking: `cache_size: 0` keeps none, and asks every time.

- An answer with records is kept for the shortest of their TTLs, a day at most.
- That a name doesn't exist, `NXDOMAIN`, or has no data of a type, is kept as RFC 2308 has it, for the minimum of the zone's SOA that comes with it, or that SOA's TTL, the lower: an hour at most.
- Never kept: a failure, as `SERVFAIL` or `REFUSED`; a truncated answer; an answer of no data that has no SOA, which tells no time; and one whose time is 0.

An answer from the cache has the client's id, the name as the client spells it, and its EDNS; its TTLs are what is left of them, less the seconds it was kept, so that the clients keep it no longer than the upstream server said: an answer is dropped when its time is over, so a TTL that is served is 1 at least. One too big for the client's UDP size is truncated, as any. The same name and type asked with the DO bit, or the CD bit, is another answer, kept beside. Beyond `cache_size`, the answer asked the longest ago makes room.

The local names are never kept: a task's name, a record, a reverse name come from memory, and follow discovery at once. Of a CNAME to a name outside, the local CNAME is always fresh, and its target's answer comes from the cache as any forwarded one.

The cache is in memory, each resolver's own, and empty at the start. The upstream servers' answers are trusted as they come, as they were before it: it adds no validation.

## The rules

They are checked at the start: a mistake stops it, saying where it is.

| The mistake | The error |
|---|---|
| A resolver without `listen` | `resolvers.lan.listen: where the resolver answers is to be given: the network of its clients, as 192.168.1.0/24, for the machine's address in it, or that address; without a port, 53` |
| A resolver without `upstream` | `resolvers.lan.upstream: the servers the resolver asks what isn't its own are to be given, one or more, as 192.168.1.1 or 1.1.1.1:53: without them, it would answer no other name` |
| An upstream by host name, without `bootstrap` | `resolvers.lan.upstream: "dns.google" is a host name: its addresses are asked of bootstrap, the servers for that alone, which is to be given, as bootstrap: 9.9.9.9; not the system's resolver, which can be this one` |
| An encrypted upstream at a host name, without `bootstrap` | `resolvers.lan.upstream: "tls://dns.example.net" is at a host name: its addresses are asked of bootstrap, the servers for that alone, which is to be given, as bootstrap: 9.9.9.9; not the system's resolver, which can be this one` |
| A scheme that isn't `tls` or `https` | `resolvers.lan.upstream: "quic://dns.example.net": the scheme quic: an upstream is plain DNS, as 1.1.1.1 or dns.example.net, tls:// for DNS over TLS, as tls://1.1.1.1, or https:// for DNS over HTTPS, as https://dns.example.net/dns-query` |
| DNS over HTTPS without a path | `resolvers.lan.upstream: "https://dns.example.net": DNS over HTTPS is asked at a path, which is to be given, as https://dns.example.net/dns-query` |
| DNS over HTTPS with a query, a fragment or a user | `resolvers.lan.upstream: "https://dns.example.net/dns-query?dns=x": DNS over HTTPS is a host, with a port or not, and a path: no user, query or fragment` |
| DNS over TLS with a path | `resolvers.lan.upstream: "tls://1.1.1.1/dns-query": DNS over TLS is a host, with a port or not: no path, which is of https://` |
| DNS over TLS with a query, a fragment or a user | `resolvers.lan.upstream: "tls://1.1.1.1?x=1": DNS over TLS is a host, with a port or not: no user, query or fragment` |
| An encrypted upstream at port 0, or past 65535 | `resolvers.lan.upstream: "tls://1.1.1.1:0": the port 0: a port is from 1 to 65535` |
| An encrypted upstream whose host is neither an address nor a host name | `resolvers.lan.upstream: "tls://:853": the host is an address or a host name, with a port or not, as tls://1.1.1.1, tls://[2606:4700:4700::1111]:853 or tls://dns.example.net` |
| A `bootstrap` with no upstream by host name | `resolvers.lan.bootstrap: the servers that find the upstream servers given by host name, and every upstream is an address: leave it out` |
| A `bootstrap` server by host name | `resolvers.lan.bootstrap: "dns.quad9.net": an address, with a port or not, as 192.168.1.1, 1.1.1.1:53 or [2001:db8::1]:53` |
| A credential whose `resolver` is no resolver | `credentials.home.settings.resolver: wan is no resolver: they are lan` |
| A credential without `resolver`, with two resolvers | `credentials.home.settings.resolver: which resolver answers the zone is to be said, of lab, lan` |
| A credential, with no resolver at all | `credentials.home: the provider resolver is a zone that a resolver answers, and there is none: add one to resolvers, with where it listens and the servers it asks` |
| Two credentials of one zone on one resolver | `credentials home and office: both are the zone home.arpa of resolver lan: a zone is one credential's` |
| Two resolvers with one entry | `resolvers lab and lan both listen on 192.168.1.0/24 port 53: an address and port is one resolver's` |
| Two resolvers on one address and port, spelled two ways | `resolvers lab and lan both listen on 192.168.1.2:53: lab as 192.168.1.0/24, lan as 192.168.1.2: an address and port is one resolver's` |
| A zone's record of a name outside it | `credentials.home.settings.records: "printer.example.com. A 192.168.1.20": printer.example.com. is not of the zone home.arpa: a zone's records are of its names, relative to it, or absolute within it` |
| A resolver's record without its trailing dot | `resolvers.lan.records: "www.example.com CNAME nas.home.arpa.": the name www.example.com is to be absolute, with its trailing dot, as www.example.com.: these records are of no zone` |
| A resolver's record of a name of its zone | `resolvers.lan.records: "tv.home.arpa. A 192.168.1.30": tv.home.arpa. is of the zone home.arpa, of credential home: give it there, in its records` |
| A record that doesn't read | `credentials.home.settings.records: "printer A 192.168.1.300": bad A A: "192.168.1.300"`, the line quoted, and what the parser says |
| A CNAME beside other records of its name | `credentials.home.settings.records: files.home.arpa. has a CNAME and other records: a CNAME is alone at its name, the other data is its target's` |
| A record of a name a task publishes | `credentials.home.settings.records: "nas TXT \"x\"": nas.home.arpa. is a name task nas publishes, which has its addresses: a record is of another name` |
| CNAMEs in a loop | `resolvers.lan: the CNAMEs a.home.arpa. -> b.home.arpa. -> a.home.arpa. are a loop` |

Two resolvers whose entries are two spellings of one address and port are told once the entries are read as the machine has them, at the start, before either listens: a network and the machine's address in it, a host name and the address it resolves to, a port alone, which is every address, and any address at that port, or `0.0.0.0` and any IPv4 address. The error names both resolvers, the address, and each one's entry as written; with two ports alone, `every address, port 53`. An address taken by another program, or another instance, fails as it listens: `address already in use`.

## At start and stop

The resolvers start with the rest, before discovery: one that can't listen on one of its addresses stops the start, as the web server does, and nothing of it is left listening. They stop with the rest, at `SIGINT` or `SIGTERM`: no new query is taken, and those being answered have the time the program gives its stop, 30 seconds, the same the updates running have, and none of their own. An upstream server has its 2 seconds, so they end well before; one still asked upstream when the time is over is given up, and the connections kept to the encrypted upstream servers are closed.

The [web report](installation.md#the-web-report) shows each resolver, where it listens, whom it answers, how many queries of each kind and how many answers its cache holds; `/status.json` has them under `resolvers`, with the addresses the bootstrap servers found for each upstream given by host name, `upstream_addresses`, and the cache's `cache_entries` of `cache_size`; `/metrics` has `ipv6ddns_resolver_queries_total`, by `kind`, `local`, `nodata`, `forwarded`, `cached`, `refused` and `servfail`, `ipv6ddns_resolver_cache_entries`, the answers in the cache, `ipv6ddns_resolver_upstream_failures_total`, by `upstream`, as written for an encrypted one, and `ipv6ddns_resolver_serving`. A query answered from the cache is `cached`, and `forwarded` one that an upstream server answered; a local name whose CNAME leads outside is `local` either way. `/healthz` fails, with 503, while a resolver isn't serving.

## Port 53

A port under 1024 needs root, or the `CAP_NET_BIND_SERVICE` capability: `sudo setcap 'cap_net_raw,cap_net_bind_service+ep' $(command -v ipv6ddns)` gives a binary run by another user both, with discovery's. In Docker the container runs as root, and Docker grants `NET_BIND_SERVICE` by default, as `NET_RAW`; a runtime, or a Kubernetes `securityContext`, that drops capabilities is to keep it. The image needs nothing more. On the host's network, the resolver listens on the host's addresses.

The Home Assistant add-on runs as root on the host's network, with Docker's capabilities and `NET_RAW`: port 53 is open to it, as far as is known, with no change to the add-on. Home Assistant's own DNS is on its internal network, not on the host's LAN address, which is the one to give.

Another DNS server on the machine holds port 53 on its addresses. systemd-resolved, on most Linux desktops and many servers, listens on `127.0.0.53:53` and `127.0.0.54:53` only, so a resolver that listens on the LAN address, as `192.168.1.0/24`, starts beside it; one on a port alone, every address, can't. dnsmasq, Pi-hole, AdGuard Home or a router's own DNS on the same machine take every address, and the resolver can't start: `address already in use`.

## Several resolvers

Run two or more instances of ipv6ddns, on different machines of the network, with the same resolver configuration, and give the clients all of them as their DNS servers: DHCP's option 6, and for IPv6 the RDNSS of the router's advertisements, or DHCPv6. Each discovers the same hosts, and has the same zones and records, so they give the same answers, as two instances that keep [one name](installation.md#several-instances) agree on its addresses; one down, the clients ask the other.

The one difference: right after a host shows, changes its address or leaves, the instances can differ for a few seconds, until each has discovered it, and an address that is gone stays on each for its own lifetime. A client can ask either meanwhile.

## Security

- **Allow**: a resolver answers the clients of `allow` alone, by default the networks it listens on. A resolver that answers anyone, on an address the internet reaches, is an open resolver: it relays any query upstream, and its answers, larger than the queries, can be sent to a victim whose address the queries forge, an amplification. Don't widen `allow` to everybody, and don't listen on a public address: a port alone, on a router, is one.
- **DNSSEC**: the local answers aren't signed. A name of a zone that is signed publicly, given another answer here, as `www.example.com` of a signed `example.com`, fails on a client that validates DNSSEC itself: give such names in a zone that isn't, as `home.arpa`, or one you don't sign. The forwarded answers are relayed as they are, signatures with them, when the client's DO bit asks for them, and are kept apart from those asked without it.
- **Upstream**: over plain DNS, the names asked and the answers cross the network in the clear, and whoever is on the path can read the ones and change the others; an [encrypted upstream](#encrypted-upstream-servers) closes that path, up to the server, which still reads every name. The clients' own queries to the resolver are plain DNS, on the LAN.
- **Cache**: an answer of an upstream server is served to every client for its TTL, a wrong one too, as with any caching resolver; nothing is kept past a day, nor past the stop. `cache_size: 0` asks every time.
