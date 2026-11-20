# The resolver

ipv6ddns can be a DNS server itself, for the clients of a network: a resolver answers the zones of its `resolver` credentials, with the addresses the tasks give their names as soon as discovery finds them, and records written for them, and asks its upstream servers, as the router or a public resolver, everything else. The clients are given its address as their DNS server, by DHCP or by the router's advertisements, and a name of the LAN, as `nas.home.arpa`, follows its host wherever its addresses move, with no DNS server of the network to update.

Nothing is sent to a provider: an update of the zone is in memory, at once, and never fails.

```yaml
resolvers:
  lan:                                    # a name: any number of resolvers
    listen: 192.168.1.0/24                # the machine's address in it, port 53
    allow: [192.168.1.0/24, fd00::/64]    # whom it answers: by default, the networks it listens on
    upstream: [192.168.1.1, 1.1.1.1]      # whom it asks the rest, in order
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
      home: [nas]                         # nas.home.arpa
```

The keys are in the reference: [`resolvers`](reference/configuration.md#resolvers), and [the provider's settings](reference/providers.md#resolver).

## A resolver

- **`listen`**, required, is where it answers, over UDP and TCP, as [`webserver.listen`](installation.md#the-web-report) takes it: a network, as `192.168.1.0/24`, for each address of the machine in it; an address, as `192.168.1.2` or `[fd00::2]:5353`; a host name; or a port alone, for every address of the machine. Without a port, 53. A port alone, on a router, is its public address too: give the network of the clients instead.
- **`allow`** is the networks, or addresses, of the clients it answers. A query from any other is `REFUSED`. By default, the networks of the machine's addresses it listens on: `192.168.1.0/24` above, as the machine's interface has it; with a port alone, every network of the machine.
- **`upstream`**, required, one or more, is the servers it asks what isn't its own: addresses, with a port or not, as `192.168.1.1`, `1.1.1.1:53` or `[2606:4700:4700::1111]`, over plain DNS. A host name isn't taken: it would need a resolver to be found.
- **`records`** are records of names of none of its zones, as a name of a public domain that the LAN reaches at a local address. Each name is absolute, with its trailing dot, its targets too.

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
3. A name of a zone, that of the zone with the longest suffix, as `printer.lab.home.arpa` of `lab.home.arpa` before `home.arpa`, is answered when a task publishes it or a record has it: the task's current addresses, as A and AAAA, or the records of its type. Answers of a zone are authoritative, `AA`.
   - Of another type, or of a task's name with no address yet, or no more, the answer is that there is none: `NOERROR`, empty, with an SOA of the zone, which the resolver makes, whose 10 seconds are how long a client keeps it. A host that shows has its name a moment after.
   - A wildcard, `*.dev`, answers any name under `dev` that has nothing of its own, and that has no name in between with something: `a.dev` and `a.b.dev`, but not `a.b.dev` when `b.dev`, or a name under it, has records. The answer has the name asked.
4. Anything else, a name that a zone doesn't have as well as one of no zone, is forwarded to the upstream servers in order, each given 2 seconds, and over TCP when its answer over UDP doesn't fit; the first answer, whatever its code, is relayed as it is, with the client's id, and the client's EDNS, its size and its DO bit, went up with the query. None answering is `SERVFAIL`. Nothing is cached: every query is asked again.

A name a zone doesn't have isn't `NXDOMAIN`, but upstream's answer: a zone can be a part of a domain that exists elsewhere, as `home.example.com` of a public `example.com`.

A CNAME is followed among the local names, the tasks', the zones' records and the resolver's, up to 8 of them, and every step is in the answer; a target that isn't local is asked upstream, and its answer appended, as the stub resolvers of the clients follow no CNAME themselves. A query of the type CNAME has the CNAME alone.

An answer that doesn't fit in the UDP size of the client, 512 bytes or what its EDNS says, has `TC` set, and the client asks again over TCP.

## The rules

They are checked at the start: a mistake stops it, saying where it is.

| The mistake | The error |
|---|---|
| A resolver without `listen` | `resolvers.lan.listen: where the resolver answers is to be given: the network of its clients, as 192.168.1.0/24, for the machine's address in it, or that address; without a port, 53` |
| A resolver without `upstream` | `resolvers.lan.upstream: the servers the resolver asks what isn't its own are to be given, one or more, as 192.168.1.1 or 1.1.1.1:53: without them, it would answer no other name` |
| An upstream that is a host name | `resolvers.lan.upstream: "dns.google": an address, with a port or not, as 192.168.1.1, 1.1.1.1:53 or [2001:db8::1]:53: a host name would need a resolver to be found` |
| A credential whose `resolver` is no resolver | `credentials.home.settings.resolver: wan is no resolver: they are lan` |
| A credential without `resolver`, with two resolvers | `credentials.home.settings.resolver: which resolver answers the zone is to be said, of lab, lan` |
| A credential, with no resolver at all | `credentials.home: the provider resolver is a zone that a resolver answers, and there is none: add one to resolvers, with where it listens and the servers it asks` |
| Two credentials of one zone on one resolver | `credentials home and office: both are the zone home.arpa of resolver lan: a zone is one credential's` |
| Two resolvers on one address and port | `resolvers lab and lan both listen on 192.168.1.0/24 port 53: an address and port is one resolver's` |
| A zone's record of a name outside it | `credentials.home.settings.records: "printer.example.com. A 192.168.1.20": printer.example.com. is not of the zone home.arpa: a zone's records are of its names, relative to it, or absolute within it` |
| A resolver's record without its trailing dot | `resolvers.lan.records: "www.example.com CNAME nas.home.arpa.": the name www.example.com is to be absolute, with its trailing dot, as www.example.com.: these records are of no zone` |
| A resolver's record of a name of its zone | `resolvers.lan.records: "tv.home.arpa. A 192.168.1.30": tv.home.arpa. is of the zone home.arpa, of credential home: give it there, in its records` |
| A record that doesn't read | `credentials.home.settings.records: "printer A 192.168.1.300": bad A A: "192.168.1.300"`, the line quoted, and what the parser says |
| A CNAME beside other records of its name | `credentials.home.settings.records: files.home.arpa. has a CNAME and other records: a CNAME is alone at its name, the other data is its target's` |
| A record of a name a task publishes | `credentials.home.settings.records: "nas TXT \"x\"": nas.home.arpa. is a name task nas publishes, which has its addresses: a record is of another name` |
| CNAMEs in a loop | `resolvers.lan: the CNAMEs a.home.arpa. -> b.home.arpa. -> a.home.arpa. are a loop` |

Two resolvers whose entries are two spellings of one address, as a network and the machine's address in it, aren't told apart until they listen: the second then fails to, and so does the start, with `address already in use`, as for any address taken, by another program or another instance.

## At start and stop

The resolvers start with the rest, before discovery: one that can't listen on one of its addresses stops the start, as the web server does, and nothing of it is left listening. They stop with the rest, at `SIGINT` or `SIGTERM`, the queries being answered first.

The [web report](installation.md#the-web-report) shows each resolver, where it listens, whom it answers and how many queries of each kind; `/status.json` has them under `resolvers`; `/metrics` has `ipv6ddns_resolver_queries_total`, by `kind`, `local`, `nodata`, `forwarded`, `refused` and `servfail`, `ipv6ddns_resolver_upstream_failures_total`, by `upstream`, and `ipv6ddns_resolver_serving`. `/healthz` fails, with 503, while a resolver isn't serving.

## Port 53

A port under 1024 needs root, or the `CAP_NET_BIND_SERVICE` capability: `sudo setcap 'cap_net_raw,cap_net_bind_service+ep' $(command -v ipv6ddns)` gives a binary run by another user both, with discovery's. In Docker the container runs as root, and Docker grants `NET_BIND_SERVICE` by default, as `NET_RAW`; a runtime, or a Kubernetes `securityContext`, that drops capabilities is to keep it. The image needs nothing more. On the host's network, the resolver listens on the host's addresses.

The Home Assistant add-on runs as root on the host's network, with Docker's capabilities and `NET_RAW`: port 53 is open to it, as far as is known, with no change to the add-on. Home Assistant's own DNS is on its internal network, not on the host's LAN address, which is the one to give.

Another DNS server on the machine holds port 53 on its addresses. systemd-resolved, on most Linux desktops and many servers, listens on `127.0.0.53:53` and `127.0.0.54:53` only, so a resolver that listens on the LAN address, as `192.168.1.0/24`, starts beside it; one on a port alone, every address, can't. dnsmasq, Pi-hole, AdGuard Home or a router's own DNS on the same machine take every address, and the resolver can't start: `address already in use`.

## Several resolvers

Run two or more instances of ipv6ddns, on different machines of the network, with the same resolver configuration, and give the clients all of them as their DNS servers: DHCP's option 6, and for IPv6 the RDNSS of the router's advertisements, or DHCPv6. Each discovers the same hosts, and has the same zones and records, so they give the same answers, as two instances that keep [one name](installation.md#several-instances) agree on its addresses; one down, the clients ask the other.

The one difference: right after a host shows, changes its address or leaves, the instances can differ for a few seconds, until each has discovered it, and an address that is gone stays on each for its own lifetime. A client can ask either meanwhile.

## Security

- **Allow**: a resolver answers the clients of `allow` alone, by default the networks it listens on. A resolver that answers anyone, on an address the internet reaches, is an open resolver: it relays any query upstream, and its answers, larger than the queries, can be sent to a victim whose address the queries forge, an amplification. Don't widen `allow` to everybody, and don't listen on a public address: a port alone, on a router, is one.
- **DNSSEC**: the local answers aren't signed. A name of a zone that is signed publicly, given another answer here, as `www.example.com` of a signed `example.com`, fails on a client that validates DNSSEC itself: give such names in a zone that isn't, as `home.arpa`, or one you don't sign. The forwarded answers are relayed as they are, signatures with them, when the client's DO bit asks for them.
- **No cache**: every query of a name not local goes upstream: the upstream servers, as the router, cache.
