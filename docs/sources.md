# Sources

A source gives addresses that have no MAC, which discovery therefore can't find. Examples are the network's public IPv4, or an address that a script knows. A task gets the addresses of the sources it names in its `sources`, in addition to the addresses its [filters](filtering.md) choose. The keys are in the [reference](reference/configuration.md#sources).

## The public IPv4

Behind IPv4 NAT, a server has a private address. The internet reaches the server at the router's public address, through a port forward. So the server's A record must be the network's public IPv4. A `dns` source finds that address:

```yaml
sources:
  wan:
    type: dns
tasks:
  web:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
        ip:
          type:             # the server's own IPv6, for the AAAA record
            - global
    sources:                # and the public IPv4, for the A record
      - wan
    endpoints:
      cloudflare:
        - www
credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: ${CLOUDFLARE_TOKEN}
      zone: example.com
      ttl: 1h
      proxied: false
```

## Types

| Type | Gives |
|---|---|
| `dns` | The network's public address for each `family`, as public resolvers see it. It asks OpenDNS for `myip.opendns.com`, or Google for `o-o.myaddr.l.google.com` if OpenDNS fails. Each query goes out over its own family, so it gets that family's public address |
| `http` | The same public address, from echo services over HTTPS. It asks ipify, icanhazip and ident.me in turn, or the `urls` you give, which must answer with the address alone |
| `command` | The addresses that a `command`, run with its `args`, prints one per line. The command runs in the configuration's directory |
| `static` | The `addresses` you list. Use it for an address that doesn't change, or that discovery can't reach |
| `homeassistant` | The addresses in the state of a Home Assistant `entity`, or of its `attribute`: see the [Home Assistant integration](home-assistant-integration.md#an-entitys-addresses) |
| `push` | The addresses your router sends, as it would to a DynDNS service: see [a router's updates](#a-routers-updates). Or those a host sends as dynamic updates, signed with a key: see [a key's updates](#a-keys-updates) |

A `dns` or `http` source asks its services in order until one answers. Each service gets its share of the run's time. So a service that hangs doesn't stop the next one from being asked, and one family doesn't hold up the other.

A `dns` source asks the public resolvers directly, over UDP port 53. Some networks redirect all outgoing DNS to a resolver of their own, for example with a router rule that forces DNS through Pi-hole or AdGuard. Some ISPs do the same. That resolver then asks on the source's behalf, and the answer can be the resolver's address instead of the network's. On such a network, use `type: http`. ipv6ddns refuses the answers it can tell were relayed, but it can't always tell.

An `http` source goes through the `HTTPS_PROXY` proxy when that variable is set. The address it finds is then the one the proxy goes out from.

A source's addresses are published as given. Discovery refuses loopback, unspecified and multicast addresses, but a source doesn't: such an address from a command, a list or an entity is published.

For `dns` and `http`, `family` is `[4]` by default. `[4, 6]` also finds the public IPv6, for a network whose hosts all go out through one address.

## Runs and lifetimes

A source runs at start, and then every `interval`. A `homeassistant` source also runs as soon as its entity changes.

A run may take up to the interval minus a second, and a minute at most. A command that is still running then is killed, along with anything it started, and the run fails.

Each run ends in one of these ways:

| A run | The source's addresses | The log |
|---|---|---|
| **Works** | The source has the addresses the run gives. An address it no longer gives goes at once, such as the public address from before the ISP changed it. If the run gives none, the source has none, and a name with no other address loses its record | — |
| **Fails** | Each address is kept for its `lifetime` after the last run that gave it. So a service that is down for a while doesn't take the record away | An error, each run |
| **Fails in part**, such as one `family` of two, or one line of a command's output that isn't an address | The addresses the run gives are added, and the others are kept for their `lifetime`. A name can have both the old address and the new one until the old one expires | An error, each run |
| **Waits**, `homeassistant` only | The addresses are kept for their `lifetime`, as after a failure, while Home Assistant restarts | A line when the wait starts and when it ends, and a warning if the wait outlasts the lifetime |

The defaults of `interval` and `lifetime` are in the [reference](reference/configuration.md#sources). A static source never expires.

A run that gives no address means different things for different sources:

| Source | Gives no address when | Which counts as |
|---|---|---|
| `command` | The command exits 0 and prints nothing, or only blank lines | No addresses: the old ones go at once |
| `homeassistant` | The state is empty, such as a cleared `input_text` | No addresses: the old ones go at once |
| | The state is `unknown` or `unavailable`, an attribute is `None`, which means it has no value, or Home Assistant isn't connected | A wait |
| `http`, `dns` | The service doesn't answer with an address | A failure. A network always has a public address, so a missing answer is the service's fault |

A static source always gives its `addresses`. A static source without any is refused when the configuration is read.

A command that can't tell what the addresses are, for example because the service it asks is down, should exit non-zero. That's a failure, which keeps the addresses. Printing nothing means there are none.

`/status.json` shows each source's runs and failures, and the log shows its errors.

## A router's updates

A router's dynamic DNS can send its public addresses to ipv6ddns, as it would to a DynDNS service, as soon as they change. A `push` source takes them, through the [web server](installation.md#the-web-report), at `/nic/update`, in the dyndns2 protocol that most routers speak:

```yaml
listeners:
  web:
    listen:
      - http://192.168.1.2:8053 # the router must reach it

webservers:
  main:
    listeners:
      - web

sources:
  wan:
    type: push
    password: ${file:wan_push_password}

tasks:
  web:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
        ip:
          type:
            - global
    sources:
      - wan
    endpoints:
      cloudflare:
        - www

credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: ${file:cloudflare_token}
      zone: example.com
      ttl: 1h
      proxied: false
```

On the router, the hostname is the source's name, `wan`, and the password the source's:

| Router | Where | What |
|---|---|---|
| UniFi | *Settings → Internet → Dynamic DNS*, service *custom* | Server `192.168.1.2:8053/nic/update?hostname=%h&myip=%i`, Hostname `wan`, Username anything, Password the source's |
| Fritz!Box | *Internet → Permit Access → DynDNS*, provider *user-defined* | Update URL `http://192.168.1.2:8053/nic/update?hostname=<domain>&myip=<ipaddr>&myipv6=<ip6addr>&ip6lanprefix=<ip6lanprefix>&password=<pass>`, Domain name `wan`, Username anything, Password the source's |
| OPNsense | *Services → Dynamic DNS*, service *Custom*, protocol *DynDNS 2* | Server `192.168.1.2:8053`, Hostname `wan`, Username anything, Password the source's, without SSL |
| pfSense | *Services → Dynamic DNS*, type *Custom* | Update URL `http://192.168.1.2:8053/nic/update?hostname=wan&myip=%IP%`, Username anything, Password the source's |
| OpenWrt | ddns-scripts, a custom update URL | `http://[USERNAME]:[PASSWORD]@192.168.1.2:8053/nic/update?hostname=[DOMAIN]&myip=[IP]` |
| ddclient | `protocol=dyndns2` | `server=192.168.1.2:8053`, `ssl=no`, the hostname `wan` |

- **Each update replaces the addresses of the families it has.** An IPv4 address replaces the IPv4 one, and the IPv6 address stays: routers that send each family apart, as OPNsense, pfSense and OpenWrt do, don't take one away with the other. `myip` takes one address or two, separated by a comma, as ddclient sends them; `myipv6`, the IPv6 one apart, and an empty value is no address.
- **Without `myip`,** the address the update came from, when it is public, as from a router on the internet. From the LAN, an update without `myip` is refused.
- **The password** is the HTTP basic one, or `password` in the URL, for the routers that write it there. The username is not checked. A refused password waits a second for its answer.
- **The answer** is dyndns2's: `good` and the addresses, or `nochg` when they didn't change, with HTTP 200; and on an error, `badauth` with 401, `nohost` with 404 for a hostname that is no push source, or `911` with 400 for an update that has no address it can take. Some routers read the status alone, so an error never comes with 200.
- **The addresses stay until the next update**, however far: routers send when the address changes, and some only every few weeks otherwise. With `lifetime`, they go if no update comes within it.
- **A restart keeps them.** They are written to `state_file`, by default `push-<source>.json` in the configuration's folder.

### The prefix of the LAN

A Fritz!Box also sends the IPv6 prefix of its LAN, as `ip6lanprefix` in the URL above, with its length, or a /64 without one. When the ISP changes it, the devices keep their addresses of the prefix before for a while, and discovery keeps them for their lifetime, an hour by default: so a name would have the old address and the new one together. A filter with `ip.prefix_source` takes only the IPv6 addresses in the prefix the source's router sent last, so the old ones leave the name as soon as the router sends the new prefix:

```yaml
# Added to the configuration above: the server's addresses of the LAN's prefix alone.
tasks:
  web:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
        ip:
          type:
            - global
          prefix_source: wan
```

- IPv4 addresses pass the rule, as does every address until the router has sent a prefix.
- A unique local address, `fd00::/8`, is in no prefix the ISP gives: a filter with the rule leaves it out. Give it a filter set of its own, if a name is to have it.
- The prefix lasts the source's `lifetime` from when the router sent it, as the addresses do, though later updates send none: past it, the rule lets every address pass until the router sends one again. It is kept in the source's file, so a restart keeps it, and shown in `/status.json`.

The web server has no other authentication, so give it an address of the LAN, not one the internet reaches. UniFi's dynamic DNS sends IPv4 alone; the IPv6 addresses of the devices come from discovery anyway.

## A key's updates

A host can send its own addresses as RFC 2136 dynamic updates, signed with a TSIG key, to a [resolver](resolver.md#dynamic-updates) of ipv6ddns: a VPS whose address changes, with `nsupdate` from cron, or a router's RFC 2136 client, as pfSense's. A key's permission of `addresses` makes them a push source's:

```yaml
sources:
  vps:
    type: push

listeners:
  home:
    listen:
      - dns://192.168.1.2

resolvers:
  home:
    listeners:
      - home
    upstream:
      - 1.1.1.1
    updates:
      keys:
        vps:
          secret: ${file:tsig_vps}
          permissions:
            - addresses:
                source: vps
                zone: example.com

tasks:
  vps:
    sources:
      - vps
    endpoints:
      cloudflare:
        - vps

credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: ${file:cloudflare_token}
      zone: example.com
      ttl: 1h
      proxied: false
```

On the VPS, as often as its address may change:

```
nsupdate -k /etc/tsig_vps.key <<EOF
server 192.168.1.2
update delete vps.example.com A
update add vps.example.com 300 A 198.51.100.42
update delete vps.example.com AAAA
update add vps.example.com 300 AAAA 2001:db8:2::42
send
EOF
```

- **The name the client updates** is the source's name in the zone, `vps.example.com`, unless the permission gives another `name`. It only says what the update is of: the names published are the tasks', as above, where the task gives it the same name.
- **An update says exactly what changes**: an address added, one removed, or all of a family removed. Unlike dyndns2, sending IPv4 leaves the IPv6 addresses as they are, and removing them takes `update delete vps.example.com AAAA`.
- **Without a `password`,** the source takes the key's updates alone, and refuses every request at `/nic/update`. It needs no web server then. With one, it takes both.
- **The addresses stay until the next update**, and a restart keeps them, as a router's. The TTL sent is ignored: the endpoint's credential sets its own.
- **Only A and AAAA records of that name**: an update of anything else is refused, unless the key has a permission of it.

## A script of yours

For anything else, a command source runs your script:

```yaml
sources:
  from-the-router:
    type: command
    command: ./wan_address.sh
    interval: 1m
    lifetime: 5m
```

What the script must do:

- **With addresses to give:** print them, one per line, and exit 0.
- **With none to give:** print nothing and exit 0. The addresses go.
- **When it can't tell**, for example because the service it asks doesn't answer: exit non-zero. The addresses stay for their `lifetime`. With `set -euo pipefail`, a failing `curl` does that for you.

A line that isn't an address is an error. One example is the `null` that `jq` prints for a missing field. Use `jq -e`, which exits non-zero there instead.

The image has the [tools](installation.md#with-docker-compose) such scripts usually need.
