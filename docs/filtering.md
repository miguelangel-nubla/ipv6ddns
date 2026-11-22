# Filtering system

A task's filters choose which of the addresses [discovery](discovery.md) finds go to the task's names. Every key is in the [reference](reference/configuration.md#task-filters).

## Core concepts

The filtering system is built around two logical levels:

1.  **Filter Sets (OR Logic)**: The top-level `filter` configuration is a **List** of sets. If an address matches **ANY** of the sets in the list, it is accepted.
2.  **Filter Rules (AND Logic)**: Within a single set, you define specific rules (e.g., match this IP type AND this MAC address). An address must match **ALL** rules defined in the set to be accepted by that set.

### Visual logic

```text
Address -> [ Set 1 ] --(Match?)--> ACCEPT
              OR
Address -> [ Set 2 ] --(Match?)--> ACCEPT
              OR
Address -> [ Set 3 ] --(Match?)--> ACCEPT
```

Inside a Set:

```text
Set 1:
  MAC Address == "..."  AND
  IP Type     == "Global"
```

## Configuration

The `filter` block is a list of objects. Each object represents a **Filter Set**.

### Structure

```yaml
filter:
  # Set 1: Match specific MAC
  - mac:
      address: "00:11:22:33:44:55"

  # Set 2: Match any Stable Global Dynamic IP
  - ip:
      type:
        - global
        - eui64
```

### Available keys

#### `filter.self`

*   **`self`** (Boolean): the addresses of the machine ipv6ddns runs on, instead of a MAC's, as a server's or a Home Assistant host's. There's no MAC to look up, and nothing changes when its network card does.
    *   They're the addresses of the interfaces discovery runs on, while the family listens. An interface without a MAC, as a PPP link or a tunnel, isn't included (see [interfaces](discovery.md#interfaces)): take its addresses from a [source](sources.md) instead, as a `command` source that reads the interface.
    *   An address the interface no longer has goes within a minute, not a lifetime later.
    *   Container bridges have this machine's addresses too: leave them out with `discovery.exclude_interfaces`.
    *   See the example [this machine](#6-this-machine-ipv6ddns-runs-on).

#### `filter.mac`

*   **`address`** (Single String): Exact match of the MAC address.
    *   Example: `00:11:22:33:44:55`. `00-11-22-33-44-55` and `0011.2233.4455` are the same MAC. Anything that isn't a MAC is a configuration error.
*   **`mask`** (List of Strings): Match against a mask. Useful for matching OUI (Vendor) or ranges. All provided masks must match.
    *   Format: `VALUE/MASK`, both whole MACs. An entry that isn't is a configuration error.
    *   Example: `00:11:22:00:00:00/ff:ff:ff:00:00:00` (Matches any device with 00:11:22 OUI)
*   **`type`** (List of Strings): Match protocol-defined MAC types. All types must match.
    *   Values: `global`, `local`, `unicast`, `multicast`. Write `!type` for "not of this type".

#### `filter.ip`

*   **`family`** (List of Integers): the address families, `4` and `6`. **Default: `[6]`.** That way, a filter that names a device's MAC doesn't also send its private IPv4 addresses to a public DNS once IPv4 discovery finds them. Give `[4]` or `[4, 6]` for IPv4.
    *   Example: `family` `4` with `type` `private`, for a device's `192.168.x.x` address in a local DNS.
*   **`prefix`** (Single String): CIDR subnet. The address must be contained within this subnet.
    *   Example: `2001:db8::/32`
*   **`type`** (List of Strings): Match semantic IP types. All types must match.
    *   Values:
        *   `global`: Global Unicast Address (Publicly routable): not private, link-local or carrier-grade NAT.
        *   `private`: RFC 1918 IPv4 (`10/8`, `172.16/12`, `192.168/16`), or IPv6 unique local.
        *   `ula`: Unique Local Address (`fc00::/7`).
        *   `cgnat`: Carrier-grade NAT IPv4 (`100.64.0.0/10`).
        *   `link_local`: Link-Local Address (`fe80::/10`, or `169.254.0.0/16`).
        *   `eui64`: IPv6, derived from MAC address (stable).
        *   `random`: IPv6, with an interface ID not derived from the MAC. That's a privacy address, or a stable address made another way, as most systems do now.
        *   `temporary`: an IPv6 privacy address of this machine, which its kernel marks as temporary. It changes every day or so. Only known on Linux, and only for the [`self`](#filterself) addresses.
    *   `!type` means "not of this type", as `!temporary`.
    *   **Common Use Case**: a `type` of `global` (Public IPs only).
*   **`mask`** (List of Strings): a bitwise match. In the bits that `MASK` sets, the address must equal `VALUE`. All masks given must match.
    *   Format: `VALUE/MASK`, both full addresses of the same family. `MASK` is an address, not a prefix length: `::1/64` is a configuration error, as is any entry that isn't two addresses. For a subnet, use `prefix`.
    *   It compares bits, not text, so how an address is written doesn't matter. `::5/::ffff:ffff:ffff:ffff` takes `2001:db8:1:1::5`, and leaves out `2001:db8:1:1:2:0:0:5`, whose interface ID is `2:0:0:5`.
    *   Examples:

        | Wanted | Mask |
        |---|---|
        | The interface ID `::5`, whatever the prefix | `::5/::ffff:ffff:ffff:ffff` |
        | The last 32 bits `dead:beef` | `::dead:beef/::ffff:ffff` |
        | The last group `5` | `::5/::ffff` |
        | Subnet `42` and interface ID `::5`, under any prefix the ISP delegates | `0:0:0:42::5/0:0:0:ffff:ffff:ffff:ffff:ffff` |
        | The IPv4 addresses ending in `.5` | `0.0.0.5/0.0.0.255` |
    *   A mask only matches addresses of its own family. With `family` `4` and `6`, an IPv6 mask leaves the IPv4 addresses out, so use one filter per family.

#### `filter.ip.seen`

Rules on how the address was seen. Discovery keeps a record of each way it saw an address, each with its own first and last time and its own lifetime. The address stays as long as any of its records does, and a rule only matches a record that is still current.

- **`seen`** is a list of rules, and the address must have a record matching each of them.
- **`not_seen`** is a list of rules, and the address must have no record matching any of them.

A rule is one of two kinds:

*   **A protocol, and how it saw the address:**
    *   `protocol`: one of the local discovery's protocols.
    *   `way`: how it saw it. Leave it out for any way.
        *   `announced`: the host said, unprompted, that the address is its own, or said something about itself from it.
        *   `answered`: the host replied to one of discovery's probes, from the address or for it.
        *   `heard`: the host used the address without discovery asking.
*   **`reported`**: something other than the host reported the address, from one of its tables.
    *   `by`: plugins, by name or by type, as `mikrotik`, or `kernel`, this machine's own. Leave it out for anyone.
    *   `from`: `neighbors`, a neighbor or ARP table; `leases`, DHCP leases; or `interfaces`, the addresses of this machine's interfaces. Leave it out for any table.
    *   A lease never finds an address on its own. It's attached to an address something else found at the lease's MAC, while the plugin reads the lease, and it keeps the address no longer than what found it. That's because a server keeps the lease of a host that left until the lease ends.
    *   `reported: {}` means by anyone, from any table.

Both kinds take `interfaces`, a list of local interfaces: the record must have been made on one of them. A plugin's reports aren't on any interface.

| `protocol` | `way` | Recorded when |
|---|---|---|
| `ndp` | `announced` | The host advertises an address unasked, as when it takes it |
| | `answered` | It answers a solicitation of the discovery's |
| | `heard` | It solicits from the address, or advertises another from it |
| `ping` | `answered` | It answers the multicast ping |
| `ssdp`, `wsd` | `answered` | It answers the search |
| `mdns` | `announced` | It announces the address as its own, in an address record of its name |
| | `heard` | It sends mDNS from the address |
| `arp` | `announced` | It sends a gratuitous ARP of the address |
| | `answered` | It answers an ARP request: the sweep's, or a solicitation's |
| | `heard` | It asks for another address from it |
| `dhcp` | `announced` | It asks its DHCP server for the address |
| | `heard` | It sends DHCPv6 from the address |
| `lldp` | `announced` | Its LLDP gives the address as its management address |
| `netbios`, `llmnr` | `answered` | It answers the question of its name |

A rule that can never match is an error at start, which says why:

*   A way a protocol never sees an address, as `ping` with `announced`. Or a protocol, table or reporter that doesn't exist: `by` must name a plugin of `discovery.plugins`, a plugin type, or `kernel`.
*   A `seen` rule for a protocol that is disabled under `discovery.protocols`: no address can have its records.
*   A `not_seen` rule that excludes every record a `seen` rule needs, as `seen` with `mdns` `announced` and `not_seen` with `mdns`: the filter could take no address.

Two things to keep in mind:

*   **A rule belongs to its filter.** A task's filters are alternatives, so an address one filter leaves out with its `not_seen` still goes to the task if another filter takes it. To keep something out of a task, give the `not_seen` to each of its filters.
*   **`not_seen` judges the records that exist now.** Say a host announces its address over mDNS a moment after another protocol found it. Until the announcement arrives, it matches `not_seen` with `mdns`, and its address goes to the task for that moment. `seen` is the other way round: an address only goes to the task once it has the record wanted.

None of these rules tells a stable address from a temporary one: only the host knows, and it tells nobody. See [after a start](discovery.md#after-a-start) for what a restart can't find straight away.

##### What the host itself showed

A router keeps a departed host's neighbor entry, and reports it until it ages out. An address the host itself answered for, or announced, is really there now:

```yaml
filter:
  - mac:
      address: 00:11:22:33:44:55
    ip:
      seen:
        - protocol: ndp
```

`ndp` sees every IPv6 address on the links local discovery runs on, in any way, and is on by default. A host on another network, which only a plugin reaches, has nothing but the plugin's report, so this filter leaves it out.

##### What the host announced over mDNS

A host's mDNS responder announces the addresses it means to be reached at, in the address records of its name:

```yaml
filter:
  - mac:
      address: 00:11:22:33:44:66
    ip:
      seen:
        - protocol: mdns
          way: announced
```

`mdns` is on by default. What gets announced is up to the host's responder: Apple's announces only its stable addresses, not its temporary ones, while avahi, on Linux, announces its temporary ones too. Only the sender's own addresses count: another host's address in an announcement isn't an announcement by that host.

##### What the router leased

The addresses a router's DHCP server handed out, which a device keeps for its lease, and not ones it chose itself, as a temporary IPv6 address:

```yaml
filter:
  - mac:
      address: 00:11:22:33:44:77
    ip:
      seen:
        - reported:
            by:
              - mikrotik
            from:
              - leases
```

It needs a [plugin](discovery.md#plugins) that reads the leases of the router handing them out: a `mikrotik`, `linux` or `freebsd` plugin reads them each time it polls. A DHCPv6 lease on `linux` or `freebsd` is matched to the MAC the neighbor table has its address at. A MikroTik router's DHCPv6 bindings have no MAC to read.

##### Not what a server leased

The addresses a host chose itself, as with SLAAC, and not one a DHCPv6 server gave it:

```yaml
filter:
  - mac:
      address: 00:11:22:33:44:88
    ip:
      type:
        - global
      not_seen:
        - reported:
            from:
              - leases
```

The lease is only known once the plugin has read it, at its next poll after the address was found. Until then, the leased address goes to the task too.

Addresses without a MAC, such as the network's public IPv4, don't go through filters: a task gets them from the [sources](sources.md) it names in its `sources`.

### Addresses that stay quiet

A host's stable IPv6 address, or the IPv4 address of a host that sends nothing, may never be seen. With `discovery.solicit`, ipv6ddns asks the hosts the filters name for them. See [solicitation](discovery.md#solicitation).

## Examples

### 1. Simple: Track a specific device by MAC
Most common use case. Updates DNS with any address found for this device.

```yaml
filter:
  - mac:
      address: "00:11:22:33:44:55"
```

### 2. Specific: Track only Global Public IP of a device
Ignore Link-Local or ULA addresses.

```yaml
filter:
  - mac:
      address: "00:11:22:33:44:55"
    ip:
      type:
        - global
```

### 3. Common server setup (Public IP)
Servers often need a stable address. By requiring `global` (public) AND `eui64` (MAC-derived, a stable interface ID), you avoid temporary privacy addresses.

```yaml
filter:
  - mac:
      address: "00:11:22:33:44:55"
    ip:
      type:
        - global
        - eui64
```

### 4. Multiple devices (OR logic)
Update the same DNS record if EITHER Device A OR Device B is found.

```yaml
filter:
  # Filter set 1: Device A
  - mac:
      address: "00:11:22:33:44:55"
  # Filter set 2: Device B
  - mac:
      address: "aa:bb:cc:dd:ee:ff"
```

### 5. Advanced: Prefix + Mask
Match the address whose interface ID is `::5`, within your static public prefix.

```yaml
filter:
  - ip:
      prefix: "2001:db8::/64"
      mask:
        - "::5/::ffff:ffff:ffff:ffff"
```

With a prefix the ISP changes, the subnet goes in the mask instead: `0:0:0:42::5/0:0:0:ffff:ffff:ffff:ffff:ffff` is interface ID `::5` of subnet `42`, under any prefix.

### 6. This machine ipv6ddns runs on
This machine's stable public IPv6 addresses, without the temporary ones, which change every day or so, plus the network's public IPv4 from a [source](sources.md), for a server behind NAT. Home Assistant add-ons, and containers on the host's network, have this machine's addresses, so their names can be endpoints of the same task.

```yaml
sources:
  wan:
    type: dns
tasks:
  this-machine:
    filter:
      - self: true
        ip:
          type:
            - global
            - "!temporary"
    sources:
      - wan
    endpoints:
      cloudflare:
        - server
        - "*.server"
credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: ${CLOUDFLARE_TOKEN}
      zone: example.com
      ttl: 1h
      proxied: false
discovery:
  exclude_interfaces:
    - docker*
    - br-*
    - veth*
    - hassio
```

For a local DNS, use its LAN address instead: `self: true` with `ip` `family` `4` and `type` `private`, and `discovery.ipv4.enabled: true`.
