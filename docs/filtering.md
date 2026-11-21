# Filtering system

A task's filters choose which of the addresses [discovery](discovery.md) finds are the task's, for its names. Every key is in the [reference](reference/configuration.md#task-filters).

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

*   **`self`** (Boolean): The addresses of the machine ipv6ddns runs on, rather than of a MAC: a server, a Home Assistant host. No MAC to look up, and no change when its network card does. They are those of the interfaces discovery runs on, while the family listens, so not those of an interface without a MAC, as a PPP link or a tunnel (see [interfaces](discovery.md#interfaces)): take those from a [source](sources.md), as a `command` one that reads the interface. An address the interface no longer has leaves within a minute, not a lifetime later. Leave out with `discovery.exclude_interfaces` the bridges of containers, whose addresses are this machine's too. See [this machine](#6-this-machine-ipv6ddns-runs-on).

#### `filter.mac`

*   **`address`** (Single String): Exact match of the MAC address.
    *   Example: `00:11:22:33:44:55`. Written as `00-11-22-33-44-55` or `0011.2233.4455`, it is the same MAC. What is no MAC is a configuration error.
*   **`mask`** (List of Strings): Match against a mask. Useful for matching OUI (Vendor) or ranges. All provided masks must match.
    *   Format: `VALUE/MASK`, both whole MACs. An entry that isn't is a configuration error.
    *   Example: `00:11:22:00:00:00/ff:ff:ff:00:00:00` (Matches any device with 00:11:22 OUI)
*   **`type`** (List of Strings): Match protocol-defined MAC types. All types must match.
    *   Values: `global`, `local`, `unicast`, `multicast`; `!type` for not of the type.

#### `filter.ip`

*   **`family`** (List of Integers): The address families, `4` and `6`. **Default: `[6]`**, so a filter that names a device's MAC doesn't also take its private IPv4 addresses to a public DNS once IPv4 discovery finds them. Give `[4]` or `[4, 6]` for IPv4.
    *   Example: a `family` of `4` with a `type` of `private` for the `192.168.x.x` address of a device, to a local DNS.
*   **`prefix`** (Single String): CIDR subnet. The address must be contained within this subnet.
    *   Example: `2001:db8::/32`
*   **`suffix`** (Single String): The host part (suffix) of the address.
    *   Case-insensitive. The filter matches against the lowercase, RFC 5952 canonical representation of the address.
    *   Example: `::1` (Matches `2001:db8::1`, `fe80::1`, etc.) or `dead:beef` (Matches `...:DEAD:BEEF`)
*   **`type`** (List of Strings): Match semantic IP types. All types must match.
    *   Values:
        *   `global`: Global Unicast Address (Publicly routable): not private, link-local or carrier-grade NAT.
        *   `private`: RFC 1918 IPv4 (`10/8`, `172.16/12`, `192.168/16`), or IPv6 unique local.
        *   `ula`: Unique Local Address (`fc00::/7`).
        *   `cgnat`: Carrier-grade NAT IPv4 (`100.64.0.0/10`).
        *   `link_local`: Link-Local Address (`fe80::/10`, or `169.254.0.0/16`).
        *   `eui64`: IPv6, derived from MAC address (stable).
        *   `random`: IPv6, an interface ID not from the MAC: a privacy address, or a stable one of another scheme, as most systems' now.
        *   `temporary`: an IPv6 privacy address of this machine's, which its kernel says is temporary: it changes every day or so. Known on Linux, and for the [`self`](#filterself) addresses only.
    *   `!type`: not of the type, as `!temporary`.
    *   **Common Use Case**: a `type` of `global` (Public IPs only).
*   **`mask`** (List of Strings): generic bitwise mask match: the address must equal `VALUE` in the bits `MASK` sets. All provided masks must match.
    *   Format: `VALUE/MASK`, both whole addresses of one family. `MASK` is an address, not a prefix length: `::1/64` is a configuration error, as any entry that isn't two addresses. For a subnet, use `prefix`.
    *   Example: `::1/::ffff:ffff:ffff:ffff` (the IPv6 addresses whose interface ID is `::1`, whatever the prefix), or `0.0.0.5/0.0.0.255` (the IPv4 addresses ending in `.5`).
    *   A mask matches the addresses of its own family only: with a `family` of `4` and `6`, an IPv6 mask leaves the IPv4 addresses out.

#### `filter.ip.seen`

How the address was seen. Discovery keeps a record of each way it saw an address, each with its own first and last time and its own lifetime: the address stays while any of them does, and a rule here matches only a record that still counts. `seen` is a list of rules, all of which the address must have a record of; `not_seen` a list of which it must have none.

A rule is one of two kinds:

*   **A protocol, and how it saw the address:**
    *   `protocol`: one of the local discovery's.
    *   `way`: how. Without, any way.
        *   `announced`: the host said the address is its own, unasked, or about itself.
        *   `answered`: it replied to a probe of the discovery's, from or for the address.
        *   `heard`: it used the address, unprompted by the discovery.
*   **`reported`**: something else than the host reported it, from one of its tables.
    *   `by`: plugins, by name or by type, as `mikrotik`; or `kernel`, this machine's own. Without, anyone.
    *   `from`: `neighbors`, a neighbor or ARP table; `leases`, DHCP leases; `interfaces`, the addresses of this machine's interfaces. Without, any. A lease finds no address: it is added to one something else found, at the lease's MAC, while the plugin reads the lease, and keeps it no longer than what found it, as a server keeps the lease of a host that left until it ends.
    *   `reported: {}` is by anyone, from any table.

Either kind takes `interfaces`, a list of local interfaces: the record was made on one of them. A plugin's reports are on none.

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

What can't match is an error at start, that says why:

*   A way a protocol never sees an address, as `ping` with `announced`; a protocol, a table or a reporter there is none of: `by` names a plugin of `discovery.plugins`, a type of plugin, or `kernel`.
*   A rule of `seen` of a protocol that is disabled, under `discovery.protocols`: no address has its records.
*   A rule of `not_seen` that wants none of every record a rule of `seen` wants, as `seen` with `mdns` `announced` and `not_seen` with `mdns`: the filter takes no address.

Two things to know of them:

*   **A rule is of its filter.** The filters of a task are alternatives: an address that one leaves out with its `not_seen` is the task's all the same when another filter takes it. To leave something out of a task, give the `not_seen` to each of its filters.
*   **`not_seen` judges the records there are.** A host that announces its address a moment after another protocol found it matches `not_seen` with `mdns` until the announcement comes, and its address is the task's for that moment. `seen` waits for what it wants: an address is the task's only once it has it.

None of these tells a stable address from a temporary one: the host knows, and says it to nobody. See [after a start](discovery.md#after-a-start) for what a restart can't find at once.

##### What the host itself showed

A router keeps the neighbor entry of a host that left, and reports it until it ages out. An address the host itself answered for, or announced, is there now:

```yaml
filter:
  - mac:
      address: 00:11:22:33:44:55
    ip:
      seen:
        - protocol: ndp
```

`ndp` sees every IPv6 address on the links the local discovery runs on, by any way; it is on by default. Of a host on another network, which only a plugin reaches, there is nothing but the plugin's report: this leaves it out.

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

`mdns` is on by default. What it announces is the responder's choice: Apple's announces its stable addresses only, not its temporary ones; avahi, on Linux, its temporary ones too. An address of another host in an announcement is no announcement of that host's: only the sender's own count.

##### What the router leased

The addresses a router's DHCP server gave, as one a device keeps for its lease, and not one it took itself, as a temporary IPv6 address:

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

It needs a [plugin](discovery.md#plugins) that reads the leases, of the router that gives them: a `mikrotik`, `linux` or `freebsd` plugin reads them as it polls. A DHCPv6 lease of `linux` or `freebsd` has its address at the MAC the neighbor table has it at; the DHCPv6 bindings of a Mikrotik router have none to read.

##### Not what a server leased

The addresses a host took itself, as those of SLAAC, and not one a DHCPv6 server gave it:

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

The lease is known once the plugin has read it, at its next poll after the address was found: until then the leased address is the task's too.

Addresses without a MAC, as the network's public IPv4, don't go through filters: a task gets them from the [sources](sources.md) it names, in its `sources`.

### Addresses that stay quiet

A host's stable IPv6 address, or the IPv4 address of a host that sends nothing, may never be seen: with `discovery.solicit`, the hosts the filters name are asked for them. See [solicitation](discovery.md#solicitation).

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
Servers often need a stable address. By requiring `global` (public) AND `eui64` (MAC-derived, static suffix), you avoid temporary privacy addresses.

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

### 5. Advanced: Prefix + Suffix
Match any address ending in `::5` that is also within your static public prefix.

```yaml
filter:
  - ip:
      prefix: "2001:db8::/64"
      suffix: "::5"
```

### 6. This machine ipv6ddns runs on
Its stable public IPv6 addresses, not the temporary ones, which change every day or so; with the network's public IPv4 from a [source](sources.md), for a server behind NAT. Add-ons of a Home Assistant, and containers on the host's network, have this machine's addresses: their names can be endpoints of the same task.

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

For a local DNS, its address on the LAN: `self: true` with an `ip` of `family` `4` and `type` `private`, and `discovery.ipv4.enabled: true`.
