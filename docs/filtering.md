# Filtering system

A task's filters choose which of the addresses [discovery](discovery.md) finds go to the task's names. Every key is in the [reference](reference/configuration.md#task-filters).

## Core concepts

A task's `filter` is a list of filter sets, and each set holds rules.

1. **Sets are alternatives (OR).** An address that matches any set in the list goes to the task.
2. **Rules add up (AND).** An address matches a set only if it matches every rule in that set, for example this MAC address and this IP type.

### Visual logic

```text
Address -> [ Set 1 ] --(Match?)--> ACCEPT
              OR
Address -> [ Set 2 ] --(Match?)--> ACCEPT
              OR
Address -> [ Set 3 ] --(Match?)--> ACCEPT
```

Inside a set:

```text
Set 1:
  MAC Address == "..."  AND
  IP Type     == "Global"
```

## Configuration

### Structure

Each item of the `filter` list is one filter set:

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

A set can have rules about the machine itself (`self`), the host's MAC (`mac`), and the address (`ip`).

#### `filter.self`

`self` is a boolean. With `self: true`, the set takes the addresses of the machine ipv6ddns runs on, instead of a MAC's. Use it for a server or a Home Assistant host. There's no MAC to look up, and nothing changes when the machine's network card does.

- The addresses are those of the interfaces discovery runs on, while the family listens.
- An interface without a MAC, such as a PPP link or a tunnel, isn't included (see [interfaces](discovery.md#interfaces)). Take its addresses from a [source](sources.md) instead, for example a `command` source that reads the interface.
- An address the interface no longer has goes within a minute, not a lifetime later.
- Container bridges have this machine's addresses too. Leave them out with `discovery.exclude_interfaces`.

See the example [this machine](#6-this-machine-ipv6ddns-runs-on).

#### `filter.mac`

| Key | Takes | Matches |
|---|---|---|
| `address` | One string | Exactly this MAC address |
| `mask` | A list of strings | A MAC that matches every mask in the list |
| `type` | A list of strings | A MAC that is of every type in the list |

- **`address`**: for example `00:11:22:33:44:55`. `00-11-22-33-44-55` and `0011.2233.4455` are the same MAC. Anything that isn't a MAC is a configuration error.
- **`mask`**: useful for matching a vendor's OUI, or a range. Each entry is `VALUE/MASK`, and both parts are whole MACs. An entry in any other form is a configuration error. For example, `00:11:22:00:00:00/ff:ff:ff:00:00:00` matches any device whose OUI is 00:11:22.
- **`type`**: the MAC types the protocol defines: `global`, `local`, `unicast`, `multicast`. Write `!type` for "not of this type".

#### `filter.ip`

| Key | Takes | Matches |
|---|---|---|
| `family` | A list of integers | An address of one of these families, `4` and `6`. Default: `[6]` |
| `prefix` | One string | An address inside this subnet |
| `type` | A list of strings | An address that is of every type in the list |
| `mask` | A list of strings | An address that matches every mask in the list |
| `seen`, `not_seen` | Lists of rules | An address by how it was seen: see [`filter.ip.seen`](#filteripseen) |

**`family`** defaults to `[6]`. That way, a filter that names a device's MAC doesn't also send the device's private IPv4 addresses to a public DNS once IPv4 discovery finds them. Give `[4]` or `[4, 6]` for IPv4. For example, `family` `4` with `type` `private` takes a device's `192.168.x.x` address, for a local DNS.

**`prefix`** is a subnet in CIDR form, for example `2001:db8::/32`. The address must be inside it.

**`type`** takes these values. Write `!type` for "not of this type", for example `!temporary`. The most common use is a `type` of `global`, for public addresses only.

| Type | Means |
|---|---|
| `global` | A global unicast address, publicly routable: not private, link-local or carrier-grade NAT |
| `private` | An RFC 1918 IPv4 address (`10/8`, `172.16/12`, `192.168/16`), or an IPv6 unique local address |
| `ula` | A unique local address (`fc00::/7`) |
| `cgnat` | A carrier-grade NAT IPv4 address (`100.64.0.0/10`) |
| `link_local` | A link-local address (`fe80::/10`, or `169.254.0.0/16`) |
| `eui64` | An IPv6 address derived from the MAC address, which is stable |
| `random` | An IPv6 address whose interface ID is not derived from the MAC. It's a privacy address, or a stable address made another way, as most systems make them now |
| `temporary` | An IPv6 privacy address of this machine, which its kernel marks as temporary. It changes every day or so. Only known on Linux and macOS, and only for the [`self`](#filterself) addresses |

**`mask`** is a bitwise match. In the bits that `MASK` sets, the address must equal `VALUE`.

- Each entry is `VALUE/MASK`, and both parts are full addresses of the same family. A part's family is the one it is written in: IPv4 with dots only, as `0.0.0.5`, and IPv6 with colons, as `::5`.
- `MASK` is an address, not a prefix length. `::1/64` is a configuration error, and so is any entry that isn't two addresses. For a subnet, use `prefix`.
- A mask compares bits, not text, so an address may be written short or in full. `::5/::ffff:ffff:ffff:ffff` takes `2001:db8:1:1::5`. It leaves out `2001:db8:1:1:2:0:0:5`, whose interface ID is `2:0:0:5`.
- A mask only matches addresses of its own family. With `family` `4` and `6`, an IPv6 mask leaves the IPv4 addresses out, so use one filter per family. That holds for an IPv6 mask such as `::ffff:ffff:ffff` too, which is also how an IPv4 address inside IPv6 looks: it is an IPv6 mask, since it is written as one.

| Wanted | Mask |
|---|---|
| The interface ID `::5`, whatever the prefix | `::5/::ffff:ffff:ffff:ffff` |
| The last 32 bits `dead:beef` | `::dead:beef/::ffff:ffff` |
| The last 48 bits `1234:dead:beef` | `::1234:dead:beef/::ffff:ffff:ffff` |
| The last group `5` | `::5/::ffff` |
| Subnet `42` and interface ID `::5`, under any prefix the ISP delegates | `0:0:0:42::5/0:0:0:ffff:ffff:ffff:ffff:ffff` |
| The IPv4 addresses ending in `.5` | `0.0.0.5/0.0.0.255` |

#### `filter.ip.seen`

`seen` and `not_seen` match an address by how it was seen.

Discovery keeps a record of each way it saw an address. Each record has its own first time, last time and lifetime. The address stays as long as any of its records does. A rule matches only a record that is still current.

- **`seen`** is a list of rules. The address must have a record that matches each of them.
- **`not_seen`** is a list of rules. The address must have no record that matches any of them.

There are two kinds of rule.

**A protocol rule** matches what a protocol saw:

- `protocol`: one of the local discovery's protocols.
- `way`: how the protocol saw the address. Leave it out for any way.
  - `announced`: the host said, unprompted, that the address is its own, or said something about itself from that address.
  - `answered`: the host replied to one of discovery's probes, from the address or for it.
  - `heard`: the host used the address without discovery asking.

**A `reported` rule** matches an address that something other than the host reported, from one of its tables:

- `by`: who reported it. Give plugins, by name or by type, such as `mikrotik`, or `kernel` for this machine's own kernel. Leave it out for anyone.
- `from`: the table it came from. `neighbors` is a neighbor or ARP table, `leases` is the DHCP leases, and `interfaces` is the addresses of this machine's interfaces. Leave it out for any table.
- `reported: {}` means by anyone, from any table.

A lease never finds an address on its own. A lease is attached to an address that something else found at the lease's MAC, for as long as the plugin reads the lease. The lease keeps the address no longer than whatever found it does. The reason is that a server keeps the lease of a host that left until the lease ends.

Both kinds of rule take `interfaces`, a list of local interfaces. The record must have been made on one of them. A plugin's reports aren't on any interface.

This table lists when each protocol records each way:

| `protocol` | `way` | Recorded when |
|---|---|---|
| `ndp` | `announced` | The host advertises an address unasked, for example when it takes the address |
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

A rule that can never match is an error at start, and the error says why:

- A way in which a protocol never sees an address, such as `ping` with `announced`.
- A protocol, table or reporter that doesn't exist. `by` must name a plugin of `discovery.plugins`, a plugin type, or `kernel`.
- A `seen` rule for a protocol that is disabled under `discovery.protocols`. No address can have that protocol's records.
- A `not_seen` rule that excludes every record a `seen` rule needs, such as `seen` with `mdns` `announced` and `not_seen` with `mdns`. The filter could take no address.

Keep two things in mind:

- **A rule belongs to its filter.** A task's filters are alternatives. So an address that one filter leaves out with its `not_seen` still goes to the task if another filter takes it. To keep something out of a task, give the `not_seen` to each of the task's filters.
- **`not_seen` judges the records that exist now.** Say a host announces its address over mDNS a moment after another protocol found it. Until the announcement arrives, the address passes a `not_seen` rule for `mdns`, so it goes to the task for that moment. `seen` works the other way round: an address goes to the task only once it has the record the rule wants.

None of these rules tells a stable address from a temporary one. Only the host knows which is which, and it tells nobody. See [after a start](discovery.md#after-a-start) for what a restart can't find straight away.

##### What the host itself showed

A router keeps the neighbor entry of a host that left, and reports it until the entry ages out. An address the host itself answered for, or announced, is really there now. This filter takes only such addresses:

```yaml
filter:
  - mac:
      address: 00:11:22:33:44:55
    ip:
      seen:
        - protocol: ndp
```

`ndp` is on by default. It sees every IPv6 address on the links local discovery runs on, in one way or another. A host on another network, which only a plugin reaches, has nothing but the plugin's report, so this filter leaves it out.

##### What the host announced over mDNS

A host's mDNS responder announces the addresses the host means to be reached at, in the address records of its name. This filter takes only those:

```yaml
filter:
  - mac:
      address: 00:11:22:33:44:66
    ip:
      seen:
        - protocol: mdns
          way: announced
```

`mdns` is on by default. What gets announced is up to the host's responder. Apple's announces only its stable addresses, not its temporary ones. Avahi, on Linux, announces its temporary ones too.

Only the sender's own addresses count. Another host's address in an announcement isn't an announcement by that other host.

##### What the router leased

This filter takes the addresses a router's DHCP server handed out, which a device keeps for its lease. It leaves out the addresses the device chose itself, such as a temporary IPv6 address:

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

It needs a [plugin](discovery.md#plugins) that reads the leases of the router that hands them out. A `mikrotik`, `linux` or `freebsd` plugin reads the leases each time it polls.

For DHCPv6, a lease on `linux` or `freebsd` is matched to the MAC that the neighbor table has the leased address at. A MikroTik router's DHCPv6 bindings have no MAC to read.

##### Not what a server leased

This filter takes the addresses a host chose itself, for example with SLAAC, and leaves out an address a DHCPv6 server gave it:

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

A lease is known only once the plugin has read it, at its next poll after the address was found. Until then, the leased address goes to the task too.

Addresses without a MAC, such as the network's public IPv4, don't go through filters. A task gets them from the [sources](sources.md) it names in its `sources`.

### Addresses that stay quiet

A host's stable IPv6 address may never be seen, and neither may the IPv4 address of a host that sends nothing. With `discovery.solicit`, ipv6ddns asks the hosts the filters name for those addresses. See [solicitation](discovery.md#solicitation).

## Examples

### 1. Simple: Track a specific device by MAC
The most common case. The name gets every address found for this device.

```yaml
filter:
  - mac:
      address: "00:11:22:33:44:55"
```

### 2. Specific: Track only Global Public IP of a device
The name gets the device's global addresses only. Link-local and ULA addresses are left out.

```yaml
filter:
  - mac:
      address: "00:11:22:33:44:55"
    ip:
      type:
        - global
```

### 3. Common server setup (Public IP)
A server usually needs a stable address. Requiring both `global` (public) and `eui64` (derived from the MAC, so a stable interface ID) leaves out the temporary privacy addresses.

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
The same name gets the addresses of device A and of device B, whichever of them is found.

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
The address whose interface ID is `::5`, within your static public prefix.

```yaml
filter:
  - ip:
      prefix: "2001:db8::/64"
      mask:
        - "::5/::ffff:ffff:ffff:ffff"
```

If your ISP changes the prefix, put the subnet in the mask instead. `0:0:0:42::5/0:0:0:ffff:ffff:ffff:ffff:ffff` is interface ID `::5` of subnet `42`, under any prefix.

### 6. This machine ipv6ddns runs on
This task takes two things:

- This machine's stable public IPv6 addresses. The temporary ones, which change every day or so, are left out.
- The network's public IPv4, from a [source](sources.md), for a server behind NAT.

Home Assistant apps, and containers on the host's network, have this machine's addresses. So their names can be endpoints of the same task.

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

For a local DNS, use the machine's LAN address instead: `self: true` with `ip` `family` `4` and `type` `private`, and `discovery.ipv4.enabled: true`.
