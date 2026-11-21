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

#### `filter.source`

*   **`source`** (List of Strings): Filter by what saw the address: a plugin's name, or a local interface's. All sources must have seen the address.
    *   Example: `["mikrotik-lan"]`

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
