# Filtering system

`ipv6ddns` uses a filtering system to determine which discovered IPv6 addresses should be used for DDNS updates.

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

#### `filter.mac`

*   **`address`** (Single String): Exact match of the MAC address.
    *   Example: `00:11:22:33:44:55`
*   **`mask`** (List of Strings): Match against a mask. Useful for matching OUI (Vendor) or ranges. All provided masks must match.
    *   Format: `VALUE/MASK`
    *   Example: `00:11:22:00:00:00/ff:ff:ff:00:00:00` (Matches any device with 00:11:22 OUI)
*   **`type`** (List of Strings): Match protocol-defined MAC types. All types must match.
    *   Values: `global`, `local`, `unicast`, `multicast`.

#### `filter.ip`

*   **`family`** (List of Integers): The address families, `4` and `6`. **Default: `[6]`**, so a filter that names a device's MAC doesn't also take its private IPv4 addresses to a public DNS once IPv4 discovery finds them. Give `[4]` or `[4, 6]` for IPv4.
    *   Example: `family: [4]` with `type: [private]` for the `192.168.x.x` address of a device, to a local DNS.
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
        *   `random`: IPv6, privacy extension / randomized address.
    *   **Common Use Case**: `type: ["global"]` (Public IPs only).
*   **`mask`** (List of Strings): generic bitwise mask match.
    *   Format: `VALUE/MASK`

#### `filter.source`

*   **`source`** (List of Strings): Filter by the discovery plugin that found the address. All sources must have seen the address.
    *   Example: `["mikrotik-lan"]`

Addresses without a MAC, as the network's public IPv4, don't go through filters: a task gets them from the [sources](../README.md#sources-the-public-ipv4-and-addresses-without-a-mac) it names, in its `sources`.

### Addresses that stay quiet

Some addresses are never seen without asking: `solicit` under a family asks for those the filters want, once a minute.

- **IPv6**: a host usually sends from its temporary addresses, so its stable one may never be seen, and routers don't list it. Every filter that names a `mac.address` and asks for the `eui64` type makes `ipv6ddns` work out that address on each /64 it is on, and ask for it with a neighbor solicitation.
- **IPv4**: a quiet host may be in no ARP table. Every filter that names a `mac.address` with `ip.family` 4 makes `ipv6ddns` ask that MAC, by ARP requests sent to it alone, for each address of the local subnets: nothing is broadcast. It needs Linux and `CAP_NET_RAW`, which Docker grants by default.

An address that answers is discovered as usual; one that doesn't is never published.

```yaml
discovery:
  ipv6:
    solicit: true
  ipv4:
    active: false   # no broadcast sweep: the hosts wanted are asked
    solicit: true
```

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
