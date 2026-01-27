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

  # Set 2: Match ANY Global Dynamic IP (e.g. for a different device or fallback)
  - ip:
      type: ["global", "eui64"]
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

*   **`prefix`** (Single String): CIDR subnet. The address must be contained within this subnet.
    *   Example: `2001:db8::/32`
*   **`suffix`** (Single String): The host part (suffix) of the address.
    *   Case-insensitive. The filter matches against the lowercase, RFC 5952 canonical representation of the address.
    *   Example: `::1` (Matches `2001:db8::1`, `fe80::1`, etc.) or `dead:beef` (Matches `...:DEAD:BEEF`)
*   **`type`** (List of Strings): Match semantic IP types. All types must match.
    *   Values:
        *   `global`: Global Unicast Address (Publicly routable).
        *   `ula`: Unique Local Address (`fc00::/7`).
        *   `link_local`: Link-Local Address (`fe80::/10`).
        *   `eui64`: derived from MAC address (stable).
        *   `random`: Privacy extension / randomized address.
    *   **Common Use Case**: `type: ["global"]` (Public IPs only).
*   **`mask`** (List of Strings): generic bitwise mask match.
    *   Format: `VALUE/MASK`

#### `filter.source`

*   **`source`** (List of Strings): Filter by the discovery plugin that found the address. All sources must have seen the address.
    *   Example: `["mikrotik-lan"]`

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
      type: ["global"]
```

### 3. Multiple devices (OR logic)
Update the same DNS record if EITHER Device A OR Device B is found.

```yaml
filter:
  - mac:
      address: "00:11:22:33:44:55" # Device A
  - mac:
      address: "aa:bb:cc:dd:ee:ff" # Device B
```

### 4. Advanced: Subnet + Suffix
Match any address ending in `::5` that is also within your public prefix.

```yaml
filter:
  - ip:
      prefix: "2001:db8::/32"
      suffix: "::5"
```

### 5. Common server setup (Public IP)
Servers often need a stable address. By requiring `global` (public) AND `eui64` (MAC-derived, static suffix), you avoid temporary privacy addresses.

```yaml
filter:
  - ip:
      type: ["global", "eui64"]
```
