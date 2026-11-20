# Mikrotik Integration

`ipv6ddns` offers deep integration with Mikrotik RouterOS. It can be used as:

1.  **DNS Provider**: Automatically creates static DNS records (`/ip/dns/static`) for discovered hosts (e.g., `nas.lan` -> `fd00::1`).
2.  **Discovery Plugin**: Uses the router's neighbor tables to find the hosts of the network, IPv6, and IPv4 with `discovery.ipv4`.
3.  **Container Host**: Runs directly on the router, removing the need for a separate server.

**Example Scenario:**
You run `ipv6ddns` in a container on your Mikrotik router. It detects your NAS and IoT devices coming online and instantly assigns them local DNS names (`nas.lan`, `cam.lan`) in the router's DNS, making them accessible by name to all your wifi clients.

## Discovery Plugin

The Mikrotik discovery plugin allows `ipv6ddns` to query the router's neighbor list and IPv6 neighbor table to find active hosts. This is useful when `ipv6ddns` is running on a device that doesn't see all network traffic (e.g., in a container or a different segment). Or just for convenience when runnning `ipv6ddns` directly as a container on RouterOS.

### Configuration

```yaml
discovery:
  plugins:
    mikrotik-router:
      type: mikrotik
      interval: 60s
      address: 192.168.88.1:8729
      username: admin
      password: ${ROUTER_PASSWORD}
      use_tls: true
      # The SHA-256 of the router's certificate: needed for the self-signed one RouterOS makes
      tls_fingerprint: "0B:30:55:7A:9F:C4:E9:0E:33:58:7D:A2:C7:EC:11:36:5B:80:A5:CA:EF:14:39:5E:83:A8:CD:F2:17:3C:61:86"
```

Its keys are in the [reference](reference/configuration.md#mikrotik).

With `use_tls: true` alone, the router's certificate is verified with the system's CAs, for the name or address in `address`. That fails for the certificate RouterOS makes itself, which is self-signed: give its `tls_fingerprint`, 64 hex digits, colons allowed, which is then all that is checked. Unlike the DNS provider below, the plugin's error doesn't show the fingerprint. Get it with:

```bash
openssl s_client -connect 192.168.88.1:8729 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

`tls_fingerprint` without `use_tls: true` is an error. Without `use_tls`, on the `api` service, port 8728, the password crosses the network in the clear.

### Requirements
- **API User**: The plugin only reads the neighbor tables (`/ipv6/neighbor/print`, and `/ip/arp/print` for IPv4), so give it a dedicated read-only user, and optionally limit it to the address `ipv6ddns` connects from:
  ```
  /user group add name=ipv6ddns-discovery policy=read,api
  /user add name=ipv6ddns-discovery group=ipv6ddns-discovery address=192.168.88.10/32 password=...
  ```
  If the same router is also the DNS provider, use a separate user for that (see below), so the discovery credentials can't change the router.
- **API Service**: Ensure `api` (port 8728) or `api-ssl` (port 8729) service is enabled under `/ip/service`.

---

## DNS Provider

The Mikrotik provider allows `ipv6ddns` to update static DNS entries (`/ip/dns/static`) on your router. This is useful for local DNS resolution of your IPv6 hosts.

### Configuration

```yaml
credentials:
  myrouter:
    provider: mikrotik
    settings:
      # Add a port unless it is the default: 8728 for cleartext, 8729 for TLS
      address: 192.168.88.1
      # Recommended: use TLS (requires API-SSL service on router)
      use_tls: true
      # If certificate cannot be validated you must provide the SHA256 fingerprint of the router's certificate. Run empty to get the fingerprint.
      # With a fingerprint, only that certificate is accepted, and use_tls must be true.
      tls_fingerprint: ""
      # Credentials
      username: admin
      password: password
      # The domain zone to append to hostnames (e.g. host.lan)
      zone: lan
      # TTL for the DNS records                
      ttl: 5m
```

### Requirements
- **API User**: Create a user on the router with `read`, `write` and `api` permissions (`write` is needed to manage `/ip/dns/static`).
- **API Service**: as for the [discovery plugin](#requirements).

---

### Limitations

- **A hostname's capitals are part of it.** RouterOS answers a query whatever its capitals, but finds the records to change by the exact letters of the name. A hostname whose capitals change in the configuration, `NAS` to `nas`, is another name to it: the records written before stay, and are still answered. Remove them by hand: `/ip dns static remove [find name="NAS.lan"]`.

## Running as a Container on RouterOS

You can run `ipv6ddns` directly on your Mikrotik router using the Container feature (available in RouterOS v7.4+).

### 1. Enable Container Support
Check out the [Mikrotik Container Documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container) for instructions on how to enable and configure the container feature.

### 2. Configure Network
Create a VETH interface and bridge it to your LAN so the container can see network traffic (essential for NDP discovery if not using plugins).

> [!NOTE]
> If you plan on using an external DNS provider (e.g. Cloudflare, Route53), you must ensure the container has internet access via this VETH interface (e.g., via NAT masquerade or proper routing).

> [!TIP]
> When running as a container on the router itself, it is recommended to use the [Mikrotik Discovery Plugin](#discovery-plugin) instead of relying on active discovery. While active discovery works if the VETH is bridged correctly, the plugin is more efficient and reliable in this environment, as it uses the router's internal tables.

### 3. Mount Configuration
Upload your `config.yaml` to the router (e.g., via SFTP or Drag & Drop on WinBox->Files).

### 4. Create and start the Container

The container image is available at:
`ghcr.io/miguelangel-nubla/ipv6ddns:v0`

You just need to create a container with this image and mount the config file at `/config.yaml`.

### Notes
- **Storage**: `ipv6ddns` runs in memory and does not write to disk, so it is safe to run on internal flash without wear concerns. The one exception is a `homeassistant` block with `key_provisioning: true`: the device's identity and the key Home Assistant gives are kept in `key_provisioning_state_file`, `homeassistant.state` beside the configuration, written only when they change, with an empty lock file beside it, made once. In a container, give the block a `key` instead, set by hand, and nothing is written: see [the Home Assistant integration](home-assistant-integration.md#the-key). However, external storage (USB/SD) is widely recommended because the container image size may exceed the available internal flash space on many devices.
