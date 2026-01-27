# Mikrotik Integration

`ipv6ddns` offers deep integration with Mikrotik RouterOS. It can be used as:

1.  **DNS Provider**: Automatically creates static DNS records (`/ip/dns/static`) for discovered hosts (e.g., `nas.lan` -> `fd00::1`).
2.  **Discovery Source**: Uses the router's neighbor table to find active IPv6 hosts on the network.
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
      # Format: interval,address,username,password,use_tls[,tls_fingerprint]
      params: 60s,192.168.88.1:8729,admin,password,true
```

For more details on the parameters, refer to the [ipv6disc documentation](https://github.com/miguelangel-nubla/ipv6disc#plugins).

---

## DNS Provider

The Mikrotik provider allows `ipv6ddns` to update static DNS entries (`/ip/dns/static`) on your router. This is useful for local DNS resolution of your IPv6 hosts.

### Configuration

```yaml
credentials:
  myrouter:
    provider: mikrotik
    settings:
      # API port (default 8728 for cleartext, 8729 for TLS)
      address: 192.168.88.1:8728
      # Recommended: use TLS (requires API-SSL service on router)
      use_tls: true
      # If certificate cannot be validated you must provide the SHA256 fingerprint of the router's certificate. Run empty to get the fingerprint.
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
- **API User**: Create a user on the router with `read`, `write` and `api` permissions.
- **API Service**: Ensure `api` (port 8728) or `api-ssl` (port 8729) service is enabled under `/ip/service`.

---

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
`ghcr.io/miguelangel-nubla/ipv6ddns:latest`

You just need to create a container with this image and mount the config file at `/config.yaml`.

### Notes
- **Storage**: `ipv6ddns` runs entirely in memory and does not write to disk, so it is safe to run on internal flash without wear concerns. However, external storage (USB/SD) is widely recommended because the container image size may exceed the available internal flash space on many devices.
