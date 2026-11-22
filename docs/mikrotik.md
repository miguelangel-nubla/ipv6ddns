# MikroTik integration

ipv6ddns works with MikroTik RouterOS in three ways, which you can use separately or together:

1. **[DNS provider](#dns-provider):** it keeps static DNS records (`/ip/dns/static`) on the router for the hosts it discovers, for example `nas.lan` -> `fd00::1`.
2. **[Discovery plugin](#discovery-plugin):** it reads the router's neighbor tables to find the hosts of the network. It finds IPv6 hosts, and IPv4 hosts too with `discovery.ipv4`.
3. **[Container host](#running-as-a-container-on-routeros):** it runs on the router itself, so you need no separate server.

For example, you run ipv6ddns in a container on your MikroTik router. When your NAS and your IoT devices come online, it finds them and at once gives them local names in the router's DNS, such as `nas.lan` and `cam.lan`. All your Wi-Fi clients can then reach them by name.

## Discovery plugin

The MikroTik discovery plugin reads the router's neighbor tables to find the active hosts. Use it when ipv6ddns runs somewhere that doesn't see all the network's traffic, for example in a container or on a different segment. It is also the convenient choice when ipv6ddns runs as a container on RouterOS itself.

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

The plugin's keys are in the [reference](reference/configuration.md#mikrotik).

How the connection is secured depends on two keys:

- **`use_tls: true` alone:** the router's certificate is verified against the system's certificate authorities, for the name or address in `address`. That fails for the self-signed certificate RouterOS makes itself.
- **`use_tls: true` with `tls_fingerprint`:** only the certificate's fingerprint is checked. Use this for a self-signed certificate. The fingerprint is 64 hex digits, and colons are allowed.
- **Without `use_tls`:** the plugin uses the plain `api` service on port 8728, and the password crosses the network unencrypted.
- **`tls_fingerprint` without `use_tls: true`** is an error.

Unlike the error of the DNS provider below, the plugin's error doesn't show the router's fingerprint. Get it with:

```bash
openssl s_client -connect 192.168.88.1:8729 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

### Requirements

- **An API user.** The plugin only reads the neighbor tables: `/ipv6/neighbor/print`, and `/ip/arp/print` for IPv4. Give it a dedicated read-only user, and optionally limit that user to the address ipv6ddns connects from:
  ```
  /user group add name=ipv6ddns-discovery policy=read,api
  /user add name=ipv6ddns-discovery group=ipv6ddns-discovery address=192.168.88.10/32 password=...
  ```
  If the same router is also the DNS provider, use a separate user for the provider (see below). The discovery credentials then can't change the router.
- **The API service.** Make sure the `api` service (port 8728) or the `api-ssl` service (port 8729) is enabled under `/ip/service`.

## DNS provider

The MikroTik provider updates static DNS entries (`/ip/dns/static`) on your router. Use it to resolve your hosts' names locally, through the router's DNS.

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

- **An API user.** Create a user on the router with the `read`, `write` and `api` permissions. `write` is needed to manage `/ip/dns/static`.
- **The API service.** The same as for the [discovery plugin](#requirements).

### Limitations

- **Upper and lower case are part of a hostname.** RouterOS answers a query whatever its case, but it finds the records to change by the exact letters of the name. If you change the case of a hostname in the configuration, say from `NAS` to `nas`, RouterOS treats it as a different name. The records written before stay, and are still answered. Remove them by hand: `/ip dns static remove [find name="NAS.lan"]`.

## Running as a container on RouterOS

You can run ipv6ddns on the MikroTik router itself, with the Container feature of RouterOS v7.4 and later.

### 1. Enable container support

Follow the [MikroTik Container documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container) to enable and configure the container feature.

### 2. Configure network

Create a VETH interface and bridge it to your LAN, so the container can see the network's traffic. Without plugins, NDP discovery depends on this.

> [!NOTE]
> If you use an external DNS provider, such as Cloudflare or Route53, the container needs internet access through this VETH interface, for example with NAT masquerade or proper routing.

> [!TIP]
> On the router itself, prefer the [MikroTik discovery plugin](#discovery-plugin) to active discovery. Active discovery works if the VETH is bridged correctly, but the plugin is more efficient and reliable here, because it reads the router's internal tables.

### 3. Mount configuration

Upload your `config.yaml` to the router, for example over SFTP, or by dragging it into Files in WinBox.

### 4. Create and start the container

Create a container with this image, and mount the configuration file at `/config.yaml`:

`ghcr.io/miguelangel-nubla/ipv6ddns:v0`

### Notes

- **Writes to disk:** ipv6ddns runs in memory and doesn't write to disk, so it causes no wear on internal flash.
- **The one exception** is a `homeassistant` block with `key_provisioning: true`. The device's identity and the key Home Assistant gives are then kept in `key_provisioning_state_file`, which is `homeassistant.state` beside the configuration. That file is written only when they change. An empty lock file is made beside it, once. In a container, give the block a `key` that you set by hand instead, and nothing is written: see [the Home Assistant integration](home-assistant-integration.md#the-key).
- **Where to store the image:** external storage (USB or SD) is still recommended, because the container image may be larger than the free internal flash of many devices.
