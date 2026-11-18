# Network wide IPv6 DDNS Updater

[![ci](https://github.com/miguelangel-nubla/ipv6ddns/actions/workflows/ci.yaml/badge.svg)](https://github.com/miguelangel-nubla/ipv6ddns/actions/workflows/ci.yaml)
[![release](https://img.shields.io/github/v/release/miguelangel-nubla/ipv6ddns)](https://github.com/miguelangel-nubla/ipv6ddns/releases/latest)

This utility discovers IPv6 addresses on your local network and updates DNS records dynamically. [Here is a detailed explanation.](#what-does-this-do)

> [!TIP]
> This tool keeps your domain names (like `myserver.example.com`) pointing to the correct IPv6 address of your devices, even if those addresses or ipv6 prefixes change, effectively acting as a Dynamic DNS client for your **entire** network.

## Why do I need this?

You have a server running a website, Home Assistant, self-hosted services, etc. You want to access it from anywhere using a domain like `myserver.example.com`.

**The Problem:**
Your Internet Service Provider (ISP) might change your home's IPv6 prefix occasionally (e.g., when you restart your router). When this happens, your server gets a new IPv6 address, and `myserver.example.com` stops working because it still points to the old address.

**The Solution:**
Instead of installing a DDNS updater on every single device (which can be tedious), you run **ipv6ddns** on *one* device in your network (like your router, a server, etc.).

1.  **ipv6ddns** continuously watches the network.
2.  It detects when your server (identified by its unique **MAC address**) gets a new IPv6 address.
3.  It automatically updates `myserver.example.com` on your DNS provider (like Duckdns, Cloudflare, or your home router) to point to the new IP.

Your setup keeps working, and you don't have to reconfigure anything when IPs change.

```
DNS:
    Provider: cloudflare
        Endpoint: remotecf
            mydomain.example.com: (last update: 2026-01-25T01:49:35Z)
                203.0.113.99
                2001:db8:1234:5678:abcd:ef01:2345:6789
                2001:db8:1234:5678:9876:5432:10fe:dcba
            ipv4.mydomain.example.com: (last update: 2026-01-25T01:53:06Z)
                203.0.113.99
    Provider: pfSense
        Endpoint: local
            *.local.internal.lan: (last update: 2026-01-25T01:22:03Z)
                10.99.1.50
Discovery:
    aa:bb:cc:00:11:22
        fd12:3456:789a::1 38m47s eth0
        fe80::100:2eff:fe33:4455 59m37s gateway:10.99.1.1:8729,eth0
    aa:bb:cc:00:33:44
        2001:db8:1234:5678::1 41m37s eth0,eth1
        2001:db8:aaaa:bbbb::3 -14h21m23s eth0
        fe80::100:2eff:fe66:7788 59m59s eth1,eth0
    12:34:56:78:90:ab
        2001:db8:1234:5678:abcd:ef01:2345:6789 35m15s eth0,eth1
        2001:db8:1234:5678:9876:5432:10fe:dcba 59m37s eth0,eth1,gateway:10.99.1.1:8729
```

## Installation

Download and run the [latest release](https://github.com/miguelangel-nubla/ipv6ddns/releases/latest) for your architecture.

### Or Use the Docker Image

The image, `ghcr.io/miguelangel-nubla/ipv6ddns`, is built for linux/386, amd64, arm/v6, arm/v7 and arm64.

```bash
docker run -it --rm --network host -v ./config.yaml:/config.yaml ghcr.io/miguelangel-nubla/ipv6ddns -live
```

Discovering hosts on the local network needs, in the container:

- **The host's network**, `--network host`: in a network of its own the container sees none of the hosts. Leave `"ipv6": true` out of `/etc/docker/daemon.json`, which is about the networks Docker makes, not the host's.
- **Raw sockets**, the `NET_RAW` capability, which Docker grants by default but other runtimes, or a Kubernetes `securityContext`, can drop. Without it, discovery logs `operation not permitted`, and only the [plugins](#discovery-plugins), which read the neighbor table of a router, find hosts.

With Docker Compose, the secrets out of the config file and a health check:

```yaml
services:
  ipv6ddns:
    image: ghcr.io/miguelangel-nubla/ipv6ddns:v0
    network_mode: host
    restart: unless-stopped
    command: ["-config_file", "/config.yaml", "-webserver_listen", "127.0.0.1:8053"]
    volumes:
      - ./config.yaml:/config.yaml:ro
    environment:
      CLOUDFLARE_TOKEN: ${CLOUDFLARE_TOKEN}
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://127.0.0.1:8053/healthz"]
```

### Or install from source

Ensure you have Go installed on your system. If not, follow the instructions on the official [Go website](https://golang.org/doc/install) to install it. Then:
```bash
go install github.com/miguelangel-nubla/ipv6ddns/cmd/ipv6ddns
```

## 🚀 Usage

1. **Configure the Service**

   Edit the configuration file (`config.yaml`) to suit your environment. You can start with the provided [example config](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/cmd/ipv6ddns/example.config.yaml).

2. **Run the Binary**

   > [!IMPORTANT]
   > This utility must be run with superuser privileges to listen for IPv6 ICMP packets.

   Use the following command to start the service:

   ```bash
   sudo ipv6ddns [flags]
   ```

3. **Example Command**

   Here's an example that runs the service with a custom config, enables the web interface on port 8053, and sets the log level to debug:

   ```bash
   sudo ipv6ddns \
     -config_file config.yaml \
     -webserver_listen 8053 \
     -log_level debug
   ```

   `-webserver_listen` takes a comma-separated list of what to listen on, in any combination:

   | Entry | Listens on |
   |---|---|
   | `8053`, `:8053` | that port, on all addresses |
   | `192.0.2.1:8053`, `[2001:db8::1]:8053` | that address and port |
   | `192.0.2.1`, `2001:db8::1`, `[2001:db8::1]` | that address, port 80 |
   | `myhost:8053`, `myhost` | every address the name resolves to, at startup |

   The report has no authentication: to keep it behind a reverse proxy, list only an address the proxy can reach. It hides the credentials, plugin params, IPv4 command arguments and update errors.

   Besides the report at `/`, the server answers:

   | Path | Serves |
   |---|---|
   | `/healthz` | `ok`, while the process runs: for container health checks |
   | `/status.json` | the host names, their addresses and updates, and the discovered hosts, as JSON |
   | `/metrics` | the same as Prometheus metrics: addresses, updates by result, last success |

   It stops on SIGINT or SIGTERM, giving the DNS updates running up to 30s to end.

4. **Access the Web report**

   After starting the service, you can see the status of the service at:

   ```
   http://<your_ip>:8053
   ```

## DDNS providers

The available DDNS providers are:

- [Cloudflare](https://www.cloudflare.com/application-services/products/dns/) (free plan compatible)
- [Duckdns](https://www.duckdns.org/) (provider only allows a single AAAA record)
- [Gravity](https://github.com/BeryJu/gravity) (hosted locally)
- [Mikrotik](https://mikrotik.com/) (RouterOS API) - [Setup Guide](docs/mikrotik.md)
- [OpenWrt](https://openwrt.org/) (SSH + UCI). Set `host_key` to the router's SSH key fingerprint, as for the Windows provider over SSH: without it, any key is accepted.
- [OPNsense](https://opnsense.org/) (Unbound DNS via API)
- [pfSense](https://www.pfsense.org/) (Unbound DNS via REST API)
- [Route53](https://aws.amazon.com/route53/) (AWS Route53 API)
- [Technitium](https://technitium.com/dns/) (HTTP API)
- [Windows DNS Server](https://learn.microsoft.com/en-us/windows-server/networking/dns/quickstart-install-configure-dns-server) (local or remote via SSH)
- :rocket: **If you’re comfortable coding, adding support for your preferred provider is a breeze**:
  - Use an existing provider in the `ddns/` directory (e.g., `cloudflare.go`) as a template.
  - Replace all instances of `cloudflare` with your provider’s name — case-sensitive!
  - Update the API logic in that file to match your provider's requirements.
  - Test your implementation thoroughly.
  - Verify that everything works correctly across multiple IP/prefix rotations.
  - Submit a pull request!

## Configuration file

The configuration is done via a `config.yaml` file. Below is a simplified example showing the structure.

For a complete reference with all available options and more providers, check the [example.config.yaml](cmd/ipv6ddns/example.config.yaml).

For full details on the filtering system (Filter Sets, logic, and available keys), see [filtering](docs/filtering.md) docs.

```yaml
tasks:
  # Whichever name you like for this task, it is only for reference
  my_public_web_server:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
        ip:
          # Only use Global Unicast Addresses (publicly routable)
          type:
            - global
          # Optional: Exclude privacy extensions (temporary addresses) by ensuring it is EUI64 derived
          # - eui64
    endpoints:
      # "example-cloudflare" refers to a credential block defined below
      example-cloudflare:
        # This will update test-webapp.example.com
        - test-webapp
    # Optional: also the network's public IPv4, for the A record, from the source below
    sources: [wan]

# Optional: addresses without a MAC, for the tasks that name them
sources:
  wan:
    # The public IPv4, as DNS resolvers see it. Or http, an echo service; command, yours; static
    type: dns

credentials:
  # Name you will use to refer to this endpoint on the tasks
  example-cloudflare:
    # One of the supported providers
    provider: cloudflare
    # Provider specific configuration
    settings:
      api_token: CLOUDFLARETOKEN
      zone: example.com
      ttl: 1h
      proxied: true
    # Optional, default 10s. time to wait before pushing updates
    debounce_time: 10s
    # Optional, default 60s. time to wait between retries on update error
    retry_time: 60s
  # ...
  # More credentials if needed
  # ...

# Optional: Discover hosts reading from network devices (pfSense, OPNsense, Mikrotik, etc.)
discovery:
  plugins:
    mikrotik-router:
      type: mikrotik
      interval: 90s
      address: 192.168.88.1:8729
      username: admin
      password: ${ROUTER_PASSWORD}
      use_tls: true

# For more info on available plugins and their configuration refer to the ipv6disc project
# https://github.com/miguelangel-nubla/ipv6disc#plugins
```

### Discovery plugins

A plugin reads the neighbor table of a router or a host, as ipv6disc does: `linux` over SSH, `freebsd` (pfSense, OPNsense) over SSH, or `mikrotik` over its API. Its settings are fields:

| Field | Plugins | |
|---|---|---|
| `interval` | all | How often to read the table, as `60s` |
| `address` | all | The host, with a port unless the default |
| `username`, `password` | all | The login |
| `identity_file` | linux, freebsd | The SSH private key, instead of the password or besides it |
| `host_key` | linux, freebsd | The host's SSH key fingerprint, `SHA256:...`, to verify it. Without it, any key is accepted, and the log warns with the fingerprint seen |
| `use_tls`, `tls_fingerprint` | mikrotik | The API over TLS, and the SHA-256 fingerprint of the router's certificate |

Or `params`, ipv6disc's string of them all, `interval,address,username,password,...`, where a comma in a value is written `\,`.

### Secrets

Any value of the configuration takes `${NAME}`, the environment variable `NAME`, and `${file:PATH}`, the content of a file without its final newline, as Docker and Kubernetes give secrets; a relative path is from the configuration file. `$${` is a literal `${`. A value from `${...}` within `params` isn't escaped: give a password with commas in the `password` field.

```yaml
credentials:
  example-cloudflare:
    provider: cloudflare
    settings:
      api_token: ${CLOUDFLARE_TOKEN}
      # or: api_token: ${file:/run/secrets/cloudflare_token}
```

An unknown setting, as a typo, is an error at start.


---

# What does this do?

## The problem
Having a domain name `my-web.example.com` point to your application on an IPv6 network is both simpler and more challenging than doing it with regular IPv4.

The classic method of directing traffic to your public IPv4 address (i.e., your router) and then using NAT is no longer a good idea, nor necessary.

IPv6 addresses are globally routable, which is nice, but you will need to know the exact IPv6, as different machines or even containers on the same host (and even different applications) will have different "public" IPv6s, or GUAs in IPv6 terminology.

In this scenario DNS names become almost mandatory, good luck trying to remember and type a different `https://[2001:0db8:85a3:0000:8a2e:0370:7334:abcd]` to access each one of your hosts.

Technically, IPv6 addresses could be static, but part of the beauty of IPv6 is the ability to use and rotate multiple different IP addresses on demand. Even if you don't want to, some ISPs change your IPv6 prefix on router reboot or periodically.

## Rationale
You might be thinking well, I will just run a DDNS updater on my server? It turns out that may not be really an option. Depending on your enviroment and ISP, each host (or even application) may have its own, *dynamic* IPv6. How do you indicate which IP should the DNS record point to? Does that mean the way to do that is to run the updater on the same container as your target application?

Unfortunately yes. That is not a great idea. Aside from the inconvenience of forking and using your own container images, there will be systems that you will not be able to modify. Think about a device on your network that has no way of running a custom executable, like an appliance, or an IP camera.

Wouldn't it be nice to have a single instance of a "DNS updater" anywhere on your network that detects the IPv6 of your desired hosts, identifies when they change, and updates the relevant DNS records accordingly?

## The solution
This utility scans the network for the IPv6s of the hosts you want to expose, identified by their MAC address, and updates the corresponding DNS records automatically.

This works for **_all your network_**, having the configuration and your credentials in a single place.

---

## Other nice usages

### Roaming over multiple IPv6 networks
This utility allows you to move between IPv6 networks and to maintain inbound connectivity.
You can have as many IPv6 addresses from different ISPs as you like and the AAAA records for your domain will be kept in sync.

For example, you can have a FTTH connection, a backup LTE connection, and Starlink on your roof. Your domain will have updated AAAA records for every WAN connection, inbound WAN failover will simply work.

#### Sources: the public IPv4, and addresses without a MAC
With IPv4 behind NAT, a server has a private address, and the world reaches it at the router's public one, through a port forward: its A record is the network's public IPv4. A source finds it, and the tasks that name the source add its addresses to their names:

```yaml
sources:
  wan:
    type: dns          # asks DNS resolvers the address they see
    family: [4]        # 4, 6 or both; default 4
    interval: 3m       # default 5m
    lifetime: 10m      # how long an address stays after the last run; default 3 intervals
tasks:
  myhome:
    filter: [...]      # the device's IPv6, by MAC
    sources: [wan]     # and the public IPv4
    endpoints: ...
```

| Type | Gives |
|---|---|
| `dns` | The public address, from OpenDNS, or Google's resolvers when it fails |
| `http` | The public address, from echo services over HTTPS, or `urls` of yours |
| `command` | The addresses a `command` with `args` prints, one per line |
| `static` | The `addresses` listed |

The `ipv4` block of a task, from before sources, still works: it becomes a command source, and the log says how to move it.

For more advanced use cases just write a custom script that prints the addresses you need, for a command source.

If you want to do the same MAC to address auto discovery in IPv4:
`ip neigh show | grep -i "00:11:22:33:44:55" | awk '{print $1}'`
or
`arp-scan --localnet | grep -i "00:11:22:33:44:55" | awk '{print $1}'`