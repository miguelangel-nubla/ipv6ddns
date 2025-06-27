# Network wide IPv6 DDNS Updater

This utility discovers IPv6 addresses on your local network and updates DNS records dynamically. [Here is a detailed explanation.](#what-does-this-do)

If you have a special use case: [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc)

## Installation

Download and run the [latest release](https://github.com/miguelangel-nubla/ipv6ddns/releases/latest) for your architecture.

### Or install from source

Ensure you have Go installed on your system. If not, follow the instructions on the official [Go website](https://golang.org/doc/install) to install it. Then:
```bash
go install github.com/miguelangel-nubla/ipv6ddns/cmd/ipv6ddns
```

### Or Use the Docker Image

This may or may not work on your system—IPv6 in Docker can be tricky.
Please do not attempt this unless you're prepared for extensive debugging and possibly making code changes.

I was able to get it working using **host networking** and **without** setting `"ipv6": true` in `/etc/docker/daemon.json`.

If you have experience with Docker and IPv6 and can help improve this, please reach out—it's been a while since I last looked into it.

```bash
docker run -it --rm --network host -v ./config.json:/config.json gcr.io/miguelangel-nubla/ipv6ddns -live
```

## 🚀 Usage

1. **Configure the Service**

   Edit the configuration file (`config.json`) to suit your environment. You can start with the provided [example config](https://github.com/miguelangel-nubla/ipv6ddns/blob/main/cmd/ipv6ddns/example.config.json).

2. **Run the Binary**

   > ⚠️ **Note:** This utility must be run with superuser privileges to listen for IPv6 ICMP packets.

   Use the following command to start the service:

   ```bash
   sudo ipv6ddns [flags]
   ```

3. **Example Command**

   Here's an example that runs the service with a custom config, enables the web interface on port 80, and sets the log level to debug:

   ```bash
   sudo ipv6ddns \
     -config_file config.json \
     -webserver_port 80 \
     -log_level debug
   ```

4. **Access the Web report**

   After starting the service, open your browser and go to:

   ```
   http://<your_host_ipv6_or_local_ip>
   ```

## Configuration

This is the structure of the `config.json` file:

```json
{ 
  "tasks": {
    "my_public_web_server": { // whichever name you like for this task, it is only for reference
      "subnets": ["2000::/3"], // only IPv6 addresses on these subnets will be updated into the DDNS provider. "2000::/3" is any GUA.
      "mac_address": ["00:11:22:33:44:55", "00:11:22:33:44:56"], // MAC addresses of the hosts to look for
      "endpoints": {
        "example-project": [ // name of the endpoint to use for this task, as configured on the credentials section at the bottom
          "test-webapp" // hostname whose AAAA records will be kept in sync. This results in updating test-webapp.example.com as defined by example-project settings
        ]
      },
      "lifetime": "1h",
      "ipv4": { // optional, also update IPv4 (A) records aquired from the command run at the specified interval. Expects one IPv4 per line in cleartext as output
        "interval": "3m",
        "command": "printf",
        "args": [
          "%s\\n",
          "192.168.0.12"
          "192.168.0.34"
        ],
        "lifetime": "10m"
      }
    }
    // ...
    // more task configurations if needed
    // ...
  },
  "credentials": {
    "example-project": { // name you will use to refer to this endpoint on the tasks
      "provider": "cloudflare", // one of the supported providers
      "settings": { // provider specific configuration
        "api_token": "CLOUDFLARETOKEN",
        "zone": "example.com",
        "ttl": "1h", // if proxied over cloudflare this will have no effect
        "proxied": true
      }
      "debounce_time": "10s", // optional, default 10s. time to wait before pushing updates
      "retry_time": "60s" // optional, default 60s. time to wait between retries on update error
    }
    // ...
    // more credentials if needed
    // ...
  }
}
```

## DDNS providers

The available DDNS providers are:

- [Cloudflare](https://www.cloudflare.com/application-services/products/dns/) (free plan compatible)
- [Duckdns](https://www.duckdns.org/) (provider only allows a single AAAA record)
- [Gravity](https://github.com/BeryJu/gravity) (hosted locally)

- :rocket: **If you’re comfortable coding, adding support for your preferred provider is a breeze**:
  - Use an existing provider in the `ddns/` directory (e.g., `cloudflare.go`) as a template.
  - Replace all instances of `cloudflare` with your provider’s name — case-sensitive!
  - Update the API logic in that file to match your provider's requirements.
  - Test your implementation thoroughly.
  - Verify that everything works correctly across multiple IP/prefix rotations.
  - Submit a pull request!

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

#### Roaming over IPv4
While IPv4 is not the focus of this project, you can stil leverage it to do the same for regular IPv4 public IPs.
```json
...
  "tasks": {
    "myhome": {
      "ipv4": {
        "interval": "3m",
        "command": "curl",
        "args": [
          "-s",
          "--ipv4",
          "ifconfig.me"
        ],
        "lifetime": "10m"
      }
...
```
For more advanced use cases just write a custom script that returns the IPv4s you need.