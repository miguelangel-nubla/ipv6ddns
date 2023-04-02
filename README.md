# IPv6 DDNS Updater

This utility discovers the IPv6 addresses of specific hosts in your network and updates DNS records dynamically. [Details](#what-does-this-do)

If you have a special use case: [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc)

## Installation

Download the [latest release](https://github.com/miguelangel-nubla/ipv6ddns/releases/latest) for your architecture.

### Or build from source

Ensure you have Go installed on your system. If not, follow the instructions on the official [Go website](https://golang.org/doc/install) to install it. Then:
```
go install github.com/miguelangel-nubla/ipv6ddns
```

## Usage

Adjust the configuration on config.json and run the binary with the desired flags:

>:warning: This utility needs to be executed as a superuser to be able to listen for IPv6 ICMP packets.
```
sudo ipv6ddns [flags]
```

### Flags

- `-config_file` (default "config.json"): Config file to use.
- `-log_level` (default "info"): Set the logging level (debug, info, warn, error, fatal, panic).
- `-storm_delay` (default "60s"): Time to allow finishing storm of host discoveries before updating the DDNS record.
- `-ttl` (default "4h"): Time to keep a discovered host entry in the table after it has been last seen. This is not the TTL of the DDNS record.
- `-live` (default false): Show the current state live on the terminal.

Depending on your IPv6 network configuration, you will need to allow outside access to the hosts you want to expose.

The easiest way is to either specify allowed subnets or simply allow by destination MAC address.

## Configuration

This is the structure of the `config.json` file:

```
{ 
  "tasks": {
    "load_balancer_for_web_app": { // whichever name you like for this task
      "subnets": ["2000::/3"], // only IPv6 addresses on these subnets will be updated. "2000::/3" is any GUA.
      "mac_address": ["00:11:22:33:44:55", "00:11:22:33:44:56"], // MAC addresses of the hosts to look for
      "endpoints": {
        "example-project": [ // name of the endpoint to use for this task, as configured on the credentials section at the bottom
          "test-webapp.example.com" // domain name whose AAAA records will be kept in sync
        ]
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
        "email": "email@example.com",
        "api_token": "CLOUDFLARETOKEN",
        "zone_name": "example.com",
        "ttl": "1h", // if proxied over cloudflare this will have no effect
        "proxied": true
      }
    }
    // ...
    // more credentials if needed
    // ...
  }
}
```

## DDNS providers

The available DDNS providers are:

- Cloudflare
- Duckdns (provider only allows a single AAAA record)

- :rocket: **Adding your preferred provider is easy**:
  - Take a provider from `ddns/` such as cloudflare.go as a template.
  - Replace every reference to cloudflare with the new provider. This is case-sensitive.
  - Replace the API calls with the ones your provider need.
  - Test.
  - Create a PR!

---

# What does this do?

## The problem
Having a domain name `my-web.example.com` point to your application on an IPv6 network is both simpler and more challenging than doing it with regular IPv4.

The classic method of directing traffic to your public IP address (i.e., your router) and then using NAT is no longer a good idea, nor necessary.

IPv6 addresses are globally routable, which is nice, but you will need to know the exact IP, as different machines or even containers on the same host (and even different applications) will have different "public" IPs, or GUAs in IPv6 terminology.

In this scenario DNS names become almost mandatory, good luck trying to remember and type a different `https://[2001:0db8:85a3:0000:8a2e:0370:7334:abcd]` to access each one of your hosts.

Technically, IPv6 addresses could be static, but part of the beauty of IPv6 is the ability to use and rotate multiple different IP addresses on demand. Even if you don't want to, some ISPs change your IPv6 prefix on router reboot or periodically.

## Rationale
You might be thinking well, I will just run a DDNS updater on my server? It turns out that may not be really an option, remember each application has its own, *dynamic* IPv6? How do you indicate which IP should the DNS record point to? Does that mean the way to do that is to run the updater on the same container as your web server?

Unfortunately yes. That is not a great idea. Aside from the inconvenience of forking and using your own container images, there will be systems that you will not be able to modify. Think about a device on your network that has no way of running a custom executable, like an appliance, or an IP camera.

Wouldn't it be nice to have a utility anywhere on your network that detects the IPv6 of your desired hosts, identifies when they change, and updates the relevant DNS records accordingly?

## The solution
This utility scans the network for the IPv6s of the hosts you want to expose, identified by their MAC address, and updates the corresponding DNS records automatically. This works for _all your network_, having the configuration and your credentials in a single place.

---

# Other nice usages

### Roaming over multiple IPv6 networks
This utility allows you to move between IPv6 networks and to maintain inbound connectivity.
You can have as many IPv6 addresses from different ISPs as you like and the AAAA records for your domain will be kept in sync.

For example, you can have a fiber connection, a backup LTE connection, and Starlink on your roof. Your domain will have AAAA records for every WAN connection, inbound WAN failover will simply work.
