# Every machine on the network by name, from Home Assistant

The Home Assistant machine is always on, and already on the network, so it makes a good DNS server for the network. The app answers `nas.lan.example.com`, `printer.lan.example.com`, and Home Assistant's own name, for every device on the network.

This page is the app's side of the guide [every machine on the network by name](../network-wide-names.md). It has the configuration as it goes in the app's file, and how to check the result from Home Assistant. Pointing the network at the DNS server is the same as on any install, so that step sends you to the plain guide. The steps that every app guide shares are in [the app's side, for every guide](README.md#the-apps-side-for-every-guide).

## The configuration

This is the whole `config.yaml`: the blocks of the starting file, with the guide's configuration added to them. The examples use `192.168.1.0/24` for the LAN, `192.168.1.1` for the router, and `192.168.1.2` for the Home Assistant machine. Use your own.

```yaml
resolvers:
  lan:
    listen:
      - 192.168.1.0/24     # Home Assistant's address on the LAN, port 53
      - 172.30.32.1        # and on the internal network, for Home Assistant and its apps
    upstream:
      - 192.168.1.1        # the rest of the world's names: your router, or 1.1.1.1

credentials:
  home:
    provider: resolver
    settings:
      zone: lan.example.com

tasks:
  lan:
    filter:
      - ip:
          family:
            - 4
            - 6
          type:
            - "!link_local"
    endpoints:
      home:
        - "{hostname}"     # printer.lan.example.com
        - "{n}.{hostname}" # 1.printer.lan.example.com, 2.printer.lan.example.com when two say printer
  homeassistant:
    filter:
      - self: true         # this machine: Home Assistant, and the apps on its network
        ip:
          family:
            - 4
            - 6
          type:
            - "!link_local"
    endpoints:
      home:
        - homeassistant    # homeassistant.lan.example.com

# From the starting file: keep these.
webserver:
  listen: 172.30.32.1:8053

log_level: info

homeassistant:
  listen: 6053
  key_provisioning: true

discovery:
  ipv4:
    enabled: true          # added: the IPv4 addresses too
  exclude_interfaces:
    - hassio
    - docker0
    - "veth*"
```

This configuration differs from the plain guide's in three ways:

- **The `homeassistant` task** names Home Assistant itself. `self: true` takes the addresses of the machine the app runs on, so the name doesn't depend on Home Assistant saying its name. The apps on the host's network, such as Mosquitto or Node-RED, are at the same addresses. If you want names for them, such as `mqtt`, add the names under the same endpoint.
- **`discovery.ipv4`** goes into the `discovery` block the file already has, beside `exclude_interfaces`.
- **There is no new `webserver` block.** The plain guide's web report is the app's page here, and the `webserver` block of the starting file already serves it.

The resolver listens on port 53 at two addresses:

- Home Assistant's address on the LAN, for the devices.
- `172.30.32.1` on Home Assistant's internal network, for Home Assistant and the apps.

The Supervisor's own DNS is at `172.30.32.3`, so the two don't get in each other's way. The configuration leaves `allow` out, because its default is the networks of both addresses.

Restart the app. Its *Log* says `resolver lan listening on 192.168.1.2:53, 172.30.32.1:53`.

Home Assistant also announces itself as `homeassistant` over mDNS, so the `lan` task may find a host with that name. The name written in the `homeassistant` task wins, and the log says so once: `homeassistant.lan.example.com is written in the configuration, so it keeps its own addresses`. That is expected.

## Point the network at it

In the router's DHCP settings, give the devices the Home Assistant machine's address as their DNS server. The plain guide has the details: [point the network at it](../network-wide-names.md#point-the-network-at-it).

## Point Home Assistant at it

Home Assistant and its apps look names up through the Supervisor's DNS, on the internal network. The Supervisor's DNS asks the machine's DNS servers, unless you've given it servers of its own.

Point it at the app. An integration that you set up by host name, such as `printer.lan.example.com`, then works as it does on the rest of the network. There are two ways:

- **Set the machine's DNS server** to `192.168.1.2`, in *Settings → System → Network*. Home Assistant, the apps and the machine itself then use the app. If the machine gets its address from the router's DHCP, the step above already gave it the app as its DNS server, and there's nothing to do.
- **Set it for Home Assistant and the apps only.** In the *Terminal & SSH* app, run `ha dns options --servers dns://172.30.32.1`. The machine keeps its own DNS servers. `ha dns reset` undoes the change.

Give only the app's address. With a second server, such as the router, some lookups go to that server instead, and the local names fail now and then.

While the app is stopped, the local names don't resolve. If you set the machine's DNS server to the app, the machine can't look up any name either until the app is started again, and that includes the names it needs for updates. The second way leaves the machine's own lookups alone.

## Check that it works

Open the app's page, *Open Web UI*. Under `Resolvers`, it lists the zone and how many names the zone has. Under `DNS`, it lists each name with its addresses.

From any device on the network, run the plain guide's [checks](../network-wide-names.md#check-that-it-works): `dig printer.lan.example.com`, `dig homeassistant.lan.example.com`.

To check from Home Assistant's side, use the *Terminal & SSH* app, which looks names up the way Home Assistant does. `nslookup printer.lan.example.com` answers with the printer's addresses.

The ipv6ddns device in Home Assistant has an entity for each name written in the configuration, such as `homeassistant`, with the name's addresses and its last update. The names made for the hosts, from `{hostname}`, have no entities, because they come and go.

## More

- [A name that matters](../network-wide-names.md#a-name-that-matters): a fixed name for a device, by its MAC.
- [Common problems](../network-wide-names.md#common-problems).
- [Your router's DNS instead](../network-wide-names.md#your-routers-dns-instead). In the app, the password file there is `${file:/config/mikrotik_password}`.
