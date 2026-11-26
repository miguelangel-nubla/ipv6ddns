# Every device by name, in the AdGuard Home app

You run the AdGuard Home app on Home Assistant as the DNS server of your network. The ipv6ddns app can write the name of every device into it, such as `nas.lan.example.com`, and keep the names right as addresses change. The two apps don't compete for port 53, because ipv6ddns answers no DNS here.

This page is the app's side of the guide [every device by name, in AdGuard Home](../adguard-home.md). It has the configuration as it goes in the app's file. The checks and everything else are the same as on any install, so those steps send you to the plain guide. The steps that every app guide shares are in [the app's side, for every guide](README.md#the-apps-side-for-every-guide).

## The configuration

This is the whole `config.yaml`: the blocks of the starting file, with the guide's configuration added to them.

```yaml
credentials:
  adguard:
    provider: adguardhome
    settings:
      address: http://127.0.0.1:45158
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
      adguard:
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
      adguard:
        - homeassistant    # homeassistant.lan.example.com

# From the starting file: keep these.
listeners:
  app:
    listen:
      - http://172.30.32.1:8053
webservers:
  main:
    listeners:
      - app

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

This configuration differs from the plain guide's in four ways:

- **The address is `http://127.0.0.1:45158`, with no user.** Both apps are on the Home Assistant machine's own network. The AdGuard Home app has its web interface there, on that port, and asks for no login: Home Assistant does that for it.
- **The `homeassistant` task** names Home Assistant itself. `self: true` takes the addresses of the machine the app runs on, so the name doesn't depend on Home Assistant saying its name.
- **`discovery.ipv4`** goes into the `discovery` block the file already has, beside `exclude_interfaces`.
- **There is no new `webservers` block.** The plain guide's web report is the app's page here, and the `listeners` and `webservers` blocks of the starting file already serve it.

Restart the app. Its page lists the names under `DNS`, each with its addresses and its last update.

## Check that it works

In the AdGuard Home app, open *Filters → DNS rewrites*. Each name is there, once for each of its addresses.

From any device on the network, run the plain guide's [checks](../adguard-home.md#check-that-it-works): `dig printer.lan.example.com`.

Home Assistant itself resolves these names when it uses AdGuard Home for DNS. To have it do so, in the *Terminal & SSH* app, run `ha dns options --servers dns://172.30.32.1`, the AdGuard Home app's address on Home Assistant's internal network. `ha dns reset` undoes it. The other way, and what to know about both, is in [point Home Assistant at it](network-wide-names.md#point-home-assistant-at-it). Write the whole name, `printer.lan.example.com`, because Home Assistant doesn't look up a short name such as `printer`.

## More

- [What to know](../adguard-home.md#what-to-know): what ipv6ddns touches in AdGuard Home, and what it leaves alone.
- [Common problems](../adguard-home.md#common-problems).
- [A name that matters](../network-wide-names.md#a-name-that-matters): a fixed name for a device, by its MAC.
