# A public name for any device, over IPv6, from Home Assistant

The app can keep a public name, such as `nas.example.com`, for any device on your network, and one for Home Assistant itself. The names follow the devices when your ISP changes your IPv6 prefix. Nothing is installed on the devices.

This page is the app's side of the guide [a public name for any device, over IPv6](../public-ipv6-names.md). It has the configuration as it goes in the app's file, and what Home Assistant adds. The firewall and the checks are the same as on any install, so those steps send you to the plain guide. The steps that every app guide shares are in [the app's side, for every guide](README.md#the-apps-side-for-every-guide).

## The configuration

Put the Cloudflare token in a file `cloudflare_token`, beside `config.yaml`. To the app, that file is `/config/cloudflare_token`.

This is the whole `config.yaml`: the blocks of the starting file, with the guide's configuration added to them. The examples use `example.com` for the domain, and `00:11:22:33:44:55` for the device's MAC. Use your own. The app's page lists every host found, with its MAC.

```yaml
credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: ${file:/config/cloudflare_token}
      zone: example.com
      ttl: 5m
      proxied: false

tasks:
  nas:
    filter:
      - mac:
          address: "00:11:22:33:44:55"
        ip:
          type:
            - global
    endpoints:
      cloudflare:
        - nas              # nas.example.com
  homeassistant:
    filter:
      - self: true         # this machine: Home Assistant, and the apps on its network
        ip:
          type:
            - global
            - "!temporary"
    endpoints:
      cloudflare:
        - ha               # ha.example.com

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
  exclude_interfaces:
    - hassio
    - docker0
    - "veth*"
```

This configuration differs from the plain guide's in three ways:

- **The `homeassistant` task** gives Home Assistant itself a public name. `self: true` takes the addresses of the machine the app runs on, so there is no MAC to look up. For its own machine, the app knows which addresses are temporary, and `"!temporary"` leaves them out. Leave the task out if you don't want Home Assistant reached from outside.
- **The token's file** is `/config/cloudflare_token`, not a name alone.
- **There is no new `webservers` block.** The plain guide's web report is the app's page here, and the `listeners` and `webservers` blocks of the starting file already serve it.

Restart the app. Its page lists both names under `DNS`, each with its addresses and its last update.

## Which address, and the firewall

A device can have several global addresses. The plain guide says [which of the device's addresses](../public-ipv6-names.md#which-of-the-devices-addresses) a name can take, and how to [open the firewall](../public-ipv6-names.md#open-the-firewall) on your router.

For Home Assistant itself, the port to allow is `8123`, to the Home Assistant machine. A Home Assistant that the internet can reach needs a strong password and two-factor authentication, at the least.

## Check that it works

Open the app's page, *Open Web UI*. Under `DNS`, it lists each name with its addresses. A name whose update fails is in red, with the provider's error.

From any computer, run the plain guide's [checks](../public-ipv6-names.md#check-that-it-works): `dig AAAA nas.example.com @1.1.1.1`.

The ipv6ddns device in Home Assistant has an entity for each name, here `nas` and `ha`, with the name's addresses and its last update.

## More

- [Common problems](../public-ipv6-names.md#common-problems).
- [IPv4 too](../public-ipv6-names.md#ipv4-too), for clients without IPv6.
- [Another DNS provider](../public-ipv6-names.md#another-dns-provider). In the app, a token's file there is `${file:/config/duckdns_token}`.
- [Publishing Home Assistant itself](../../../homeassistant/addon/DOCS.md#publishing-home-assistant-itself), in the app's documentation: the names of your other apps, on the same task.
