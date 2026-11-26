# Guides for the Home Assistant app

These are the [guides](../README.md) for ipv6ddns when it runs as the Home Assistant app. The app is the same program as any other install, with the same configuration. Three things differ: where the configuration file is, how you edit it, and how you see what ipv6ddns does.

The steps below cover those three things, for every guide. Each guide for the app then has only the steps that are specific to the app, if there are any. For everything else, it sends you to the plain guide.

## The app's side, for every guide

1. **Install the app**, and start it once, as [its documentation](../../../homeassistant/addon/DOCS.md#installation) says. It writes a starting `config.yaml`. Until you add tasks, it only discovers.
2. **Edit `config.yaml`** with the File editor or Studio Code Server app. The file is in the app's folder, `addon_configs/<id>_ipv6ddns` (`app_configs` in recent versions of Home Assistant).
3. **Keep what the starting file has.** It has four blocks:
   - `listeners` and `webservers` serve the app's page.
   - `homeassistant` makes ipv6ddns a device in Home Assistant.
   - `discovery` leaves out Home Assistant's own containers.

   Add a guide's blocks to the file, beside these. When a guide has a block that the file already has, such as `discovery`, put the guide's keys into the existing block. A key written twice is an error, and the app doesn't start.
4. **Keep secrets in files beside it.** To the app, a file next to `config.yaml` is `/config/<file>`. So put a token in a file, and write `${file:/config/cloudflare_token}` in `config.yaml`, not the token itself.
5. **Restart the app** after each change. If something is wrong with the file, the *Log* tab says what, and where.
6. **See what it does** on the app's page, *Open Web UI*. It shows the hosts found, the names, and their updates. This page is the web report that the plain guides refer to. The plain guides have it at `http://<machine>:8053`, but the app serves it to Home Assistant only.

## The guides

| You want | Start here |
|---|---|
| Every machine on the network by name, `nas.lan.example.com`, from every device | [Network-wide names, the app's side](network-wide-names.md) |
| A public name for a device, or for Home Assistant, that follows it when the ISP changes the IPv6 prefix | [A public name over IPv6, the app's side](public-ipv6-names.md) |
| Every device by name, in the AdGuard Home app you already run | [AdGuard Home, the app's side](adguard-home.md) |

For a Pi-hole on another machine, follow [every device by name, in Pi-hole](../pi-hole.md). In the app, the password's file there is `${file:/config/pihole_password}`.

To give Home Assistant itself a public name, such as `ha.example.com`, see the app's own documentation: [publishing Home Assistant itself](../../../homeassistant/addon/DOCS.md#publishing-home-assistant-itself).
