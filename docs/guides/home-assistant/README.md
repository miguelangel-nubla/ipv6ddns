# Guides for the Home Assistant add-on

These are the [guides](../README.md) for ipv6ddns when it runs as the Home Assistant add-on. The add-on is the same program as any other install, with the same configuration. Three things differ: where the configuration file is, how you edit it, and how you see what ipv6ddns does.

The steps below cover those three things, for every guide. Each guide for the add-on then has only the steps that are specific to the add-on, if there are any. For everything else, it sends you to the plain guide.

## The add-on's side, for every guide

1. **Install the add-on**, and start it once, as [its documentation](../../../homeassistant/addon/DOCS.md#installation) says. It writes a starting `config.yaml`. Until you add tasks, it only discovers.
2. **Edit `config.yaml`** with the File editor or Studio Code Server add-on. The file is in the add-on's folder, `addon_configs/<id>_ipv6ddns` (`app_configs` in recent versions of Home Assistant).
3. **Keep what the starting file has.** It has three blocks:
   - `webserver` serves the add-on's page.
   - `homeassistant` makes ipv6ddns a device in Home Assistant.
   - `discovery` leaves out Home Assistant's own containers.

   Add a guide's blocks to the file, beside these. When a guide has a block that the file already has, such as `discovery`, put the guide's keys into the existing block. A key written twice is an error, and the add-on doesn't start.
4. **Keep secrets in files beside it.** To the add-on, a file next to `config.yaml` is `/config/<file>`. So put a token in a file, and write `${file:/config/cloudflare_token}` in `config.yaml`, not the token itself.
5. **Restart the add-on** after each change. If something is wrong with the file, the *Log* tab says what, and where.
6. **See what it does** on the add-on's page, *Open Web UI*. It shows the hosts found, the names, and their updates. This page is the web report that the plain guides refer to. The plain guides have it at `http://<machine>:8053`, but the add-on serves it to Home Assistant only.

## The guides

| You want | Start here |
|---|---|
| Every machine on the network by name, `nas.home.arpa`, from every device | [Network-wide names, the add-on's side](network-wide-names.md) |

To give Home Assistant itself a public name, such as `ha.example.com`, see the add-on's own documentation: [publishing Home Assistant itself](../../../homeassistant/addon/DOCS.md#publishing-home-assistant-itself).
