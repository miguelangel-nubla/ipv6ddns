# Guides for the Home Assistant add-on

These are the [guides](../README.md) for ipv6ddns run as the Home Assistant add-on. ipv6ddns is the same program there, with the same configuration as any other install. What differs is where the file is, how you edit it, and how you see what it does. That part is here once. Each guide then has the steps that are the add-on's own, where it has any, and the rest is the plain guide.

## The add-on's side, for every guide

1. **Install the add-on**, and start it once, as [its documentation](../../../homeassistant/addon/DOCS.md#installation) says. It writes a starting `config.yaml` and only discovers until you add tasks.
2. **Edit `config.yaml`** in the add-on's folder, `addon_configs/<id>_ipv6ddns` (`app_configs` in recent versions of Home Assistant), with the File editor or Studio Code Server add-on.
3. **Keep what the starting file has.** Its `webserver` block serves the add-on's page, its `homeassistant` block makes ipv6ddns a device in Home Assistant, and its `discovery` block leaves out Home Assistant's own containers. A guide's blocks go into the file beside them. Where a guide has a block the file already has, as `discovery`, put its keys in the one that is there: a key written twice is an error, and the add-on doesn't start.
4. **Keep secrets in files beside it.** A file next to `config.yaml` is `/config/<file>` to the add-on: write a token as `${file:/config/cloudflare_token}`, not into `config.yaml` itself.
5. **Restart the add-on** after each change. The *Log* tab says what is wrong with the file, if anything is, and where.
6. **See what it does** on the add-on's page, *Open Web UI*: the hosts found, the names, and their updates. It is the web report the plain guides refer to, at `http://<machine>:8053` there. The add-on's is served to Home Assistant only.

## The guides

| You want | Start here |
|---|---|
| Every machine on the network by name, `nas.home.arpa`, from every device | [Network-wide names, the add-on's side](network-wide-names.md) |

Home Assistant itself at a public name, as `ha.example.com`, is in the add-on's own documentation: [publishing Home Assistant itself](../../../homeassistant/addon/DOCS.md#publishing-home-assistant-itself).
