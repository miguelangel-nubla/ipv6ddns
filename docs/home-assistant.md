# Home Assistant add-on

ipv6ddns runs as a Home Assistant add-on, installed from the [add-on repository](https://github.com/miguelangel-nubla/hassio-repository), on Home Assistant OS and Supervised installations, on amd64 and aarch64. Its user documentation, as the add-on store shows it, is [DOCS.md](../homeassistant/addon/DOCS.md). This page is about how the add-on is built.

## How it is made

- **The add-on itself** is [`homeassistant/addon/`](../homeassistant/addon/), as the add-on repository publishes it: its manifest, `config.yaml`, its pages and its icons.
- **Its image**, `ghcr.io/miguelangel-nubla/ipv6ddns-addon`, is the ipv6ddns image with a different entry point, [`homeassistant/run.sh`](../homeassistant/run.sh). The first time, it writes a [starting configuration](../homeassistant/starter.config.yaml); then it runs ipv6ddns with it. The add-on has no options of its own, and passes the program no other flag. Both images are built from [`Dockerfile.goreleaser`](../Dockerfile.goreleaser) at each release, tagged with its version, which is what the add-on pulls.
- **Publishing:** a release notifies the add-on repository, which publishes the new version to Home Assistant. This needs the secret `DISPATCH_TOKEN` in this repository: a token allowed to dispatch to the add-on repository.
- **Network:** the add-on runs on the host's network with `NET_RAW`, so discovery works as it would on the host. The starting configuration leaves out Home Assistant's own bridges.
- **The add-on's page:** the report is served at the host's address on the Supervisor's network, `172.30.32.1`, which the Supervisor uses as the add-on's address. It isn't served to the outside network. The starting configuration's `webserver.listen` says this, at the port given as the manifest's `ingress_port`.
- **Tested** on Home Assistant OS 18.4 with Supervisor 2026.11.0, in QEMU on aarch64: installed from the add-on repository, it starts, writes its configuration and discovers, and its page, `/healthz` and `/status.json` work through ingress.
