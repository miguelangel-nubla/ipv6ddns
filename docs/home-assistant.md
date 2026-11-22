# Home Assistant app

ipv6ddns runs as a Home Assistant app. You install it from the [app repository](https://github.com/miguelangel-nubla/hassio-repository), on Home Assistant OS and Supervised installations, on amd64 and aarch64.

To use the app, read its user documentation, [DOCS.md](../homeassistant/addon/DOCS.md), which is what the app store shows. This page is about how the app is built.

## How it is made

- **The app itself** is the folder [`homeassistant/addon/`](../homeassistant/addon/), which the app repository publishes as it is: the manifest (`config.yaml`), the pages and the icons.
- **Its image**, `ghcr.io/miguelangel-nubla/ipv6ddns-addon`, is the ipv6ddns image with a different entry point, [`homeassistant/run.sh`](../homeassistant/run.sh). On its first start, the script writes a [starting configuration](../homeassistant/starter.config.yaml). Then it runs ipv6ddns with that file. The app has no options of its own, and passes the program no other flag. Both images are built from [`Dockerfile.goreleaser`](../Dockerfile.goreleaser) at each release and tagged with the release's version, which is the tag the app pulls.
- **Publishing:** a release notifies the app repository, which publishes the new version to Home Assistant. This needs the secret `DISPATCH_TOKEN` in this repository. It is a token that is allowed to dispatch to the app repository.
- **Network:** the app runs on the host's network with `NET_RAW`, so discovery works as it would on the host. The starting configuration excludes Home Assistant's own bridges from discovery.
- **The app's page:** the report is served at `172.30.32.1`, the host's address on the Supervisor's network, which the Supervisor uses as the app's address. The report isn't served to the outside network. The starting configuration sets this in `webserver.listen`, with the port that the manifest gives as `ingress_port`.
- **Tested** on Home Assistant OS 18.4 with Supervisor 2026.11.0, in QEMU on aarch64. Installed from the app repository, the app starts, writes its configuration and discovers hosts. Its page, `/healthz` and `/status.json` work through ingress.
