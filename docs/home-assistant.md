# Home Assistant add-on

ipv6ddns runs as a Home Assistant add-on, from the [add-on repository](https://github.com/miguelangel-nubla/hassio-repository), on Home Assistant OS and Supervised installations, amd64 and aarch64. Its documentation, as the add-on store shows it, is [DOCS.md](../homeassistant/addon/DOCS.md).

## How it is made

- [`homeassistant/addon/`](../homeassistant/addon/) is the add-on, as the add-on repository publishes it: its manifest, `config.yaml`, its pages and icons.
- Its image, `ghcr.io/miguelangel-nubla/ipv6ddns-addon`, is the image of ipv6ddns with a start, [`homeassistant/run.sh`](../homeassistant/run.sh), that writes a [starting configuration](../homeassistant/starter.config.yaml) the first time, and runs ipv6ddns with it: the add-on has no options of its own, and gives the program no other flag. Both come from [`Dockerfile.goreleaser`](../Dockerfile.goreleaser), each release, with the version for its tag, as the add-on pulls it.
- A release tells the add-on repository, which publishes the new version to Home Assistant. That needs the secret `DISPATCH_TOKEN` in this repository: a token allowed to dispatch to the add-on repository.
- The add-on is on the host's network, with `NET_RAW`, so discovery works as on the host; the starting configuration leaves out Home Assistant's own bridges. Its report is served at the host's address on the Supervisor's network, `172.30.32.1`, which the Supervisor gives as the add-on's address, for the add-on's page, and not to the network outside: `webserver.listen` of the starting configuration says so, at the port that is the manifest's `ingress_port`.
- Tested on Home Assistant OS 18.4, Supervisor 2026.11.0, in QEMU on aarch64: installed from the add-on repository, it starts, writes its configuration, discovers, and its page, `/healthz` and `/status.json` work through ingress.
