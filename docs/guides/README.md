# Guides

Each guide sets up one thing, from start to end. It says what you end up with and what you need, gives the whole configuration, and shows how to check that it works and what usually goes wrong. You don't need to read anything else first. A guide links to the rest of the documentation for the details.

Running ipv6ddns as the Home Assistant app? Start at the [guides for the app](home-assistant/README.md). They cover what is different in the app, and then send you back here.

| You want | Guide |
|---|---|
| Every machine on the network by name, `nas.lan.example.com`, from every device, with nothing set per host | [Every machine on the network by name](network-wide-names.md) |
| A public name for a device, `nas.example.com`, that follows it when the ISP changes the IPv6 prefix | [A public name for any device, over IPv6](public-ipv6-names.md) |
| The same name on a network with several ISPs, fiber and LTE or two providers, with the addresses of each, that fails over when one goes down | [Multi-WAN: a public name on a network with several ISPs](multi-wan.md) |
| Every device by name, in the AdGuard Home you already run | [Every device by name, in AdGuard Home](adguard-home.md) |
| Every device by name, in the Pi-hole you already run | [Every device by name, in Pi-hole](pi-hole.md) |
