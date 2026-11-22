# Names by the hosts' names

A task's name can be a template. Instead of one fixed name, a template makes a name for every host the task matches, from what the host calls itself. Every device on the LAN that announces a name gets one in DNS, such as `printer.lan.example.com` or `laptop.lan.example.com`, with no task of its own. Names appear as hosts arrive, and go when they leave.

```yaml
resolvers:
  lan:
    listen: 192.168.1.0/24
    upstream:
      - 192.168.1.1

credentials:
  home:
    provider: resolver
    settings:
      zone: lan.example.com

tasks:
  lan:
    filter:
      - ip:
          type:
            - ula
    endpoints:
      home:
        - "{hostname}"
        - "{n}.{hostname}"
```

How the parts fit together:

- **The hosts' names** come from [discovery](discovery.md#names): mDNS, which is on by default, other protocols that carry names, or a plugin that reads your router's DHCP leases.
- **The task's filter** decides which hosts get a name, and which of each host's addresses the name has, as it does for any task.
- **The endpoint** can be any credential: a [resolver](resolver.md) zone, a DNS provider, or both.

The zone here is a subdomain of a domain you own. Without one, use `home.arpa`: see [choosing a domain](resolver.md#choosing-a-domain).

For a complete setup, see the guide [every machine on the network by name](guides/network-wide-names.md).

## The placeholders

| In the name | It is | The name's addresses |
|---|---|---|
| `{hostname}` | A name of the host | Those of every host with that name that the filter matches |
| `{n}` | The host's position among hosts with the same name, from 1, ordered by MAC. Needs `{hostname}` | The host's own |
| `{mac}` | The host's MAC, as twelve digits: `001122334455` | The host's own |

Write a template in quotes, because YAML gives a bare `{` a meaning of its own. You can add text around the placeholders: `"{hostname}.lan"`, `"{n}.{hostname}"`, `"{mac}.hosts"`, or `"*.{hostname}"` for a wildcard.

- **`{hostname}` on its own** is one name shared by every host called that. If two devices both say `printer`, `printer` has the addresses of both. A host with several names, say one from mDNS and another from the router's leases, gets each of them.
- **`{n}.{hostname}`** tells hosts with the same name apart: `1.printer`, `2.printer`, in MAC order. The number is only the host's position among the hosts present right now. When `1.printer` leaves, the other one becomes `1.printer`. A host that is alone with its name is `1.` too, so the name exists whether or not another host shows up.
- **`{mac}`** stays the same whichever hosts come and go, and whatever the host calls itself. It needs no name at all, so `"{mac}.hosts"` works even with every name protocol turned off.

## A name written wins

Any device on the network can claim to be called `nas` or `router`. So a name written in the configuration always beats a template:

- **A task's fixed name** keeps only its own task's addresses. A host that calls itself the same, and would get that name from a template at the same endpoint, is left out of it. The log says so once.
- **A resolver zone's record** stays as written. A host with the same name doesn't change its answer.

A name that isn't in the configuration has no such protection. Say you created a record by hand at a provider, `www`. A template `"{hostname}"` takes it over as soon as a host on the network says it's called `www`. The record gets that host's addresses, and the addresses you gave it are removed. To keep the hosts' names apart from your own records, put something around the placeholder, such as `"{hostname}.lan"` or `"{hostname}.hosts"`.

For a name that matters, write it in a task, with a filter by MAC, and leave templates for everything else.

Names are cleaned before use. Each becomes one DNS label of lower-case letters, digits and hyphens. A cleaned name is never `*` and never contains a dot.

## When a host leaves

When discovery lets a host go, at the end of its [lifetime](discovery.md#lifetimes), the host's names lose its addresses. A name left with no address has its records removed, and is then forgotten. A resolver stops answering the name straight away. From then on it asks its upstream servers for it, as for any name it doesn't have.

ipv6ddns can't know about the names it created before it was last started. If a host left while ipv6ddns wasn't running, the host's records stay at the DNS provider, and nothing removes them. The records of hosts that are still there are corrected as the hosts are found. A resolver doesn't have this problem, since it keeps its names in memory. If a name must be exactly right at a provider across restarts, write it in a task.

## What it doesn't do

- **Sources:** the addresses of a task's [`sources`](sources.md), which have no MAC, go only to the names written in the task. A template's names belong to hosts, and a source's addresses don't belong to any host.
- **Home Assistant entities:** the [Home Assistant device](home-assistant-integration.md) has an entity for each name written in the configuration. It has none for a template's names, which aren't known when the device starts.
- **Rate limits:** each name from a template is updated on its own. On a network with many named hosts, that means as many updates when ipv6ddns starts, and a provider that limits requests may slow them down. The [retry](reference/configuration.md) takes care of any update that is refused.

## The errors

| The mistake | The error |
|---|---|
| A placeholder that doesn't exist | `task lan: endpoint home: the name "{host}": {host} isn't a placeholder: use {hostname}, {n} or {mac}` |
| `{n}` without `{hostname}` | `task lan: endpoint home: the name "{n}.lan": {n} numbers the hosts that share a name, so it needs {hostname} too, as {n}.{hostname}` |
| A brace on its own | `task lan: endpoint home: the name "nas}": a brace that isn't part of a placeholder: use {hostname}, {n} or {mac}` |
| `{hostname}` with nothing that learns names | `task lan: endpoint home: the name "{hostname}" uses the hosts' names, but nothing learns them: turn on a protocol under discovery.protocols that does, as mdns, or add a plugin` |
