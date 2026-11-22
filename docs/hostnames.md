# Names by the hosts' names

A task's name can be a template: instead of one fixed name, it makes a name for every host the task matches, from what the host calls itself. Every device on the LAN that announces a name gets one in DNS, with no task of its own, as `printer.home.arpa` or `laptop.home.arpa`. Names appear as hosts arrive, and go when they leave.

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
      zone: home.arpa

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

The hosts' names come from [discovery](discovery.md#names): mDNS, which is on by default, other protocols that carry names, or a plugin that reads your router's DHCP leases. The task's filter decides which hosts get a name, and which of their addresses it has, as for any task. The endpoint can be any credential: a [resolver](resolver.md) zone, a DNS provider, or both.

For a complete setup, see the guide [every machine on the network by name](guides/network-wide-names.md).

## The placeholders

| In the name | It is | The name's addresses |
|---|---|---|
| `{hostname}` | A name of the host | Those of every host with that name that the filter matches |
| `{n}` | The host's position among hosts with the same name, from 1, ordered by MAC. Needs `{hostname}` | The host's own |
| `{mac}` | The host's MAC, as twelve digits: `001122334455` | The host's own |

Write a template in quotes, because YAML reads a bare `{` as something of its own. You can add text around the placeholders: `"{hostname}.lan"`, `"{n}.{hostname}"`, `"{mac}.hosts"`, or `"*.{hostname}"` for a wildcard.

- **`{hostname}` on its own** is one name shared by every host called that. If two devices both say `printer`, `printer` has the addresses of both. A host with several names, say one from mDNS and another from the router's leases, gets each of them.
- **`{n}.{hostname}`** tells them apart: `1.printer`, `2.printer`, in MAC order. The number is the position among the hosts present right now, nothing more: when `1.printer` leaves, the other one becomes `1.printer`. A host that is alone with its name is `1.` too, so the name exists whether another one shows up or not.
- **`{mac}`** stays the same whatever comes and goes, and whatever the host calls itself. It needs no name at all, so `"{mac}.hosts"` works even with every name protocol turned off.

## A name written wins

Any device on the network can claim to be called `nas` or `router`. So a name written in the configuration always beats a template:

- **A task's fixed name** at the same endpoint keeps its own task's addresses only. A host that calls itself the same is left out of it, and the log says so once.
- **A resolver zone's record** stays as written. A host with the same name doesn't change its answer.

A name that isn't in the configuration has no such protection. If you created a record by hand at a provider, say `www`, a template `"{hostname}"` takes it over as soon as a host on the network says it's called `www`: the record gets that host's addresses, and the others are removed. To keep the hosts' names apart from your own records, put something around the placeholder, as `"{hostname}.lan"` or `"{hostname}.hosts"`.

For a name that matters, write it in a task, with a filter by MAC, and leave templates for everything else.

Names are cleaned before use: each becomes one DNS label of lower-case letters, digits and hyphens. A cleaned name is never `*` and never contains a dot.

## When a host leaves

A host's names lose its addresses when discovery lets the host go, at the end of its [lifetime](discovery.md#lifetimes). A name left with no address has its records removed, and is then forgotten. A resolver stops answering it straight away, and from then on asks its upstream servers, as for any name it doesn't have.

What ipv6ddns can't know about is names it created before it was started. If a host left while ipv6ddns wasn't running, its records stay at a DNS provider, and nothing removes them. The records of hosts that are still there are corrected as they're found. A resolver doesn't have this problem, since it keeps its names in memory. If a name must be exactly right at a provider across restarts, write it in a task.

## What it doesn't do

- **Sources:** a task's [`sources`](sources.md), addresses without a MAC, only go to the names written in it. A template's names belong to hosts, and a source's addresses don't belong to any host.
- **Home Assistant entities:** the [Home Assistant device](home-assistant-integration.md) has an entity for each name written in the configuration, but none for a template's names, which aren't known when it starts.
- **Rate limits:** each name from a template is updated on its own. On a network with many named hosts, that's as many updates when ipv6ddns starts, which a provider that limits requests may slow down. The [retry](reference/configuration.md) takes care of any that are refused.

## The errors

| The mistake | The error |
|---|---|
| A placeholder that doesn't exist | `task lan: endpoint home: the name "{host}": {host} is no placeholder: they are {hostname}, {n} and {mac}` |
| `{n}` without `{hostname}` | `task lan: endpoint home: the name "{n}.lan": {n} is the place of a host among those of one name: it needs {hostname} beside it, as {n}.{hostname}` |
| A brace on its own | `task lan: endpoint home: the name "nas}": a brace that is of no placeholder: they are {hostname}, {n} and {mac}` |
| `{hostname}` with nothing that learns names | `task lan: endpoint home: the name "{hostname}" is of the hosts' names, which nothing learns: it needs a protocol of discovery.protocols that does, as mdns, or a plugin` |
