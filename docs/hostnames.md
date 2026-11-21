# Names by the hosts' names

A task's host name can be a template: a name for each host its filters match, by what the host is called. With it, every host of the LAN that says its name has one in DNS, with no task of its own: `printer.home.arpa`, `laptop.home.arpa`, as they come and go.

```yaml
discovery:
  hostnames:
    enabled: true
  protocols:
    mdns:
      enabled: true

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

The hosts' names are those [discovery learns](discovery.md#names), with `discovery.hostnames` and a protocol that learns them, or a plugin that reads its router's leases. The filter says which hosts, and which of their addresses, as for any task. The endpoint is any credential: a [resolver](resolver.md)'s zone, a DNS provider, or both.

## The placeholders

| In the name | It is | Its addresses |
|---|---|---|
| `{hostname}` | A name of the host | Alone in the name: those of every host called so, that the filter matches |
| `{n}` | The host's place among those of its name, from 1, by MAC: needs `{hostname}` | The host's |
| `{mac}` | The host's MAC, its twelve digits, as `001122334455` | The host's |

A template is written in quotes, as YAML takes a `{` for something of its own. It can have more around the placeholders, as `"{hostname}.lan"`, `"{n}.{hostname}"`, `"{mac}.hosts"`, or `"*.{hostname}"` for a wildcard.

- **`{hostname}`**, alone, is one name for all the hosts called so: two that both say `printer` are both under `printer`, with the addresses of each. A host with several names, as one by mDNS and another in the router's leases, has each of them.
- **`{n}.{hostname}`** tells them apart: `1.printer`, `2.printer`, in the order of their MACs. It is the place among those there now, and nothing more: when the first leaves, the second is `1.printer`. A host alone of its name is its `1.`, so that the name is there whether another comes or not.
- **`{mac}`** is the host's own, whatever comes and goes, and whatever it is called. It needs no name: `"{mac}.hosts"` alone works without `discovery.hostnames`.

## A name written wins

A host is called what it says, and anything on the network can say `nas`, or `router`. So a name that is written in the configuration is never a template's:

- A name of a task, written as it is, at the same endpoint, has its task's addresses and no other. A host called the same is left out of it, and the log says so, once.
- A record of a resolver's zone is the record: a host called the same doesn't change its answer.

For a name that matters, write it, with a filter by MAC: a template is for the rest. A name is cleaned to one DNS label before it is used, of lower case letters, digits and hyphens: none is `*`, nor has a dot.

## When a host leaves

Its names lose its addresses when discovery lets it go, after its [lifetime](discovery.md#lifetimes): a name with none left has its records removed, and is then forgotten. A resolver stops answering it at once, and asks its upstream servers, as for any name it doesn't have.

What ipv6ddns doesn't know is the names it made before it was started. A host that left while ipv6ddns wasn't running keeps its records at a DNS provider, which nothing removes: those of the hosts that are there are set right as they are found. A resolver has no such records, as its names are in memory. For a name that has to be exact at a provider through restarts, write it.

## What it doesn't do

- A task's [`sources`](sources.md), addresses without a MAC, are of its names written as they are: a template's names are of hosts, which a source's addresses aren't.
- The [Home Assistant device](home-assistant-integration.md) has an entity for each name written in the configuration, and none for a template's, which aren't known when it starts.
- Each name of a template is updated on its own at a provider: a network of many named hosts is as many updates when ipv6ddns starts, which a provider that limits its requests may slow down. The [retry](reference/configuration.md) takes care of those refused.

## The errors

| The mistake | The error |
|---|---|
| A placeholder there is none of | `task lan: endpoint home: the name "{host}": {host} is no placeholder: they are {hostname}, {n} and {mac}` |
| `{n}` without `{hostname}` | `task lan: endpoint home: the name "{n}.lan": {n} is the place of a host among those of one name: it needs {hostname} beside it, as {n}.{hostname}` |
| A brace alone | `task lan: endpoint home: the name "nas}": a brace that is of no placeholder: they are {hostname}, {n} and {mac}` |
| `{hostname}` without the names learned | `task lan: endpoint home: the name "{hostname}" is of the hosts' names, which aren't learned: it needs enabled: true under discovery.hostnames, and a protocol that learns them, as mdns` |
