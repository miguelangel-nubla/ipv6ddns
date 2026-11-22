# Configuration

The configuration is one file, YAML or JSON, given with `-config_file`. Every key is in the [configuration reference](reference/configuration.md); the [example configuration](../cmd/ipv6ddns/example.config.yaml) has most of them at work.

## Its parts

```yaml
tasks:          # the names to keep, and which addresses they get
  nas:
    filter:     # the addresses discovery finds that are the task's
      - mac:
          address: "00:11:22:33:44:55"
    sources:                # and those of these sources
      - wan
    endpoints:
      home-dns:             # the names: nas, at the home-dns credential
        - nas

credentials:    # the DNS providers, and their settings
  home-dns:
    provider: technitium
    settings:
      address: http://127.0.0.1:5380
      token: ${TECHNITIUM_TOKEN}
      zone: home.example.com
      ttl: 5m

sources:        # addresses without a MAC
  wan:
    type: dns

discovery:      # how hosts are found: IPv6 by default
  ipv4:
    enabled: true
```

- A **task** gives names their addresses. Its [filters](filtering.md) choose, among the addresses [discovery](discovery.md) finds, those of the task; its `sources` add the addresses of [sources](sources.md). Its `endpoints` say which names, at which credentials, get them. A name in several tasks gets the addresses of all.
- A **credential** is a DNS provider with its settings: those of each provider are in the [providers reference](reference/providers.md). Its `debounce` gathers the changes of a moment into one update, and a failed update is retried after `retry`: until then the provider is left alone, and addresses that change meanwhile go with the retry, not before it.
- **Sources** and **discovery** find the addresses.
- A **resolver**, of `resolvers`, is a DNS server of ipv6ddns's own for the network's clients, which answers the zones of the `resolver` credentials: see the [resolver](resolver.md).

An endpoint's name is in the credential's zone: `nas` is `nas.home.example.com`, `""` is the zone itself, `"*.nas"` a wildcard. Written whole, as `nas.home.example.com`, or in another case, it is the same name: the tasks that name it either way give it their addresses together.

Names are expected in lower case: in the configuration, and in the records at the provider. Some providers match a record's name as it is written, so a record of the name in another case, as `NAS` made by hand, may not be found: it is neither updated nor removed, and is answered beside the name's own.

A record disabled at the provider, of Mikrotik or OPNsense, is the provider's own choice: it is left as it is, whatever its address, and no record is added beside it, so its address stays unanswered, also when the name has it again. Technitium enables the disabled records of a name when a record is added to it: there they are records as any other.

## Secrets

Any string value takes:

| | |
|---|---|
| `${NAME}` | The environment variable `NAME` |
| `${file:PATH}` | The content of a file, without its final newline, as Docker and Kubernetes give secrets. A relative path is from the configuration file |
| `$${` | A literal `${` |

```yaml
credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: ${file:/run/secrets/cloudflare_token}
      zone: example.com
      ttl: 1h
      proxied: false
```

A variable or a file that isn't there is an error, which names the key, not the value.

## Validation

The configuration is checked as it loads, against its [schema](../config/schema.json): an unknown key, as a typo, a wrong type, a missing required key, or a plugin with the keys of another type, stops the start with what is wrong and where. The `discovery` block is read first, by ipv6disc, whose errors say in words what there is in place of what was written: every one of them, not the first alone. The providers' settings and the plugins are checked by their own code too, so a mistake shows at the start, rather than at the first update. So are the filters: a `mac.address` that is no MAC, or a `mask` entry that is not `VALUE/MASK`, is an error that names the task.

In YAML, a key given twice in one block, as two tasks of one name after a copy, or two `credentials:` blocks, is an error too, and not the last one winning. That includes a key that follows a merge key (`<<:`) which already brought it.
