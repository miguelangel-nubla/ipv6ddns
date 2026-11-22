# Configuration

The configuration is a single file, YAML or JSON, given with `-config_file`. Every key is in the [configuration reference](reference/configuration.md), and the [example configuration](../cmd/ipv6ddns/example.config.yaml) shows most of them in use. For a complete setup to start from, see the [guides](guides/README.md).

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

- **A task** gives names their addresses. Its [filters](filtering.md) choose which of the addresses [discovery](discovery.md) finds belong to it, and its `sources` add the addresses of [sources](sources.md). Its `endpoints` say which names get them, at which credentials. A name used in several tasks gets the addresses of all of them.
- **A credential** is a DNS provider with its settings; each provider's are in the [providers reference](reference/providers.md). Two timings apply to it:
  - `debounce` gathers the changes of a short moment into one update.
  - `retry` is how long to wait after a failed update. Until then the provider is left alone, and addresses that change in the meantime go with the retry, not before it.
- **Sources** and **discovery** find the addresses.
- **A resolver**, under `resolvers`, is ipv6ddns's own DNS server for the network's clients, answering the zones of the `resolver` credentials: see the [resolver](resolver.md).

An endpoint's name is inside the credential's zone: `nas` is `nas.home.example.com`, `""` is the zone itself, and `"*.nas"` is a wildcard. Written in full, as `nas.home.example.com`, or in another case, it's still the same name, and the tasks that name it either way give it their addresses together.

The exception is a `route53` endpoint, whose zone is only learned from AWS at the first update. There, `nas` and `nas.home.example.com` are two names, each writing the records with only its own addresses, and the start warns about them. Write the name one way there.

Write names in lower case, both in the configuration and in the records at the provider. Some providers match a record's name exactly as written, so a record made by hand in another case, as `NAS`, may not be found. It's then neither updated nor removed, and is answered alongside the name's own records.

A record disabled at a MikroTik or OPNsense provider is treated as the provider's own choice. It's left as it is, whatever its address, and no record is added beside it. So its address stays unanswered, even when the name has that address again. Technitium re-enables a name's disabled records whenever a record is added to it, so there they behave like any other record.

## Secrets

Any string value takes:

| | |
|---|---|
| `${NAME}` | The environment variable `NAME` |
| `${file:PATH}` | The content of a file, without its final newline, the way Docker and Kubernetes provide secrets. A relative path is relative to the configuration file |
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

A missing variable or file is an error, which names the key, not the value.

## Validation

The configuration is checked as it loads, against its [schema](../config/schema.json). An unknown key, as a typo, a wrong type, a missing required key, or a plugin with another type's keys, stops the start, saying what is wrong and where.

- **The `discovery` block** is read first, by ipv6disc. Its errors say in words what is expected in place of what was written, and it reports all of them, not just the first.
- **The providers' settings and the plugins** are also checked by their own code, so a mistake shows at the start rather than at the first update.
- **The filters** too: a `mac.address` that isn't a MAC, or a `mask` entry that isn't `VALUE/MASK`, is an error that names the task.

In YAML, a key given twice in one block is an error too, instead of the last one silently winning: two tasks with the same name after a copy, or two `credentials:` blocks. That includes a key repeated after a merge key (`<<:`) that already brought it.
