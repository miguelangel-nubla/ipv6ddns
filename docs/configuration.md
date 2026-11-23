# Configuration

The configuration is a single file, in YAML or JSON, which you pass with `--config`.

- Every key is in the [configuration reference](reference/configuration.md).
- The [example configuration](../cmd/ipv6ddns/example.config.yaml) shows most keys in use.
- The [guides](guides/README.md) have complete setups to start from.

## Its parts

```yaml
tasks:          # the names to keep, and which addresses they get
  nas:
    filter:     # which discovered addresses the task takes
      - mac:
          address: "00:11:22:33:44:55"
    sources:                # plus the addresses of these sources
      - wan
    endpoints:
      home-dns:             # the names to keep at the home-dns credential
        - nas

credentials:    # the DNS providers, and their settings
  home-dns:
    provider: technitium
    settings:
      address: http://127.0.0.1:5380
      token: ${TECHNITIUM_TOKEN}
      zone: lan.example.com
      ttl: 5m

sources:        # addresses without a MAC
  wan:
    type: dns

discovery:      # how hosts are found: IPv6 by default
  ipv4:
    enabled: true
```

- **A task** gives names their addresses.
  - Its [filters](filtering.md) choose which of the addresses that [discovery](discovery.md) finds belong to the task.
  - Its `sources` add the addresses of the [sources](sources.md) it lists.
  - Its `endpoints` say which names get those addresses, and at which credentials.

  A name used in several tasks gets the addresses of all of them.
- **A credential** is a DNS provider with its settings. Each provider's settings are in the [providers reference](reference/providers.md). A credential also has two timings:
  - `debounce` is a short wait that gathers several changes into one update.
  - `retry` is how long to wait after a failed update. Until then, ipv6ddns leaves the provider alone. Addresses that change in the meantime are sent with the retry, not before it.
- **Sources** and **discovery** are where the addresses come from.
- **A resolver**, under `resolvers`, is ipv6ddns's own DNS server for the clients on the network. It answers the zones of the `resolver` credentials: see the [resolver](resolver.md).

### How names are written

An endpoint's name is relative to the credential's zone:

- `nas` is `nas.lan.example.com`;
- `""` is the zone itself;
- `"*.nas"` is a wildcard.

You can also write the name in full, `nas.lan.example.com`, or in another letter case. It is still the same name, and all the tasks that use it, however they write it, give it their addresses together.

The exception is a `route53` endpoint, because its zone is only learned from AWS at the first update. There, `nas` and `nas.lan.example.com` count as two names. Each one writes the records with only its own addresses, and ipv6ddns warns about them at start. For `route53`, write each name one way only.

Write names in lower case, both in the configuration and in the records at the provider. Some providers match a record's name exactly as written, so a record you created by hand in another case, such as `NAS`, may not be found. It is then neither updated nor removed, and the provider answers it alongside the name's own records.

### Disabled records

At a MikroTik or OPNsense provider, ipv6ddns treats a disabled record as your own choice. It leaves the record as it is, whatever its address, and adds no record next to it. So that address stays unanswered, even when the name has it again.

Technitium is different: it re-enables a name's disabled records whenever a record is added to the name. There, disabled records behave like any other record.

## Secrets

Any string value in the configuration can contain:

| You write | It becomes |
|---|---|
| `${NAME}` | The environment variable `NAME` |
| `${file:PATH}` | The content of a file, without its final newline. This is how Docker and Kubernetes provide secrets. A relative path is relative to the configuration file |
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

A missing variable or file is an error. The error names the key, not the value.

## Validation

The configuration is checked against its [schema](../config/schema.json) as it loads. Any of these stops the start, with an error that says what is wrong and where:

- an unknown key, such as a typo;
- a value of the wrong type;
- a missing required key;
- a plugin with the keys of another plugin type.

Some parts get further checks:

- **The `discovery` block** is read first, by ipv6disc. Its errors say in words what was expected instead of what you wrote. All of its errors are reported, not just the first.
- **The providers' settings and the plugins** are also checked by their own code, so a mistake shows at start instead of at the first update.
- **The filters** are checked too. A `mac.address` that isn't a MAC, or a `mask` entry that isn't `VALUE/MASK`, is an error that names the task.

In YAML, a key written twice in one block is an error too, instead of the last one silently winning. Typical cases are two tasks with the same name after a copy and paste, or two `credentials:` blocks. A key repeated after a merge key (`<<:`) that already brought it in is also an error.
