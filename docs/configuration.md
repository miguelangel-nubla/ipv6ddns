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

## Upgrading from v0.22.3

The discovery is configured as [ipv6disc](https://github.com/miguelangel-nubla/ipv6disc), the library it is, configures it, so that both take the same keys; and every setting is in the file, with three flags left. What was written another way no longer loads: the start stops with an error that names the key, and for those that moved, where it is now. Nothing is left deprecated in their place.

| Up to v0.22.3 | Now |
|---|---|
| `lifetime`, at the top | [`discovery.lifetime`](discovery.md#lifetimes) |
| `-lifetime` | `discovery.lifetime`, in the file |
| `-log_level` | `log_level`, in the file |
| `-webserver_listen`, and `webserver_listen` at the top | [`webserver.listen`](installation.md#the-web-report), in the file |
| `discovery.ipv4: true`, `discovery.ipv6: false` | The family's switches: [`discovery.ipv4.enabled: true`](discovery.md#families-and-ways), `discovery.ipv6.enabled: false` |
| A `discovery.ipv4` block without `enabled`, which turned IPv4 on | `enabled: true` in it: IPv4 is off unless it says so |
| `discovery.ipv6.solicit`, `discovery.ipv4.solicit` | [`discovery.solicit.ipv6`, `discovery.solicit.ipv4`](discovery.md#solicitation) |
| `discovery.solicit_eui64` | `discovery.solicit.ipv6` |
| `discovery.listen`, `discovery.active` | `discovery.ipv6.listen`, `discovery.ipv6.active`, and the same of `ipv4` |
| A plugin's `params`, one string | Its [fields](reference/configuration.md#discovery-plugins), each a key: `interval`, `address`, `username` and the others of its type, in the order the string had them |

```yaml
log_level: info
webserver:
  listen:
    - 8053
discovery:
  lifetime: 1h
  ipv4:
    enabled: true
  solicit:
    ipv6: true
```

One of these is no error, and wants a look: a `discovery.ipv4` block that only had its ways, as `active: false` under `ipv4`, loads, and discovers no IPv4 until `enabled: true` is added. The log warns of it at start: that the block has no `enabled`, and IPv4 is off.

The same release has new keys, all off unless asked for: the [protocols](discovery.md#protocols), each with its switch, and the [names](discovery.md#names) of the hosts.

In the Home Assistant add-on, the log level was an option of the add-on, and the address of its page a flag the add-on gave: both are in its `config.yaml` now, and one from before needs [two lines added](../homeassistant/addon/DOCS.md#the-add-ons-page).

Two things from before still work, each with a warning in the log that says what to write instead, and go in v1.0: a task's `ipv4` block, a command, which is a [command source](sources.md) named `<task>.ipv4` until it is moved to `sources`; and a credential's `debounce_time` and `retry_time`, which are `debounce` and `retry`.

And two changed before this, in the same release:

- A `homeassistant` block from up to v0.22.3, which had no `listen` it needed, and, without a `key`, as `homeassistant: {}`, or with `state_file`, nothing that said Home Assistant gives the key. It is an error at start, which says what to add: [`listen`, and `key_provisioning: true`](home-assistant-integration.md#a-configuration-from-before-v0230), and the device stays as it was.
- An entry of `webserver.listen` without a port, as `192.0.2.1` or `10.2.3.0/24`, was at port 80 up to v0.22.3, and is at 8053 now, as every example and the health check have it. Give `:80` to keep it.
