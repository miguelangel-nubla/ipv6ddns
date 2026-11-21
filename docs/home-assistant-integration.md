# Home Assistant integration

With a `homeassistant` block, ipv6ddns is a device of Home Assistant's ESPHome integration, which every Home Assistant has: no custom integration to install. It works with ipv6ddns anywhere on the network, in the [add-on](../homeassistant/addon/DOCS.md), in Docker or as a binary.

- **To Home Assistant**, each name's addresses, last update, and an update problem; the hosts discovered; and a button to update every name now.
- **From Home Assistant**, the state of any entity, for a [`homeassistant` source](sources.md#types): a router's WAN address sensor can give a name its A record, as it changes.

## Setting it up

The block says two things, and ipv6ddns doesn't start without either: where the device listens, and how it has its encryption key.

```yaml
homeassistant:
  listen: 192.168.1.0/24            # the network Home Assistant is on
  key: ${file:homeassistant.key}    # your own: openssl rand -base64 32 > homeassistant.key
```

```yaml
homeassistant:
  listen: 192.168.1.0/24
  key_provisioning: true            # Home Assistant gives it: kept in homeassistant.state
```

- **`listen`**: where Home Assistant connects. The network Home Assistant is on, as above, or an address of the machine on it: the device listens on the machine's addresses there only, at 6053, and announces itself on those interfaces only. A port alone, `listen: 6053`, is every address of the machine: the internet's too, where the machine is a router or has a public address. There is no default, as there is no address that does for everyone: see [where it listens](#where-it-listens).
- **The key**: your own, or one Home Assistant gives it, one or the other: see [the key](#the-key).

Home Assistant finds the device by mDNS, `ipv6ddns`, under *Settings → Devices & services → Discovered*. Add it: Home Assistant asks for your key, or, with `key_provisioning`, makes one and gives it, as to ESPHome's devices. Where mDNS doesn't reach, as across VLANs, or with `announce: false`, add the ESPHome integration by hand with ipv6ddns' address and its port, 6053 by default. The device announces itself on the interfaces that are up, with an address, when ipv6ddns starts: started before the network, it isn't discovered, and is added by hand, or found after a restart.

The keys of the block are in the [reference](reference/configuration.md#home-assistant).

### The key

#### Your own: `key`

```yaml
homeassistant:
  listen: 192.168.1.0/24
  key: ${file:homeassistant.key}
```

Make one with `openssl rand -base64 32`, and give it in the configuration: written there, read from a file, as above, or from the environment, `key: ${HOMEASSISTANT_KEY}`, as [any secret](configuration.md#secrets).

- **Adding it**, Home Assistant asks for the key: paste it.
- **The key is fixed**: the device takes connections with it only, from the start, and Home Assistant can't change it.
- **Nothing is written**: no state file, no lock file. So it is the way for a container, which then needs no volume for data, and for a configuration on a read-only file system.
- The device's MAC, by which Home Assistant knows it for good, comes from the key: another key in the configuration is another device to Home Assistant.

#### Given by Home Assistant: `key_provisioning: true`

```yaml
homeassistant:
  listen: 192.168.1.0/24
  key_provisioning: true
  # key_provisioning_state_file: homeassistant.state
```

- **Adding it**, Home Assistant makes a key and gives it to the device, which keeps it, and takes connections with it only from then on. Only a client with the key can change it, as Home Assistant does when the device is deleted there: the device is without a key again, to be added again.
- **What is written**: `key_provisioning_state_file`, `homeassistant.state` beside the configuration by default, relative to the configuration's folder. It holds the device's identity, which its MAC comes from, made at the first start, and the key, once given: written when they change, and readable by its owner only. Beside it, a lock file, `homeassistant.state.lock`, empty, made once, which the instance holds while it runs: [one state file for each instance](#several-devices). ipv6ddns must be able to write the file: where it can't make it, it doesn't start, and says so. In a container, the file is gone with the container unless its folder is a volume, and the device is a new one each time: give a `key` there instead.
- **Before it has its key**, the device takes connections without one, for Home Assistant to give it: those see its entities, but their button presses, and the states they send, are dropped, so nobody can give a `homeassistant` source an address, and they aren't Home Assistant connected, which the sources wait for. If someone else gives it a key first, Home Assistant asks for the key when adding it: delete the state file, restart, and add it again.
- **Deleting the file**, with ipv6ddns stopped, makes the device a new one at the next start, with another MAC and no key: Home Assistant discovers it as new, and the old device stays there, unavailable, until deleted.

#### Neither

A block with no `key` and no `key_provisioning: true` is an error at start, as is one with both, and a `key_provisioning_state_file` without `key_provisioning: true`:

```
homeassistant: the device needs its encryption key, one way or the other: key, your own, made with "openssl rand -base64 32", written there or read from a file or the environment, as ${file:homeassistant.key}; or key_provisioning: true, for Home Assistant to give it when it adds the device, kept in key_provisioning_state_file
```

Without the block there is no device, and no error.

#### A configuration from before v0.23.0

Up to v0.22.3, the device listened on every address unless `listen` said otherwise, and a block without a `key`, as `homeassistant: {}`, was a device Home Assistant gave the key, with `state_file` naming its file. Now both are said, and a block that doesn't say them doesn't start:

| Before | Now |
|---|---|
| Any block without `listen` | Add `listen`: the network Home Assistant is on, or `6053` for every address, as before |
| `homeassistant: {}`, or a block with no `key` | Add `key_provisioning: true` |
| `state_file: guests.state` | `key_provisioning: true`, and `key_provisioning_state_file: guests.state` |
| A block with a `key` | As it is, with `listen` |

With `key_provisioning: true` the state file there is, `homeassistant.state` or the one named, is read as before: the device, its key and its entities stay as they were, with nothing to do in Home Assistant.

### Several devices

Each instance with a `homeassistant` block is a device of its own: two on one machine, or on several machines of one network, are two devices to Home Assistant, each with its entities and its key. They need each:

```yaml
homeassistant:
  listen: 192.168.1.0/24
  name: ipv6ddns-guests                        # its own name on the network
  port: 6054                                   # on one machine: its own port
  key_provisioning: true
  key_provisioning_state_file: guests.state    # in one folder: its own state file; or its own key
```

- **A name**, as every instance is `ipv6ddns` by default. Home Assistant knows a device on the network by its name: two that announced one would be one device to it, at the port of whichever answered last, and gone when either stops. So before it announces itself, ipv6ddns looks for a second and a half for a device already announced with its name, or with its MAC under another name: finding one, it logs the error and doesn't announce itself, and the first stays as it was. It still runs, updates, and takes Home Assistant's connections, added by its address.
- **A port**, on one machine: the one started second with a port that is taken doesn't start.
- **An identity**: a `key` of its own, or, with `key_provisioning: true`, a state file of its own, as the device's MAC, by which Home Assistant knows it for good, comes from them. The state file is `homeassistant.state` beside the configuration by default, so two configurations in one folder name theirs, with `key_provisioning_state_file`. While it runs, an instance holds its state file, with a lock file beside it, `<state file>.lock`: another with the same one doesn't start, and says which file. Not on Windows or Solaris, which have no such lock.

Each announces itself on its own, under its own name: one that stops takes back its own announcement only.

The look is at start, on the interfaces the device announces itself on. Two instances started at the same moment don't see each other, nor do two that mDNS doesn't reach between. And a configuration copied whole to a second machine, with its `key` or its state file, is the same name, MAC and port there: nothing tells the two apart, and Home Assistant sees one device, at two addresses. Give the copy its name and its key.

### Where it listens

`listen` is required: the device listens where it says only, and announces itself on the interfaces that hold those addresses, so Home Assistant connects to one it can reach.

```yaml
homeassistant:
  key: ${file:homeassistant.key}
  listen: 10.2.3.0/24
```

- **A network**, as above: the machine's addresses in it, as they are when ipv6ddns starts. The one to give on a router, or on any machine with a public address or a network Home Assistant isn't on, as a container on several beside Home Assistant's.
- **An address**, `10.2.3.4`, or a host name: that one.
- **A port alone**, `6053`: every address of the machine, announced on each interface discovery runs on. For a machine of one network, as the add-on's, Home Assistant's own. On a router it is the internet's too: with `key_provisioning: true`, until Home Assistant adds the device, anyone who reaches the port could give it a key first.

Without it, ipv6ddns doesn't start:

```
homeassistant.listen: where the device listens, for Home Assistant to connect, is to be given: the network Home Assistant is on, as 192.168.1.0/24, an address of the machine on it, or a port alone, 6053, for every address of the machine, the internet's too where the machine is a router's
```

It takes the entries of [`webserver.listen`](installation.md#the-web-report): a port, an address, a network of the machine's addresses, or a host name, each with `:port` or not; without one, `port`, 6053. The device announces the port it listens on, so `listen: 10.2.3.4:7000` is found at 7000; it announces one, so entries of several ports need `announce: false`. Two networks on one wire, as two macvlan networks on one bridge, both reach Home Assistant's mDNS: list the one Home Assistant can connect to.

## The entities

| Entity | |
|---|---|
| *name* addresses | The addresses the name has now, comma separated. Home Assistant's states hold 255 characters, as six IPv6 addresses written whole: beyond that, the first ones, and `+3 more` for the rest |
| *name* last update | When its records were last updated |
| *name* update | A problem when its last update failed |
| Discovered hosts | How many hosts discovery knows |
| Update now | Updates every name now, as after a change |

*name* is the name's domain, as `www.example.com`. Home Assistant knows an entity by its name, and makes its id of the device's and the entity's: `sensor.ipv6ddns_www_example_com_addresses`, `binary_sensor.ipv6ddns_www_example_com_update`. So a name whose domain changes, as when its host name or zone does in the configuration, is new entities to Home Assistant, and the old ones stay unavailable until deleted. Route 53 learns its zone at the first update, after the entities are made: they are named by the host name alone, as `www addresses`.

The device's own id of an entity is of the name's endpoint and host name in the configuration, as `cloudflare_www_addresses`. Two names that give the same, as the host names `a-b` and `a.b` of one endpoint, get a hash of their own each, as `cloudflare_a_b_1f0c2a9e_addresses`, and the log warns of it: they stay two entities.

## An entity's addresses

```yaml
homeassistant:
  listen: 192.168.1.0/24
  key: ${file:homeassistant.key}
sources:
  router-wan:
    type: homeassistant
    entity: sensor.router_wan_ip      # or its attribute: attribute: wan_ip
tasks:
  home:
    sources:
      - router-wan
    endpoints:
      cloudflare:
        - home
credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: ${CLOUDFLARE_TOKEN}
      zone: example.com
      ttl: 5m
      proxied: false
```

The state is one address or more, separated by commas or spaces. A change runs the source at once. An empty state is none: the addresses go at once, as a [command](sources.md#runs-and-lifetimes) that prints nothing.

While Home Assistant restarts, the source waits: Home Assistant isn't connected, or the entity is `unknown` or `unavailable`, or its attribute `None`, its states for none, until its integration is up. A wait isn't a failure: the addresses stay for the source's `lifetime`, and the log says when the wait starts and ends, at info, and warns if it outlasts the lifetime, when the addresses go. Give the lifetime longer than Home Assistant's restarts. Connected for 30 seconds without a state of the entity is an error: Home Assistant has no entity of that id, or it has no such attribute. Home Assistant sends every state again each time it connects, and only those count: an entity deleted or renamed while it restarted is that error then, rather than its last address kept.

## Recipes

The blocks headed `# Home Assistant` go in Home Assistant's configuration, as `configuration.yaml` or a package; the helpers can be made in its UI too, under *Settings → Devices & services → Helpers*. The others are ipv6ddns'.

### A record you set by hand

A text helper holds the address, and a name follows it: set it from a dashboard, an automation with `input_text.set_value`, or Assist. Cleared, the record goes at once; while Home Assistant restarts, it stays.

```yaml
# Home Assistant: a text helper
input_text:
  vpn_address:
    name: VPN address
    max: 100
```

```yaml
homeassistant:
  listen: 192.168.1.0/24
  key: ${file:homeassistant.key}
sources:
  vpn:
    type: homeassistant
    entity: input_text.vpn_address
tasks:
  vpn:
    sources:
      - vpn
    endpoints:
      cloudflare:
        - vpn
credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: "${CLOUDFLARE_TOKEN}"
      zone: example.com
      ttl: 5m
      proxied: false
```

It takes one address or more, separated by commas or spaces: `203.0.113.7, 2001:db8::7`.

### Switching a name between servers

A select helper picks the server, and a template sensor gives its address: a name moves to the standby for maintenance, by hand, or by an automation when the primary stops answering.

```yaml
# Home Assistant: a select helper, and a template sensor of its address
input_select:
  web_server:
    name: Web server
    options:
      - primary
      - standby

template:
  - sensor:
      - name: web_server_address
        unique_id: web_server_address
        state: >-
          {{ {'primary': '203.0.113.10, 2001:db8::10',
              'standby': '198.51.100.20, 2001:db8:1::20'}.get(states('input_select.web_server'), '') }}

automation:
  - alias: Web server to the standby when the primary is down
    triggers:
      - trigger: state
        entity_id: binary_sensor.web_primary_ping
        to: "off"
        for: "00:02:00"
    actions:
      - action: input_select.select_option
        target:
          entity_id: input_select.web_server
        data:
          option: standby
```

`binary_sensor.web_primary_ping` is one of the [Ping integration](https://www.home-assistant.io/integrations/ping/)'s.

```yaml
homeassistant:
  listen: 192.168.1.0/24
  key: ${file:homeassistant.key}
sources:
  web:
    type: homeassistant
    entity: sensor.web_server_address
tasks:
  www:
    sources:
      - web
    endpoints:
      cloudflare:
        - www
credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: "${CLOUDFLARE_TOKEN}"
      zone: example.com
      ttl: 5m
      proxied: false
```

### Devices discovery doesn't reach

A device on a network ipv6ddns can't discover, as a VLAN it isn't on, may be known to Home Assistant: a router's integration gives each device tracker its address in the `ip` attribute. A private address, its record goes in the local network's DNS, as a Technitium server's zone.

```yaml
homeassistant:
  listen: 192.168.1.0/24
  key: ${file:homeassistant.key}
sources:
  printer:
    type: homeassistant
    entity: device_tracker.printer
    attribute: ip
tasks:
  printer:
    sources:
      - printer
    endpoints:
      lan:
        - printer
credentials:
  lan:
    provider: technitium
    settings:
      address: "http://192.0.2.53:5380"
      token: "${TECHNITIUM_TOKEN}"
      zone: lan.example.com
      ttl: 5m
```

`printer.lan.example.com` then has the printer's address. An integration that drops the attribute when the device leaves leaves it at the last address: Home Assistant sends nothing for an attribute gone, so ipv6ddns keeps what it last sent, until Home Assistant connects again, when a state it doesn't send is an error. One that sets it to none sends `None`, a wait, and the record stays for the source's `lifetime`.

### Two WANs in one record

A template sensor joins the public addresses of two connections, dropping the one that is down, so the name has the addresses that answer.

```yaml
# Home Assistant: the addresses of both WANs, without one that has none
template:
  - sensor:
      - name: wan_addresses
        unique_id: wan_addresses
        state: >-
          {{ [states('sensor.wan1_ip'), states('sensor.wan2_ip')]
             | reject('in', ['unknown', 'unavailable', ''])
             | join(', ') }}
```

```yaml
homeassistant:
  listen: 192.168.1.0/24
  key: ${file:homeassistant.key}
sources:
  wan:
    type: homeassistant
    entity: sensor.wan_addresses
tasks:
  home:
    sources:
      - wan
    endpoints:
      cloudflare:
        - home
credentials:
  cloudflare:
    provider: cloudflare
    settings:
      api_token: "${CLOUDFLARE_TOKEN}"
      zone: example.com
      ttl: 5m
      proxied: false
```

### Alerts, and updating now

The device's entities in automations: a notification when a name's update keeps failing, and an update of every name when the router comes back, rather than at the next change discovery sees. The ids are of the [names' domains](#the-entities): `home.example.com`'s here. Home Assistant lists them under *Settings → Devices & services → ESPHome → ipv6ddns*.

```yaml
# Home Assistant: automations
automation:
  - alias: ipv6ddns update failing
    triggers:
      - trigger: state
        entity_id: binary_sensor.ipv6ddns_home_example_com_update
        to: "on"
        for: "00:10:00"
    actions:
      - action: notify.notify
        data:
          message: "{{ trigger.to_state.name }} has failed for 10 minutes"

  - alias: ipv6ddns update now, the router back
    triggers:
      - trigger: state
        entity_id: binary_sensor.router_wan_connected
        to: "on"
    actions:
      - action: button.press
        target:
          entity_id: button.ipv6ddns_update_now
```

## How it works

ipv6ddns speaks the ESPHome native API, as ESPHome 2026.11 does: the connection is encrypted with the key, Noise_NNpsk0_25519_ChaChaPoly_SHA256, and the device announces itself as `_esphomelib._tcp`. Its MAC, by which Home Assistant knows it, comes from the identity in the state file, or from a fixed key: keep them, and Home Assistant keeps the device. As ESPHome's devices, it drops a connection that says nothing for 150 seconds, which Home Assistant's pings every 20 keep from, or that reads nothing for 10, and Home Assistant connects again. CI connects to it with `aioesphomeapi`, the library Home Assistant's integration uses, at the version Home Assistant has.
