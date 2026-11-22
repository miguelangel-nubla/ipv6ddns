# Home Assistant integration

With a `homeassistant` block, ipv6ddns becomes a device of Home Assistant's ESPHome integration, which every Home Assistant already has: there's no custom integration to install. It works wherever ipv6ddns runs on the network: the [add-on](../homeassistant/addon/DOCS.md), Docker, or a plain binary.

- **To Home Assistant** it sends each name's addresses, its last update and whether the update has a problem, the number of hosts discovered, and a button to update every name now.
- **From Home Assistant** it reads the state of any entity, for a [`homeassistant` source](sources.md#types). For example, a router's WAN address sensor can give a name its A record, and follow it as it changes.

## Setting it up

The block must say two things, or ipv6ddns doesn't start: where the device listens, and how it gets its encryption key.

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

- **`listen`** is where Home Assistant connects. Give the network Home Assistant is on, as above, or the machine's address on it. The device then listens only on the machine's addresses there, at port 6053, and announces itself only on those interfaces. A port alone, `listen: 6053`, means every address of the machine, including a public one if the machine is a router or has one. There's no default, because no address suits everyone: see [where it listens](#where-it-listens).
- **The key** is either your own, or one Home Assistant gives it: see [the key](#the-key).

Home Assistant finds the device by mDNS, as `ipv6ddns`, under *Settings → Devices & services → Discovered*. When you add it, Home Assistant asks for your key, or, with `key_provisioning`, makes one and gives it, as it does for ESPHome devices.

Where mDNS doesn't reach, as across VLANs, or with `announce: false`, add the ESPHome integration by hand with ipv6ddns' address and port, 6053 by default. The device announces itself on the interfaces that are up and have an address when ipv6ddns starts. If ipv6ddns starts before the network is up, the device isn't discovered: add it by hand, or restart ipv6ddns.

The keys of the block are in the [reference](reference/configuration.md#home-assistant).

### The key

#### Your own: `key`

```yaml
homeassistant:
  listen: 192.168.1.0/24
  key: ${file:homeassistant.key}
```

Make one with `openssl rand -base64 32`, and put it in the configuration: written there, read from a file as above, or from the environment as `key: ${HOMEASSISTANT_KEY}`, like [any secret](configuration.md#secrets).

- **When you add the device**, Home Assistant asks for the key: paste it.
- **The key is fixed.** The device only accepts connections with it, from the start, and Home Assistant can't change it.
- **Nothing is written to disk**: no state file, no lock file. That makes it the right choice in a container, which then needs no data volume, and for a configuration on a read-only file system.
- **The device's MAC comes from the key**, and Home Assistant knows the device by that MAC for good. A different key in the configuration is a different device to Home Assistant.

#### Given by Home Assistant: `key_provisioning: true`

```yaml
homeassistant:
  listen: 192.168.1.0/24
  key_provisioning: true
  # key_provisioning_state_file: homeassistant.state
```

- **When you add the device**, Home Assistant makes a key and gives it to the device, which keeps it and from then on only accepts connections with it. Only a client that has the key can change it. Home Assistant does that when you delete the device there: the device is left without a key, ready to be added again.
- **What's written to disk** is `key_provisioning_state_file`: `homeassistant.state` by default, beside the configuration, and relative to the configuration's folder if you give another. It holds the device's identity, made at the first start, which its MAC comes from, and the key once it's given. It's written when they change, and only its owner can read it.

  Beside it is an empty lock file, `homeassistant.state.lock`, which the instance holds while it runs: [one state file per instance](#several-devices). ipv6ddns must be able to write the state file; if it can't create it, it doesn't start, and says why. In a container, the file disappears with the container unless its folder is a volume, and the device is a new one every time: give it a `key` instead.
- **Before it has its key**, the device accepts connections without one, so that Home Assistant can give it one. Those connections see its entities, but their button presses and the states they send are ignored. So nobody can give a `homeassistant` source an address that way, and these connections don't count as Home Assistant being connected, which the sources wait for. If someone else gives it a key first, Home Assistant asks you for the key when adding it: delete the state file, restart, and add it again.
- **Deleting the state file**, with ipv6ddns stopped, makes the device a new one at the next start, with another MAC and no key. Home Assistant discovers it as new, and the old device stays there, unavailable, until you delete it.

#### Neither

It's an error at start to give neither `key` nor `key_provisioning: true`, to give both, or to give a `key_provisioning_state_file` without `key_provisioning: true`:

```
homeassistant: the device needs its encryption key, one way or the other: key, your own, made with "openssl rand -base64 32", written there or read from a file or the environment, as ${file:homeassistant.key}; or key_provisioning: true, for Home Assistant to give it when it adds the device, kept in key_provisioning_state_file
```

Without the `homeassistant` block there's no device, and no error.

### Several devices

Each instance with a `homeassistant` block is a device of its own. Two instances, on one machine or on two machines of the same network, are two devices to Home Assistant, each with its own entities and key. Each one needs:

```yaml
homeassistant:
  listen: 192.168.1.0/24
  name: ipv6ddns-guests                        # its own name on the network
  port: 6054                                   # on one machine: its own port
  key_provisioning: true
  key_provisioning_state_file: guests.state    # in one folder: its own state file; or its own key
```

- **Its own name.** Every instance is called `ipv6ddns` by default, and Home Assistant knows a device on the network by its name. Two that announce the same name would look like one device, at the port of whichever answered last, and vanish when either stops. So before announcing itself, ipv6ddns looks for a second and a half for a device already announced with its name, or with its MAC under another name. If it finds one, it logs an error and doesn't announce itself, and the first one is left as it was. It still runs, updates names, and accepts Home Assistant's connections if you add it by address.
- **Its own port**, on one machine. Of two with the same port, the one started second doesn't start.
- **Its own identity**: its own `key`, or, with `key_provisioning: true`, its own state file, since the device's MAC, by which Home Assistant knows it for good, comes from them. The state file is `homeassistant.state` beside the configuration by default, so two configurations in one folder need `key_provisioning_state_file` to name their own. While it runs, an instance holds its state file, with a lock file beside it, `<state file>.lock`. Another instance with the same file doesn't start, and says which file. This lock doesn't exist on Windows or Solaris.

Each instance announces itself separately, under its own name, and one that stops only withdraws its own announcement.

The check for another device happens at start, on the interfaces the device announces itself on. So two instances started at the same moment don't see each other, and neither do two that mDNS doesn't reach between. A configuration copied whole to a second machine, with its `key` or state file, has the same name, MAC and port there: nothing tells the two apart, and Home Assistant sees one device at two addresses. Give the copy its own name and key.

### Where it listens

`listen` is required. The device only listens where it says, and announces itself on the interfaces that have those addresses, so Home Assistant connects to an address it can reach.

```yaml
homeassistant:
  key: ${file:homeassistant.key}
  listen: 10.2.3.0/24
```

- **A network**, as above: the machine's addresses in it, as they are when ipv6ddns starts. Use this on a router, or on any machine that has a public address or is on networks Home Assistant isn't on, such as a container attached to several networks.
- **An address**, `10.2.3.4`, or a host name: just that one.
- **A port alone**, `6053`: every address of the machine, announced on each interface discovery runs on. Fine for a machine on a single network, as the add-on's, which is Home Assistant's own. On a router, though, it includes the internet side: with `key_provisioning: true`, anyone who reaches the port before Home Assistant adds the device could give it a key first.

Without it, ipv6ddns doesn't start:

```
homeassistant.listen: where the device listens, for Home Assistant to connect, is to be given: the network Home Assistant is on, as 192.168.1.0/24, an address of the machine on it, or a port alone, 6053, for every address of the machine, the internet's too where the machine is a router's
```

It takes the same entries as [`webserver.listen`](installation.md#the-web-report): a port, an address, a network of the machine's addresses, or a host name, each with or without `:port`. Without a port, it's `port`, 6053 by default.

The device announces the port it listens on, so with `listen: 10.2.3.4:7000` it's found at 7000. It can announce only one port, so entries with different ports need `announce: false`. If two networks share one wire, as two macvlan networks on one bridge, both reach Home Assistant's mDNS: list only the one Home Assistant can connect to.

## The entities

| Entity | |
|---|---|
| *name* addresses | The name's current addresses, comma separated. A Home Assistant state holds 255 characters, about six full IPv6 addresses; beyond that, the first ones and `+3 more` for the rest |
| *name* last update | When its records were last updated |
| *name* update | A problem when its last update failed |
| Discovered hosts | How many hosts discovery knows |
| Update now | Updates every name now, as after a change |

*name* is the name's domain, as `www.example.com`. Home Assistant builds an entity's id from the device's name and the entity's: `sensor.ipv6ddns_www_example_com_addresses`, `binary_sensor.ipv6ddns_www_example_com_update`.

So if a name's domain changes, because its host name or zone changed in the configuration, Home Assistant sees new entities, and the old ones stay unavailable until you delete them. Route 53 learns its zone at the first update, after the entities are made, so its entities are named by the host name alone, as `www addresses`.

Internally, the device identifies an entity by the name's endpoint and host name in the configuration, as `cloudflare_www_addresses`. If two names give the same id, as the host names `a-b` and `a.b` of one endpoint, each gets a hash added, as `cloudflare_a_b_1f0c2a9e_addresses`, the log warns about it, and they stay two entities.

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

The state is one or more addresses, separated by commas or spaces. A change runs the source at once. An empty state means no addresses, and they go at once, like a [command](sources.md#runs-and-lifetimes) that prints nothing.

While Home Assistant restarts, the source waits. That covers Home Assistant not being connected, and the entity being `unknown` or `unavailable`, or its attribute `None`, as entities are until their integration is up. Waiting isn't a failure:

- The addresses stay for the source's `lifetime`. Make the lifetime longer than a Home Assistant restart.
- The log says, at info level, when the wait starts and ends, and warns if it lasts longer than the lifetime, when the addresses go.

If Home Assistant is connected for 30 seconds without sending the entity's state, that's an error: it has no entity with that id, or the entity has no such attribute. Home Assistant sends every state again each time it connects, and only those count. So an entity deleted or renamed while Home Assistant restarted shows up as that error, rather than keeping its last address.

## Recipes

The blocks headed `# Home Assistant` go in Home Assistant's configuration, as `configuration.yaml` or a package. You can also create the helpers in its UI, under *Settings → Devices & services → Helpers*. The other blocks are ipv6ddns'.

### A record you set by hand

A text helper holds the address, and a name follows it. Set it from a dashboard, from an automation with `input_text.set_value`, or with Assist. When you clear it, the record goes at once; while Home Assistant restarts, it stays.

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

It takes one or more addresses, separated by commas or spaces: `203.0.113.7, 2001:db8::7`.

### Switching a name between servers

A select helper picks the server, and a template sensor gives its address. The name moves to the standby by hand, for maintenance, or by an automation when the primary stops answering.

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

`binary_sensor.web_primary_ping` comes from the [Ping integration](https://www.home-assistant.io/integrations/ping/).

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

Home Assistant may know a device on a network ipv6ddns can't discover, such as a VLAN it isn't on: a router's integration gives each device tracker its address in the `ip` attribute. Since that's a private address, its record goes in the local network's DNS, here a zone on a Technitium server.

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

`printer.lan.example.com` then has the printer's address.

What happens when the device leaves depends on the integration:

- **If it removes the attribute**, Home Assistant sends nothing, so ipv6ddns keeps the last address until Home Assistant reconnects. Then the missing state is an error.
- **If it sets the attribute to none**, Home Assistant sends `None`, which is a wait, and the record stays for the source's `lifetime`.

### Two WANs in one record

A template sensor joins the public addresses of two internet connections, leaving out one that's down, so the name only has addresses that answer.

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

The device's entities can drive automations: a notification when a name's update keeps failing, and an update of every name when the router comes back, rather than waiting for the next change discovery sees. The entity ids come from the [names' domains](#the-entities), `home.example.com` here. Home Assistant lists them under *Settings → Devices & services → ESPHome → ipv6ddns*.

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

ipv6ddns speaks the ESPHome native API, as ESPHome 2026.11 does. The connection is encrypted with the key, using Noise_NNpsk0_25519_ChaChaPoly_SHA256, and the device announces itself as `_esphomelib._tcp`.

Its MAC, by which Home Assistant knows it, comes from the identity in the state file, or from a fixed key: keep them, and Home Assistant keeps the device.

Like ESPHome devices, it drops a connection that sends nothing for 150 seconds (Home Assistant pings every 20, which prevents that), or that reads nothing for 10. Home Assistant then connects again.

CI tests it with `aioesphomeapi`, the library Home Assistant's integration uses, at the version Home Assistant ships.
