# Home Assistant integration

A `homeassistant` block makes ipv6ddns a device in Home Assistant. It uses the ESPHome integration, which every Home Assistant already has, so there's no custom integration to install. It works wherever ipv6ddns runs on the network: as the [app](../homeassistant/addon/DOCS.md), in Docker, or as a plain binary.

- **Home Assistant gets** each name's addresses, when the name was last updated, and whether that update has a problem. It also gets the number of hosts discovered, and a button that updates every name now.
- **ipv6ddns gets** the state of any entity, through a [`homeassistant` source](sources.md#types). For example, a router's WAN address sensor can give a name its A record, and the record follows the sensor as it changes.

## Setting it up

The block must say two things: where the device listens, and how it gets its encryption key. Without either one, ipv6ddns doesn't start.

With a key of your own:

```yaml
homeassistant:
  listen: 192.168.1.0/24            # the network Home Assistant is on
  key: ${file:homeassistant.key}    # your own: openssl rand -base64 32 > homeassistant.key
```

Or with a key that Home Assistant gives the device:

```yaml
homeassistant:
  listen: 192.168.1.0/24
  key_provisioning: true            # Home Assistant provides the key, kept in homeassistant.state
```

- **`listen`** is where Home Assistant connects. Give the network Home Assistant is on, as in the examples, or the machine's address on that network. The device then listens only on the machine's addresses in that network, at port 6053, and announces itself only on those interfaces. A port alone, `listen: 6053`, means every address of the machine. That includes a public address, if the machine is a router or has one. There's no default, because no address suits everyone: see [where it listens](#where-it-listens).
- **The key** is either your own, or one that Home Assistant gives the device: see [the key](#the-key).

Home Assistant finds the device by mDNS. It appears as `ipv6ddns` under *Settings → Devices & services → Discovered*. When you add it, Home Assistant asks for your key. With `key_provisioning`, Home Assistant makes a key and gives it to the device instead, as it does for ESPHome devices.

Add the device by hand where mDNS doesn't reach, for example across VLANs, or when the block has `announce: false`. To do that, add the ESPHome integration with the address of ipv6ddns and its port, 6053 by default.

The device announces itself on the interfaces that are up and have an address when ipv6ddns starts. If ipv6ddns starts before the network is up, the device isn't discovered. Add it by hand, or restart ipv6ddns.

Every key of the block is in the [reference](reference/configuration.md#home-assistant).

### The key

#### Your own: `key`

```yaml
homeassistant:
  listen: 192.168.1.0/24
  key: ${file:homeassistant.key}
```

Make a key with `openssl rand -base64 32`, and put it in the configuration like [any secret](configuration.md#secrets). You can write it there, read it from a file as above, or read it from the environment with `key: ${HOMEASSISTANT_KEY}`.

- **When you add the device**, Home Assistant asks for the key. Paste it.
- **The key is fixed.** From the start, the device only accepts connections that use it, and Home Assistant can't change it.
- **Nothing is written to disk**: no state file, and no lock file. That makes `key` the right choice in a container, which then needs no data volume, and for a configuration on a read-only file system.
- **The device's MAC comes from the key.** Home Assistant knows the device by that MAC for good, so a different key in the configuration is a different device to Home Assistant.

#### Given by Home Assistant: `key_provisioning: true`

```yaml
homeassistant:
  listen: 192.168.1.0/24
  key_provisioning: true
  # key_provisioning_state_file: homeassistant.state
```

**When you add the device**, Home Assistant makes a key and gives it to the device. The device keeps the key, and from then on only accepts connections that use it. Only a client that has the key can change it. Home Assistant does so when you delete the device there: the device is left without a key, ready to be added again.

**The state file** is what's written to disk. It is `key_provisioning_state_file`:

- By default it's `homeassistant.state`, beside the configuration. A relative path you give is relative to the configuration's folder.
- It holds the device's identity, which is made at the first start and which the device's MAC comes from. It also holds the key, once Home Assistant has given it.
- It's written when the identity or the key changes, and only its owner can read it.
- Beside it is an empty lock file, `homeassistant.state.lock`. The instance holds the lock while it runs, because each instance needs [a state file of its own](#several-devices).
- ipv6ddns must be able to write the state file. If it can't create the file, it doesn't start, and says why.
- In a container, the file disappears with the container unless its folder is a volume. The device is then a new one every time. Give the device a `key` instead.

**Before it has its key**, the device accepts connections without one, so that Home Assistant can give it one. Those connections see the device's entities, but the device ignores their button presses and the states they send. So nobody can give a `homeassistant` source an address that way. These connections also don't count as Home Assistant being connected, which is what the sources wait for.

If someone else gives the device a key first, Home Assistant asks you for the key when you add the device. Delete the state file, restart ipv6ddns, and add the device again.

**Deleting the state file**, with ipv6ddns stopped, makes the device a new one at the next start, with another MAC and no key. Home Assistant discovers it as a new device. The old device stays in Home Assistant, unavailable, until you delete it.

#### Neither

Give exactly one of `key` and `key_provisioning: true`. Each of these is an error at start:

- neither `key` nor `key_provisioning: true`;
- both of them;
- a `key_provisioning_state_file` without `key_provisioning: true`.

```
homeassistant: the device needs an encryption key, in one of two ways. key: your own, made with "openssl rand -base64 32", written there or read from a file or the environment, as ${file:homeassistant.key}. Or key_provisioning: true: Home Assistant gives the key when it adds the device, and it's stored in key_provisioning_state_file
```

Without the `homeassistant` block there's no device, and no error.

### Several devices

Each instance with a `homeassistant` block is a device of its own. Two instances are two devices to Home Assistant, each with its own entities and key, whether they run on one machine or on two machines of the same network. Each instance needs settings of its own:

```yaml
homeassistant:
  listen: 192.168.1.0/24
  name: ipv6ddns-guests                        # its own name on the network
  port: 6054                                   # its own port, when both run on one machine
  key_provisioning: true
  key_provisioning_state_file: guests.state    # its own state file, when both are in one folder (or its own key)
```

**Its own name.** Every instance is called `ipv6ddns` by default, and Home Assistant knows a device on the network by its name. Two instances that announce the same name would look like one device, at the port of whichever answered last, and that device would vanish when either instance stops.

So before it announces itself, ipv6ddns looks for a second and a half for a device that is already announced with its name, or with its MAC under another name. If it finds one, it logs an error and doesn't announce itself, and the first device is left as it was. The instance still runs and updates names. It also accepts Home Assistant's connections, if you add it by address.

**Its own port**, on one machine. When two instances have the same port, the one started second doesn't start.

**Its own identity.** The device's MAC, by which Home Assistant knows it for good, comes from the `key`, or from the state file with `key_provisioning: true`. So each instance needs its own `key`, or its own state file.

- The state file is `homeassistant.state` beside the configuration by default. Two configurations in one folder must each name their own with `key_provisioning_state_file`.
- While it runs, an instance holds its state file, with a lock file beside it, `<state file>.lock`. Another instance with the same file doesn't start, and says which file.
- This lock doesn't exist on Windows or Solaris.

Each instance announces itself separately, under its own name. An instance that stops only withdraws its own announcement.

The check for another device has limits. It happens at start, on the interfaces the device announces itself on. So two instances started at the same moment don't see each other. Neither do two instances that mDNS doesn't reach between.

A configuration copied whole to a second machine, with its `key` or its state file, has the same name, MAC and port there. Nothing tells the two apart, and Home Assistant sees one device at two addresses. Give the copy its own name and key.

### Where it listens

`listen` is required. The device listens only where `listen` says, and announces itself on the interfaces that have those addresses. That way Home Assistant connects to an address it can reach.

```yaml
homeassistant:
  key: ${file:homeassistant.key}
  listen: 10.2.3.0/24
```

An entry of `listen` is one of these:

- **A network**, as above. The device listens on the machine's addresses in that network, as they are when ipv6ddns starts. Use a network on a router, and on any machine that has a public address or is on networks Home Assistant isn't on, such as a container attached to several networks.
- **An address**, such as `10.2.3.4`, or a host name. The device listens on just that one.
- **A port alone**, such as `6053`. The device listens on every address of the machine, and announces itself on each interface discovery runs on. That's fine for a machine on a single network, like the app's, whose machine is Home Assistant's own. On a router, though, every address includes the internet side. With `key_provisioning: true`, anyone who reaches the port before Home Assistant adds the device could give it a key first.

Without `listen`, ipv6ddns doesn't start:

```
homeassistant.listen is missing: give where Home Assistant can connect to the device. That's the network Home Assistant is on, as 192.168.1.0/24, or this machine's address on it. A port alone, as 6053, means every address of the machine, including the internet-facing one on a router
```

`listen` takes the same entries as a [listener's `listen`](installation.md#the-web-report), without the scheme: a port, an address, a network of the machine's addresses, or a host name, each with or without `:port`. An entry without a port uses `port`, which is 6053 by default.

The device announces the port it listens on. With `listen: 10.2.3.4:7000`, Home Assistant finds it at 7000. The device can announce only one port, so entries with different ports need `announce: false`.

If two networks share one wire, such as two macvlan networks on one bridge, an announcement on either reaches Home Assistant's mDNS. List only the network Home Assistant can connect to.

## The entities

| Entity | |
|---|---|
| *name* addresses | The name's current addresses, separated by commas |
| *name* last update | When the name's records were last updated |
| *name* update | A problem, when the name's last update failed |
| Discovered hosts | How many hosts discovery knows |
| Update now | A button that updates every name now, for example after a change |

A Home Assistant state holds 255 characters, about six full IPv6 addresses. When a name has more addresses than fit, the state has the first ones, and then a count of the rest, such as `+3 more`.

*name* is the name's domain, such as `www.example.com`. Home Assistant builds an entity's id from the device's name and the entity's name: `sensor.ipv6ddns_www_example_com_addresses`, `binary_sensor.ipv6ddns_www_example_com_update`.

So when a name's domain changes, because you changed its host name or its zone in the configuration, Home Assistant sees new entities. The old ones stay unavailable until you delete them.

Route 53 is an exception. ipv6ddns learns a Route 53 zone at the first update, after the entities are made. So the entities of a Route 53 name are named by the host name alone, such as `www addresses`.

Internally, the device identifies an entity by the endpoint and the host name the configuration gives the name, such as `cloudflare_www_addresses`. Two names can give the same id, like the host names `a-b` and `a.b` of one endpoint. Each then gets a hash added, such as `cloudflare_a_b_1f0c2a9e_addresses`, and the log warns about it. They stay two entities.

## An entity's addresses

A `homeassistant` source takes its addresses from the state of an entity, or from one of the entity's attributes. A task that lists the source gives those addresses to its names:

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

The state is one or more addresses, separated by commas or spaces. When the state changes, the source runs at once. An empty state means the source has no addresses, and the old ones go at once, as they do for a [command](sources.md#runs-and-lifetimes) that prints nothing.

While Home Assistant restarts, the source waits. The source waits in each of these cases:

- Home Assistant isn't connected.
- The entity is `unknown` or `unavailable`, or its attribute is `None`. Entities are in that state until their integration is up.

Waiting isn't a failure:

- The addresses stay for the source's `lifetime`. Make the lifetime longer than a restart of Home Assistant takes.
- The log says when the wait starts and when it ends, at info level. It warns if the wait lasts longer than the lifetime, which is when the addresses go.

It is an error when Home Assistant has been connected for 30 seconds and hasn't sent the entity's state. Home Assistant then has no entity with that id, or the entity has no such attribute.

Home Assistant sends every state again each time it connects, and only those states count. So an entity that was deleted or renamed while Home Assistant restarted shows up as that error. It doesn't keep its last address.

## Recipes

The blocks headed `# Home Assistant` go in Home Assistant's configuration: `configuration.yaml`, or a package. You can also create the helpers in Home Assistant's UI, under *Settings → Devices & services → Helpers*. The other blocks go in the configuration of ipv6ddns.

### A record you set by hand

A text helper holds the address, and a name follows it. Set the helper from a dashboard, from an automation with `input_text.set_value`, or with Assist. When you clear the helper, the record goes at once. While Home Assistant restarts, the record stays.

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

The helper takes one or more addresses, separated by commas or spaces: `203.0.113.7, 2001:db8::7`.

### Switching a name between servers

A select helper picks the server, and a template sensor gives that server's address. You can move the name to the standby by hand, for maintenance. An automation can also move it when the primary stops answering.

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

Home Assistant may know a device on a network that ipv6ddns can't discover, such as a VLAN ipv6ddns isn't on. A router's integration gives each device tracker its address in the `ip` attribute, and a source can read it. That address is private, so its record goes in the local network's DNS. Here that's a zone on a Technitium server.

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

- **If the integration removes the attribute**, Home Assistant sends nothing, so ipv6ddns keeps the last address until Home Assistant reconnects. After that, the missing state is an error.
- **If the integration sets the attribute to none**, Home Assistant sends `None`. That is a wait, and the record stays for the source's `lifetime`.

### Two WANs in one record

A template sensor joins the public addresses of two internet connections, and leaves out a connection that is down. The name then only has addresses that answer.

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

The device's entities can drive automations. This example has two:

- A notification when a name's update keeps failing.
- An update of every name when the router comes back, instead of waiting for the next change that discovery sees.

The entity ids come from the [names' domains](#the-entities), `home.example.com` here. Home Assistant lists them under *Settings → Devices & services → ESPHome → ipv6ddns*.

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

ipv6ddns speaks the ESPHome native API, the way ESPHome 2026.11 does. The connection is encrypted with the key, using Noise_NNpsk0_25519_ChaChaPoly_SHA256. The device announces itself as `_esphomelib._tcp`.

Home Assistant knows the device by its MAC. The MAC comes from the identity in the state file, or from a fixed key. Keep the state file or the key, and Home Assistant keeps the device.

Like ESPHome devices, the device drops a connection that sends nothing for 150 seconds, or that reads nothing for 10 seconds. Home Assistant pings every 20 seconds, which prevents the first. After a drop, Home Assistant connects again.

CI tests the device with `aioesphomeapi`, the library Home Assistant's integration uses, at the version Home Assistant ships.
