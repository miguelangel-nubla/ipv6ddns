# Certificates for other machines

Your NAS, a reverse proxy or any other machine gets a certificate from Let's Encrypt for its name, `nas.lan.example.com`, by the DNS challenge. Its ACME client, certbot, lego or acme.sh, sends the challenge's TXT record to ipv6ddns, signed with a key of its own. ipv6ddns writes the record through the credential of your public zone, as it does for its [own certificates](../resolver.md#a-certificate-from-lets-encrypt).

So the machine never holds your DNS provider's token. Its key can write the challenge of its own names, and nothing else. Nothing about the name needs to be public, except the certificate itself, which every certificate authority logs.

## What you need

- ipv6ddns running with a [resolver](../resolver.md), here on `192.168.1.2`.
- A credential of your public zone that can write TXT records: `cloudflare`, `route53`, `rfc2136` or `duckdns`. Here, Cloudflare's, of `example.com`.
- On the machine, an ACME client that speaks RFC 2136: certbot with its `dns-rfc2136` plugin, lego, or acme.sh with `nsupdate`.

## The configuration

Make a key for the machine, on any machine with BIND's tools:

```
tsig-keygen -a hmac-sha256 nas
```

It prints the key. Its secret is the base64 after `secret`: put it in a file beside the configuration, `tsig_nas`.

```yaml
credentials:
  public:
    provider: cloudflare
    settings:
      api_token: ${file:cloudflare_token}
      zone: example.com
      ttl: 1h
      proxied: false

listeners:
  home:
    listen:
      - dns://192.168.1.2

resolvers:
  home:
    listeners:
      - home
    upstream:
      - 1.1.1.1
    updates:
      keys:
        nas:
          secret: ${file:tsig_nas}
          permissions:
            - challenges:
                credential: public
                names:
                  - nas.lan
                  - "*.nas.lan"
```

- **`keys.nas`** is the key, by the name the client gives it.
- **`challenges`** lets it write the TXT records of the DNS challenge, `_acme-challenge.nas.lan.example.com`, through `public`. The names are relative to the credential's zone. A wildcard shares its parent's challenge, so `*.nas.lan` adds nothing to what `nas.lan` allows, but writing it says what the certificate is for.
- **Who may send.** The key is used from the resolver's `allow`, by default the networks it listens on. To narrow it, give the key an `allow` of its own: see [where updates may come from](../resolver.md#where-updates-may-come-from).

Restart ipv6ddns. Its log says nothing more until the first update.

## The client

### certbot

Install the plugin: `apt install python3-certbot-dns-rfc2136`, or the `certbot/dns-rfc2136` container. Write its settings, `/etc/letsencrypt/rfc2136.ini`, readable by root alone:

```
dns_rfc2136_server = 192.168.1.2
dns_rfc2136_port = 53
dns_rfc2136_name = nas
dns_rfc2136_secret = <the secret of tsig_nas>
dns_rfc2136_algorithm = HMAC-SHA256
dns_rfc2136_sign_query = true
```

```
certbot certonly --dns-rfc2136 --dns-rfc2136-credentials /etc/letsencrypt/rfc2136.ini \
  --dns-rfc2136-propagation-seconds 30 -d nas.lan.example.com -d '*.nas.lan.example.com'
```

- **`dns_rfc2136_server`** is an address: certbot's plugin takes no name.
- **`sign_query = true`** is needed: certbot finds the zone with SOA queries, and ipv6ddns answers them, for the key's names, only when they are signed.
- **`--dns-rfc2136-propagation-seconds`** is how long certbot waits before Let's Encrypt checks. ipv6ddns answers once the provider took the record; 30 seconds leaves time for its servers to serve it.

certbot renews by itself, with the same settings.

### lego

```
DNSUPDATE_NAMESERVER=192.168.1.2:53 \
DNSUPDATE_TSIG_KEY=nas \
DNSUPDATE_TSIG_SECRET=<the secret of tsig_nas> \
DNSUPDATE_TSIG_ALGORITHM=hmac-sha256. \
lego run --email you@example.com --dns dnsupdate --domains nas.lan.example.com
```

lego finds the zone through the public DNS, and checks the record there before Let's Encrypt does, of the machine's own DNS servers. When those cache, that check can fail: see [the record doesn't show](#common-problems). Give it a public resolver to ask, `--dns.resolvers 1.1.1.1:53`, and it sees the record as Let's Encrypt does. Before lego 5, the provider was `rfc2136`, and its variables `RFC2136_NAMESERVER` and so on.

### acme.sh

Write the key as BIND does, `/etc/acme/nas.key`:

```
key "nas" {
	algorithm hmac-sha256;
	secret "<the secret of tsig_nas>";
};
```

```
NSUPDATE_SERVER=192.168.1.2 NSUPDATE_KEY=/etc/acme/nas.key \
acme.sh --issue --dns dns_nsupdate -d nas.lan.example.com
```

## Check that it works

The client says it got the certificate. ipv6ddns logs each record it wrote and removed:

```
resolver home: key nas: updated challenges: _acme-challenge.nas.lan.example.com
```

The web report lists the key under the resolver, with its counts and its last update, and `/status.json` has them too. When nothing is logged, the client's updates don't reach ipv6ddns: check `dns_rfc2136_server`, and that the machine is in the key's `allow`.

## Common problems

- **`NOTAUTH`, and `BADSIG` in the log.** The secret is wrong. Copy it again from `tsig_nas`, the base64 alone.
- **`NOTAUTH`, and `BADKEY`.** The key's name isn't one of `keys`, or its algorithm isn't the key's: `HMAC-SHA256` by default.
- **`NOTAUTH`, and `BADTIME`.** The clocks of the machine and of ipv6ddns are more than 5 minutes apart. Set up NTP on both.
- **`REFUSED`.** The log says why: a name outside the key's `names`, a machine outside its `allow`, or an update without a signature.
- **`SERVFAIL`.** The provider refused to write the record: the log has its error, such as a token without the permission to edit DNS.
- **certbot can't find the zone.** `dns_rfc2136_sign_query` must be `true`.
- **Let's Encrypt doesn't see the record.** Wait longer before it checks: a larger `--dns-rfc2136-propagation-seconds`.
- **The client times out waiting for the record, which the provider has.** The client checks the record itself, through a DNS server of the network that cached its absence, from an earlier try: a name that wasn't there is remembered as absent for the zone's negative TTL, half an hour at Cloudflare. lego does so: give it `--dns.resolvers 1.1.1.1:53`, which asks a public resolver, or wait that long. certbot only waits its propagation seconds, and doesn't check.

## What to know

- **A key per machine.** One machine's key writes only its own names, so a machine taken over can't get certificates for others.
- **60 updates a minute, of each key.** Each update is a write at the provider: a client that tries again and again is refused past them, and doesn't use up the provider's limits of the account. A certificate of 30 names, each added and removed, is within them.
- **Its records are removed** when the client removes them, as clients do once Let's Encrypt has checked. One the client left is removed an hour later. What ipv6ddns wrote is kept in `challenges-<key>-<credential>.json` beside the configuration, so a removal after a restart, or the hour, still removes it.
- **ipv6ddns's own certificates** are its own: a name of `certificates` can't be a key's too.
- **Several names, or zones.** A key can have several `challenges` permissions, each of its credential, for names of several zones.

## More

- [Dynamic updates](../resolver.md#dynamic-updates): the keys, the permissions, and the answers.
- [Encrypted DNS for the clients](../resolver.md#encrypted-dns-for-the-clients): ipv6ddns's own certificate, for DNS over TLS.
- [The configuration reference](../reference/configuration.md#updates): every key.
