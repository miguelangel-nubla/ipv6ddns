package ddns

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/miguelangel-nubla/ipv6ddns/pkg/duration"
	"github.com/miguelangel-nubla/ipv6disc"
)

type OpenWrt struct {
	Address  string            `json:"address"`
	Username string            `json:"username"`
	Password string            `json:"password"`
	SSHKey   string            `json:"ssh_key"`
	HostKey  string            `json:"host_key"`
	Zone     string            `json:"zone"`
	TTL      duration.Duration `json:"ttl"`

	// Connects to run the commands, for tests: nil is over SSH.
	dial func() (commandRunner, error)

	// A change was sent and is not known to be committed and loaded by dnsmasq: the next update
	// commits and reloads, whatever it finds. Read and set during an update, one at a time.
	pending bool

	unverified unverifiedHostKeys
}

func (o *OpenWrt) Warnings() []string {
	return o.unverified.Warnings()
}

func init() {
	RegisterProvider("openwrt", NewOpenWrt)
}

func NewOpenWrt(settings json.RawMessage) (Service, error) {
	var service OpenWrt
	if err := decodeSettings(settings, "openwrt", &service); err != nil {
		return nil, err
	}
	return &service, nil
}

// Update changes the domain sections of the name, commits and reloads dnsmasq, in one command: a
// connection lost halfway doesn't leave half of it.
//
// uci shows the changes not committed yet as made. So after an update that failed, the next can
// find nothing to change with the changes still to commit, or committed and dnsmasq not reloaded:
// it commits and reloads then, rather than report as updated what dnsmasq doesn't serve.
func (o *OpenWrt) Update(hostname string, addrCollection *ipv6disc.AddrCollection) error {
	// One update of a router at a time: another's would commit the half of this one.
	defer lockDevice("openwrt", o.Address)()

	dial := o.dial
	if dial == nil {
		dial = o.connect
	}
	runner, err := dial()
	if err != nil {
		return err
	}
	defer runner.Close()

	// -X names the anonymous sections cfgXXXXXX rather than @domain[N], whose numbers shift when
	// one is deleted.
	output, err := runner.Run("uci -X show dhcp")
	if err != nil {
		return err
	}

	fqdn := FQDN(hostname, o.Zone)

	// The address of each of the name's domain sections.
	existingIPs := make(map[string]string) // IP -> section
	var idsToDelete []string
	for id, record := range uciDomains(string(output)) {
		// Whatever its case: dnsmasq answers with the sections of the name written in another.
		if !strings.EqualFold(record.name, fqdn) {
			continue
		}
		ip, ok := canonicalIP(record.ip)
		if !ok {
			continue
		}
		if _, duplicate := existingIPs[ip]; duplicate {
			idsToDelete = append(idsToDelete, id)
			continue
		}
		existingIPs[ip] = id
	}

	desiredIPs := desiredRecords(addrCollection)

	for ip, id := range existingIPs {
		if _, ok := desiredIPs[ip]; !ok {
			idsToDelete = append(idsToDelete, id)
		}
	}

	var ipsToAdd []string
	for ip := range desiredIPs {
		if _, exists := existingIPs[ip]; !exists {
			ipsToAdd = append(ipsToAdd, ip)
		}
	}

	var commands []string
	for _, id := range idsToDelete {
		commands = append(commands, fmt.Sprintf("uci delete dhcp.%s", id))
	}
	for _, ip := range ipsToAdd {
		// A named section, the same for the same name and address.
		hash := sha256.Sum256([]byte(fqdn + ip))
		id := "ipv6ddns_" + hex.EncodeToString(hash[:])[:8]
		commands = append(commands,
			fmt.Sprintf("uci set dhcp.%s=domain", id),
			fmt.Sprintf("uci set dhcp.%s.name=%s", id, shellQuote(fqdn)),
			fmt.Sprintf("uci set dhcp.%s.ip=%s", id, shellQuote(ip)),
		)
	}

	if len(commands) == 0 && !o.pending {
		// Nothing to change, unless an update before this process started left its changes to
		// commit.
		staged, err := runner.Run("uci changes dhcp")
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(staged)) == "" {
			return nil
		}
	}

	commands = append(commands, "uci commit dhcp", "/etc/init.d/dnsmasq reload")
	o.pending = true
	if _, err := runner.Run(strings.Join(commands, " && ")); err != nil {
		return err
	}
	// The reload returns before dnsmasq has read the records again: it is a signal, which procd
	// sends. The update ends once dnsmasq answers with them.
	var removed []string
	for ip := range existingIPs {
		if _, ok := desiredIPs[ip]; !ok {
			removed = append(removed, ip)
		}
	}
	if err := o.served(runner, string(output), fqdn, slices.Collect(maps.Keys(desiredIPs)), removed); err != nil {
		return err
	}
	o.pending = false
	return nil
}

// How long dnsmasq has to answer with the records of an update, after its reload; how long it
// has to answer at all, as it doesn't while it starts again; and how often it is asked.
var (
	openWrtServedTimeout    = 10 * time.Second
	openWrtReachableTimeout = 3 * time.Second
	openWrtServedInterval   = 100 * time.Millisecond
)

// served waits for the router's dnsmasq to answer for fqdn with every address of want and none
// of removed: an error, once the time is up. It asks on the router, at 127.0.0.1, where dnsmasq
// answers unless it was moved: with another port, with more than one dnsmasq, or when nothing
// answers there, there is nothing to ask, and the reload is taken as done, as it was before.
// Other addresses of the name, as those of a static lease, are not of the update.
func (o *OpenWrt) served(runner commandRunner, config, fqdn string, want, removed []string) error {
	if !dnsmasqAtDefault(config) {
		return nil
	}
	var got []string
	answered := false
	for begun := time.Now(); ; time.Sleep(openWrtServedInterval) {
		// It ends with an error for a name without addresses, which is an answer too.
		output, err := runner.Run("nslookup " + shellQuote(fqdn) + " 127.0.0.1 2>&1 || true")
		if err != nil {
			return err
		}
		var reached bool
		reached, got = nslookupAddresses(string(output))
		answered = answered || reached
		ok := reached
		for _, ip := range want {
			ok = ok && slices.Contains(got, ip)
		}
		for _, ip := range removed {
			ok = ok && !slices.Contains(got, ip)
		}
		if ok {
			return nil
		}
		if waited := time.Since(begun); !answered && waited >= openWrtReachableTimeout {
			return nil
		} else if waited >= openWrtServedTimeout {
			break
		}
	}
	slices.Sort(want)
	return fmt.Errorf("the records of %s are written, but after %s dnsmasq answers at 127.0.0.1 with %v, not with %v: is its reload failing? See logread on the router", fqdn, openWrtServedTimeout, got, want)
}

// dnsmasqAtDefault is whether the dhcp configuration, as uci -X show dhcp gives it, has one
// dnsmasq, at port 53.
func dnsmasqAtDefault(config string) bool {
	instances := map[string]bool{}
	for line := range strings.SplitSeq(config, "\n") {
		key, value, _ := strings.Cut(strings.TrimSpace(line), "=")
		id, option, isOption := strings.Cut(strings.TrimPrefix(key, "dhcp."), ".")
		switch {
		case !isOption && value == "dnsmasq":
			instances[id] = true
		case option == "port" && instances[id] && strings.Trim(value, "'") != "53":
			return false
		}
	}
	return len(instances) <= 1
}

// nslookupAddresses reads what BusyBox's nslookup wrote: whether a server answered, and the
// addresses of the name, each as canonicalIP writes it.
func nslookupAddresses(output string) (reached bool, addresses []string) {
	name := false
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		switch {
		case len(fields) == 0:
			name = false
		case fields[0] == "Server:":
			reached = true
		case fields[0] == "Name:":
			name = true
		case name && strings.HasPrefix(fields[0], "Address"):
			if ip, ok := canonicalIP(fields[len(fields)-1]); ok {
				addresses = append(addresses, ip)
			}
		}
	}
	slices.Sort(addresses)
	return reached, addresses
}

// connect logs in over SSH, to run the commands of an update.
func (o *OpenWrt) connect() (commandRunner, error) {
	client, hostKey, err := dialSSH(sshTarget{o.Address, o.Username, o.Password, o.SSHKey, o.HostKey})
	if err != nil {
		return nil, err
	}
	if o.HostKey == "" {
		o.unverified.note(o.Address, hostKey)
	}
	return newSSHCommandRunner(client), nil
}

type uciDomain struct {
	name string
	ip   string
}

// uciDomains reads the domain sections, the DNS records of dnsmasq, out of `uci -X show dhcp`, by
// section ID. Its lines are:
//
//	dhcp.cfg0af37d=domain
//	dhcp.cfg0af37d.name='host.lan'
//	dhcp.cfg0af37d.ip='192.168.1.10'
//
// The other sections, such as the static leases of hosts, have names and addresses too.
func uciDomains(output string) map[string]uciDomain {
	types := make(map[string]string)
	options := make(map[string]map[string]string)
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		// A quoted value has both its quotes: one alone is no value of uci's.
		if quoted, ok := strings.CutPrefix(value, "'"); ok {
			if value, ok = strings.CutSuffix(quoted, "'"); !ok {
				continue
			}
		} else if strings.Contains(value, "'") {
			continue
		}
		path := strings.Split(key, ".")
		if len(path) < 2 || path[0] != "dhcp" || path[1] == "" {
			continue
		}
		id := path[1]
		switch len(path) {
		case 2:
			types[id] = value
		case 3:
			if options[id] == nil {
				options[id] = make(map[string]string)
			}
			options[id][path[2]] = value
		}
	}

	domains := make(map[string]uciDomain)
	for id, sectionType := range types {
		if sectionType == "domain" {
			domains[id] = uciDomain{name: options[id]["name"], ip: options[id]["ip"]}
		}
	}
	return domains
}

// shellQuote makes s a single-quoted shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (o *OpenWrt) Domain(hostname string) string {
	return FQDN(hostname, o.Zone)
}
