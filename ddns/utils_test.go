package ddns

import (
	"testing"
)

func TestFQDN(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		zone     string
		want     string
	}{
		{
			name:     "simple",
			hostname: "host1",
			zone:     "example.com",
			want:     "host1.example.com",
		},
		{
			name:     "hostname with zone suffix",
			hostname: "host1.example.com",
			zone:     "example.com",
			want:     "host1.example.com",
		},
		{
			name:     "hostname ending like the zone",
			hostname: "myexample.com",
			zone:     "example.com",
			want:     "myexample.com.example.com",
		},
		{
			name:     "hostname that is the zone",
			hostname: "example.com",
			zone:     "example.com",
			want:     "example.com",
		},
		{
			// By design, as the one above: a name written in full. What keeps a device called
			// lan, of a {hostname} template, from writing the zone's own records is the worker.
			name:     "hostname that is a zone of one label",
			hostname: "lan",
			zone:     "lan",
			want:     "lan",
		},
		{
			name:     "empty hostname",
			hostname: "",
			zone:     "example.com",
			want:     "example.com",
		},
		{
			name:     "empty zone",
			hostname: "host1.com",
			zone:     "",
			want:     "host1.com",
		},
		{
			name:     "hostname with zone suffix in another case",
			hostname: "host1.Example.COM",
			zone:     "example.com",
			want:     "host1.Example.COM",
		},
		{
			name:     "trailing dots",
			hostname: "host1.",
			zone:     "example.com.",
			want:     "host1.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FQDN(tt.hostname, tt.zone); got != tt.want {
				t.Errorf("FQDN(%q, %q) = %q, want %q", tt.hostname, tt.zone, got, tt.want)
			}
		})
	}
}

func TestSplitFQDN(t *testing.T) {
	tests := []struct {
		name     string
		fqdn     string
		wantHost string
		wantDom  string
	}{
		{
			name:     "simple",
			fqdn:     "host1.example.com",
			wantHost: "host1",
			wantDom:  "example.com",
		},
		{
			name:     "two parts",
			fqdn:     "example.com",
			wantHost: "example",
			wantDom:  "com",
		},
		{
			name:     "subdomain",
			fqdn:     "sub.host1.example.com",
			wantHost: "sub",
			wantDom:  "host1.example.com",
		},
		{
			name:     "no dots",
			fqdn:     "hostname",
			wantHost: "hostname",
			wantDom:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotHost, gotDom := SplitFQDN(tt.fqdn)
			if gotHost != tt.wantHost || gotDom != tt.wantDom {
				t.Errorf("SplitFQDN(%q) = (%q, %q), want (%q, %q)", tt.fqdn, gotHost, gotDom, tt.wantHost, tt.wantDom)
			}
		})
	}
}

func TestRelativeName(t *testing.T) {
	for _, tt := range []struct{ hostname, zone, want string }{
		{"host1", "example.com", "host1"},
		{"host1.example.com", "example.com", "host1"},
		{"host1.example.com.", "example.com.", "host1"},
		{"Host1.Example.COM", "example.com", "Host1"},
		{"a.host1", "example.com", "a.host1"},
		{"*.host1.example.com", "example.com", "*.host1"},
		{"myexample.com", "example.com", "myexample.com"},
		{"", "example.com", ""},
		{"example.com", "example.com", ""},
		{"example.com.", "Example.com", ""},
		{"host1.com", "", "host1.com"},
	} {
		if got := RelativeName(tt.hostname, tt.zone); got != tt.want {
			t.Errorf("RelativeName(%q, %q) = %q, want %q", tt.hostname, tt.zone, got, tt.want)
		}
	}
}
