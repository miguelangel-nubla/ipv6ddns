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
