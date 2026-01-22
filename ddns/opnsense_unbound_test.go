package ddns

import (
	"testing"
)

func TestOpnsenseUnbound_SplitFQDN(t *testing.T) {
	tests := []struct {
		name     string
		zone     string
		fqdn     string
		wantHost string
		wantDom  string
	}{
		{
			name:     "simple host",
			zone:     "example.com",
			fqdn:     "host1.example.com",
			wantHost: "host1",
			wantDom:  "example.com",
		},
		{
			name:     "subdomain in host",
			zone:     "example.com",
			fqdn:     "sub1.host1.example.com",
			wantHost: "sub1",
			wantDom:  "host1.example.com",
		},
		{
			name:     "root domain",
			zone:     "example.com",
			fqdn:     "example.com",
			wantHost: "",
			wantDom:  "example.com",
		},
		{
			name:     "no zone set, simple host",
			zone:     "",
			fqdn:     "host1.com",
			wantHost: "host1",
			wantDom:  "com",
		},
		{
			name:     "no zone set, multiple parts",
			zone:     "",
			fqdn:     "a.b.c.d",
			wantHost: "a",
			wantDom:  "b.c.d",
		},
		{
			name:     "trailing dots",
			zone:     "example.com.",
			fqdn:     "host1.example.com.",
			wantHost: "host1",
			wantDom:  "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &OpnsenseUnbound{Zone: tt.zone}
			gotHost, gotDom := u.splitFQDN(tt.fqdn)
			if gotHost != tt.wantHost || gotDom != tt.wantDom {
				t.Errorf("splitFQDN(%q) got = (%q, %q), want (%q, %q)", tt.fqdn, gotHost, gotDom, tt.wantHost, tt.wantDom)
			}
		})
	}
}
