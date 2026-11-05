package main

import (
	"net/http"
	"reflect"
	"testing"
)

func TestParseListenList(t *testing.T) {
	tests := []struct {
		list string
		want []string
	}{
		{"8053", []string{":8053"}},
		{":8053", []string{":8053"}},
		{"192.0.2.1", []string{"192.0.2.1:80"}},
		{"192.0.2.1:8053", []string{"192.0.2.1:8053"}},
		{"2001:db8::1", []string{"[2001:db8::1]:80"}},
		{"[2001:db8::1]", []string{"[2001:db8::1]:80"}},
		{"[2001:db8::1]:8053", []string{"[2001:db8::1]:8053"}},
		{"myhost", []string{"myhost:80"}},
		{"myhost:8053", []string{"myhost:8053"}},
		{"fe80::1%eth0", []string{"[fe80::1%eth0]:80"}},
		{"192.0.2.1, [2001:db8::1]:8053 ,myhost,9000", []string{"192.0.2.1:80", "[2001:db8::1]:8053", "myhost:80", ":9000"}},
		{"8053,:8053", []string{":8053"}},
	}
	for _, tt := range tests {
		got, err := parseListenList(tt.list)
		if err != nil {
			t.Errorf("parseListenList(%q): %v", tt.list, err)
		} else if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("parseListenList(%q) = %q, want %q", tt.list, got, tt.want)
		}
	}
}

func TestParseListenListRefuses(t *testing.T) {
	for _, list := range []string{"0", "65536", "192.0.2.1:0", "myhost:http", "192.0.2.1,", ",", "[2001:db8::1", "2001:db8::1]:80", "a:b:c"} {
		if got, err := parseListenList(list); err == nil {
			t.Errorf("parseListenList(%q) = %q, want an error", list, got)
		}
	}
}

func TestListenAll(t *testing.T) {
	// localhost resolves to 127.0.0.1 here too: one listener each, not an error for the repeat.
	addresses, err := parseListenList("127.0.0.1:18996,127.0.0.1:18997,localhost:18996")
	if err != nil {
		t.Fatal(err)
	}
	listeners, err := listenAll(addresses)
	if err != nil {
		t.Fatal(err)
	}
	if len(listeners) < 2 {
		t.Fatalf("got %d listeners, want at least 2", len(listeners))
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
	for _, listener := range listeners {
		defer listener.Close()
		go http.Serve(listener, mux)
		response, err := http.Get("http://" + listener.Addr().String() + "/")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
	}
	if _, err := listenAll([]string{addresses[0]}); err == nil {
		t.Error("listening twice on one address: want an error")
	}
}
