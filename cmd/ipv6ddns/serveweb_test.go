package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

// serveWeb serves HTTP, or HTTPS by HTTP/2 and HTTP/1.1 with a TLS configuration, until shut down,
// which is no error; a listener that fails is one.
func TestServeWeb(t *testing.T) {
	// The test's certificate, which its client trusts, for 127.0.0.1.
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	defer ts.Close()
	cert := ts.TLS.Certificates[0]
	transport := ts.Client().Transport.(*http.Transport).Clone()
	transport.ForceAttemptHTTP2 = true
	client := &http.Client{Transport: transport}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })
	for _, c := range []struct {
		name, scheme string
		tls          *tls.Config
		proto        int
	}{
		{"HTTP", "http", nil, 1},
		{"HTTPS", "https", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &http.Server{Handler: handler, TLSConfig: c.tls}
			done := make(chan error, 1)
			go func() { done <- serveWeb(zap.NewNop().Sugar(), server, l) }()
			resp, err := client.Get(c.scheme + "://" + l.Addr().String() + "/")
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(body) != "ok" || resp.ProtoMajor != c.proto {
				t.Errorf("%q over HTTP/%d", body, resp.ProtoMajor)
			}
			if err := server.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Errorf("after the shutdown: %v", err)
			}
		})
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if err := serveWeb(zap.NewNop().Sugar(), &http.Server{Handler: handler}, l); err == nil {
		t.Error("a closed listener served")
	}
}
