package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
			go func() { done <- serveWeb(zap.NewNop().Sugar(), "webservers.main", server, l) }()
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
	if err := serveWeb(zap.NewNop().Sugar(), "webservers.main", &http.Server{Handler: handler}, l); err == nil {
		t.Error("a closed listener served")
	}
}

// shortWebTimes makes the web servers' times short, for a test.
func shortWebTimes(t *testing.T, read, shutdown time.Duration) {
	t.Helper()
	savedRead, savedShutdown := webReadTimeout, webShutdownTimeout
	webReadTimeout, webShutdownTimeout = read, shutdown
	t.Cleanup(func() { webReadTimeout, webShutdownTimeout = savedRead, savedShutdown })
}

// A request whose body never comes, from anyone, with no password: the server, as main makes it,
// ends it at its read timeout, and then its stop has nothing to wait for.
func TestWebServerEndsAStalledBody(t *testing.T) {
	shortWebTimes(t, 300*time.Millisecond, 3*time.Second)
	_, handler := pushWorker(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := newWebServer(allowOnly(handler, nil), nil)
	go server.Serve(l)
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST /nic/update HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1000\r\n\r\nhostname=")
	// Answered, as a request that doesn't read, once the body's time is over.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer to a request whose body never comes: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("answered %d, want 400", resp.StatusCode)
	}
	start := time.Now()
	if err := stopWeb([]*http.Server{server}); err != nil || time.Since(start) > 2*time.Second {
		t.Errorf("the stop: %v, after %s: the request is over, and it has nothing to wait for", err, time.Since(start))
	}
}

// A web server made as main makes them has every time: none set would leave a connection open for
// as long as its client wants.
func TestWebServerTimes(t *testing.T) {
	server := newWebServer(http.NotFoundHandler(), nil)
	if server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.IdleTimeout <= 0 {
		t.Errorf("times: headers %s, read %s, idle %s", server.ReadHeaderTimeout, server.ReadTimeout, server.IdleTimeout)
	}
	// An answer has the time of the slowest: a body that took all of its time, then a refusal's wait.
	if server.WriteTimeout <= server.ReadTimeout+refusedWait {
		t.Errorf("write %s, not over read %s and the wait of a refusal, %s", server.WriteTimeout, server.ReadTimeout, refusedWait)
	}
}

// The web servers stop in a time of their own, short: a request that doesn't end is cut off after
// it, with an error, and the worker's stop, after, has all of its time.
func TestStopWebCutsOffARequestThatStays(t *testing.T) {
	shortWebTimes(t, webReadTimeout, 200*time.Millisecond)
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := newWebServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
	}), nil)
	go server.Serve(l)
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	<-entered
	start := time.Now()
	if err := stopWeb([]*http.Server{server}); err == nil {
		t.Error("a request still in progress, and no error")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("the stop took %s, of a time of %s", took, webShutdownTimeout)
	}
	// Cut off: the connection is closed.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("the connection after the stop: %v, want it closed", err)
	}
}
