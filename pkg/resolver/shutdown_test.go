package resolver

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// inFlight asks s a name its slow upstream server takes a second to answer, and returns once the
// query is there: the answer, or the error, comes on the channel.
func inFlight(t *testing.T, s *Server, up *upstream, network string) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	before := up.queries.Load()
	go func() {
		m := new(dns.Msg)
		m.SetQuestion("example.org.", dns.TypeA)
		resp, _, err := (&dns.Client{Net: network, Timeout: 5 * time.Second}).Exchange(m, s.Addresses()[0])
		if err == nil && (resp.Rcode != dns.RcodeSuccess || !slices.Equal(answers(resp), []string{"example.org. A 192.0.2.53"})) {
			err = errors.New(resp.String())
		}
		done <- err
	}()
	for deadline := time.Now().Add(3 * time.Second); up.queries.Load() == before; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the query never reached the upstream server")
		}
	}
	return done
}

// A shutdown waits for the queries being answered, for as long as its context gives: one whose
// upstream server takes a second is answered, over UDP and over TCP, and no new one is.
func TestShutdownAnswersInFlight(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			up := newUpstream(t)
			up.slow.Store(true)
			cfg, _ := testConfig(t, up.address)
			s := startWith(t, cfg, func(s *Server) { s.timeout = 5 * time.Second })
			address := s.Addresses()[0]
			done := inFlight(t, s, up, network)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			began := time.Now()
			if err := s.Shutdown(ctx); err != nil {
				t.Fatalf("shutdown: %v", err)
			}
			// As long as the query took, of the upstream server's second; not as long as the context gives.
			if took := time.Since(began); took < 500*time.Millisecond || took > 5*time.Second {
				t.Errorf("the shutdown took %s, want the second of the query", took.Round(time.Millisecond))
			}
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("the query being answered: %v", err)
				}
			case <-time.After(time.Second):
				t.Error("the query being answered had no answer by the end of the shutdown")
			}
			if st := s.Status(); st.Serving || st.Queries[Forwarded] != 1 {
				t.Errorf("status: %+v", st)
			}
			if _, _, err := (&dns.Client{Net: network, Timeout: 300 * time.Millisecond}).Exchange(new(dns.Msg).SetQuestion("printer.home.arpa.", dns.TypeA), address); err == nil {
				t.Error("answering once stopped")
			}
		})
	}
}

// Its context done, the shutdown gives up the queries still asked upstream, and ends.
func TestShutdownGivesUp(t *testing.T) {
	up := newUpstream(t)
	up.slow.Store(true)
	cfg, _ := testConfig(t, up.address)
	s := startWith(t, cfg, func(s *Server) { s.timeout = 5 * time.Second })
	done := inFlight(t, s, up, "tcp")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	began := time.Now()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("shutdown: %v, want that its time was over", err)
	}
	if took := time.Since(began); took < 150*time.Millisecond || took > 700*time.Millisecond {
		t.Errorf("the shutdown took %s, want the 200ms of its context", took.Round(time.Millisecond))
	}
	// The query was given up then, not a second later with the upstream server's answer.
	select {
	case err := <-done:
		if err == nil {
			t.Error("the query was answered as if the upstream server had")
		}
	case <-time.After(700 * time.Millisecond):
		t.Error("the query was still being asked upstream after the shutdown")
	}
}
