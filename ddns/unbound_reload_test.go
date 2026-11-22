package ddns

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// An OPNsense whose reconfigure fails once: the override is saved, and Unbound doesn't serve it.
// The next update finds nothing to change, and must reconfigure still, not report as updated
// what Unbound doesn't serve.
func TestOpnsenseUnboundReconfiguresAfterFailure(t *testing.T) {
	var mutex sync.Mutex
	var overrides []map[string]string
	reconfigures, failReconfigure := 0, true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		switch r.URL.Path {
		case "/api/unbound/settings/searchHostOverride":
			writeJSON(w, map[string]any{"rows": overrides})
		case "/api/unbound/settings/addHostOverride":
			var body struct{ Host map[string]string }
			json.NewDecoder(r.Body).Decode(&body)
			body.Host["uuid"] = "u1"
			overrides = append(overrides, body.Host)
			writeJSON(w, map[string]string{"result": "saved"})
		case "/api/unbound/service/reconfigure":
			reconfigures++
			if failReconfigure {
				failReconfigure = false
				http.Error(w, "busy", http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]string{"status": "ok"})
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	}))
	defer server.Close()

	service := &OpnsenseUnbound{Address: server.URL, Key: "key", Secret: "secret", Zone: "lan"}
	if err := service.Update("nas", collectionWith(wantedIP)); err == nil || !strings.Contains(err.Error(), "reconfigure") {
		t.Fatalf("the first update: %v, want the reconfigure's error", err)
	}
	if err := service.Update("nas", collectionWith(wantedIP)); err != nil {
		t.Fatal(err)
	}
	if reconfigures != 2 {
		t.Errorf("got %d reconfigures, want 2: the update after the failure, with nothing to change, reconfigures", reconfigures)
	}
	// And once it succeeded, nothing to change is nothing to do.
	if err := service.Update("nas", collectionWith(wantedIP)); err != nil {
		t.Fatal(err)
	}
	if reconfigures != 2 {
		t.Errorf("got %d reconfigures, want 2: none once nothing is left to apply", reconfigures)
	}
}

// The same of a pfSense whose apply fails once.
func TestPfsenseRestapiUnboundAppliesAfterFailure(t *testing.T) {
	type override struct {
		ID     int      `json:"id"`
		Host   string   `json:"host"`
		Domain string   `json:"domain"`
		IP     []string `json:"ip"`
	}
	var mutex sync.Mutex
	var overrides []override
	applies, failApply := 0, true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mutex.Lock()
		defer mutex.Unlock()
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v2/services/dns_resolver/host_overrides":
			writeJSON(w, map[string]any{"status": "ok", "code": 200, "data": overrides})
		case "POST /api/v2/services/dns_resolver/host_override":
			var body override
			json.NewDecoder(r.Body).Decode(&body)
			body.ID = len(overrides)
			overrides = append(overrides, body)
			writeJSON(w, map[string]any{"status": "ok", "code": 200})
		case "POST /api/v2/services/dns_resolver/apply":
			applies++
			if failApply {
				failApply = false
				http.Error(w, "busy", http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]any{"status": "ok", "code": 200})
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	service := &PfsenseRestapiUnbound{Address: server.URL, Key: "key", Zone: "lan"}
	if err := service.Update("nas", collectionWith(wantedIP)); err == nil || !strings.Contains(err.Error(), "apply") {
		t.Fatalf("the first update: %v, want the apply's error", err)
	}
	if err := service.Update("nas", collectionWith(wantedIP)); err != nil {
		t.Fatal(err)
	}
	if applies != 2 {
		t.Errorf("got %d applies, want 2: the update after the failure, with nothing to change, applies", applies)
	}
	if err := service.Update("nas", collectionWith(wantedIP)); err != nil {
		t.Fatal(err)
	}
	if applies != 2 {
		t.Errorf("got %d applies, want 2: none once nothing is left to apply", applies)
	}
}
