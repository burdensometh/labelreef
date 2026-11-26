package serve

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"labelreef/reload"
	"labelreef/zone"
)

func controlFor(t *testing.T) (*Control, reload.Config) {
	t.Helper()
	path, cfg := copyConfig(t)
	manager := managerAt(t, path, cfg, reload.Boundary{})
	server := testServer(t, manager, nil)
	return &Control{Manager: manager, DNS: server}, cfg
}

func get(t *testing.T, c *Control, host, target string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Host, r.RemoteAddr = host, "127.0.0.1:50200"
	r.Header.Set(ControlHeader, ControlValue)
	out := httptest.NewRecorder()
	c.ServeHTTP(out, r)
	return out
}

func post(t *testing.T, c *Control, host string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/publish", bytes.NewReader(body))
	r.Host, r.RemoteAddr = host, "127.0.0.1:50200"
	r.Header.Set(ControlHeader, ControlValue)
	r.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	c.ServeHTTP(out, r)
	return out
}

func TestExportV2AndPublishV2(t *testing.T) {
	control, cfg := controlFor(t)

	v1 := get(t, control, cfg.Control, "/v1/export?origin=lab.test.")
	if v1.Code != http.StatusOK {
		t.Fatalf("v1 export: %d %s", v1.Code, v1.Body.String())
	}
	var v1File zone.FileV1
	if err := zone.DecodeJSON(bytes.NewReader(v1.Body.Bytes()), zone.MaxV1Bytes, &v1File); err != nil ||
		v1File.Version != 1 {
		t.Fatalf("default export is not v1: %v", err)
	}

	v2 := get(t, control, cfg.Control, "/v1/export?origin=lab.test.&format=v2")
	if v2.Code != http.StatusOK {
		t.Fatalf("v2 export: %d %s", v2.Code, v2.Body.String())
	}
	v2Bytes := append([]byte(nil), v2.Body.Bytes()...)
	var v2File zone.FileV2
	if err := zone.DecodeJSON(bytes.NewReader(v2Bytes), zone.MaxV2Bytes, &v2File); err != nil ||
		v2File.Version != 2 {
		t.Fatalf("v2 export envelope wrong: %v", err)
	}
	if len(v2File.RRSets) == 0 || v2File.RRSets[0].TTL == nil || len(v2File.RRSets[0].Records) == 0 {
		t.Fatal("v2 export missing grouped RRset shape")
	}
	if again := get(t, control, cfg.Control, "/v1/export?origin=lab.test.&format=v2"); again.Code != http.StatusOK || !bytes.Equal(again.Body.Bytes(), v2Bytes) {
		t.Fatal("v2 export is not repeatable")
	}

	if bad := get(t, control, cfg.Control, "/v1/export?origin=lab.test.&format=v3"); bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "v1 or v2") {
		t.Fatalf("bad format rejected incorrectly: %d %s", bad.Code, bad.Body.String())
	}

	// Publishing the v2 envelope of the live zone is a no-op that still goes
	// through the generic decoder and the primary publish path.
	seed, err := os.ReadFile("../examples/zones/lab-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	if out := post(t, control, cfg.Control, seed); out.Code != http.StatusOK ||
		!strings.Contains(out.Body.String(), `"changed":false`) {
		t.Fatalf("identical v2 publish should be a no-op: %d %s", out.Code, out.Body.String())
	}

	// Two RRsets with the same canonical owner/type must be refused even when
	// their relative spellings differ, so an RRset TTL has one source.
	var conflictFile zone.FileV2
	if err := zone.DecodeJSON(bytes.NewReader(seed), zone.MaxV2Bytes, &conflictFile); err != nil {
		t.Fatal(err)
	}
	conflictTTL := uint32(301)
	conflictFile.RRSets = append(conflictFile.RRSets, zone.RRsetV2{
		Name: "ns", Type: "A", TTL: &conflictTTL, Records: []string{"192.0.2.54"},
	})
	var conflict bytes.Buffer
	if err := zone.EncodeJSON(&conflict, conflictFile); err != nil {
		t.Fatal(err)
	}
	if out := post(t, control, cfg.Control, conflict.Bytes()); out.Code != http.StatusConflict ||
		!strings.Contains(out.Body.String(), "conflicts with rrset") {
		t.Fatalf("conflicting v2 RRset accepted: %d %s", out.Code, out.Body.String())
	}

	// A v2 envelope carrying an unknown field must be refused.
	badBody := bytes.Replace(seed, []byte(`"rrsets":`), []byte(`"extra": 1, "rrsets":`), 1)
	if bytes.Equal(badBody, seed) {
		t.Fatal("unknown-field fixture pattern not found")
	}
	if out := post(t, control, cfg.Control, badBody); out.Code != http.StatusConflict ||
		!strings.Contains(out.Body.String(), "unknown field") {
		t.Fatalf("unknown v2 field accepted: %d %s", out.Code, out.Body.String())
	}
}
