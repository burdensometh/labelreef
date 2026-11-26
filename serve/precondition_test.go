package serve

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"labelreef/reload"
	"labelreef/serial"
	"labelreef/transfer"
	"labelreef/zone"
)

func decodeInlineEdit(t *testing.T, body string) serial.EditV1 {
	t.Helper()
	edit, err := serial.DecodeEdit(strings.NewReader(body))
	if err != nil {
		t.Fatalf("decode edit: %v", err)
	}
	return edit
}

func primaryStateFile(t *testing.T, cfg reload.Config) string {
	t.Helper()
	sum := sha256.Sum256([]byte("lab.test."))
	return filepath.Join(cfg.StateDir, hex.EncodeToString(sum[:])+".json")
}

func stateHistoryCount(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var state struct {
		Version    int              `json:"version"`
		Generation uint64           `json:"generation"`
		Zone       any              `json:"zone"`
		History    []map[string]any `json:"history"`
	}
	if err := zone.DecodeJSON(f, serial.MaxStateBytes, &state); err != nil {
		t.Fatal(err)
	}
	return len(state.History)
}

// TestGuardedEditAppliesAcrossUnrelatedChange drives the full manager path:
// an unrelated edit advances the serial, then a guarded edit whose RRset
// preconditions still hold applies against the current zone.
func TestGuardedEditAppliesAcrossUnrelatedChange(t *testing.T) {
	path, cfg := copyConfig(t)
	manager := managerAt(t, path, cfg, reload.Boundary{})

	unrelated := decodeInlineEdit(t, `{"version":1,"origin":"lab.test.","base":4294967294,`+
		`"next":4294967295,"remove":[],"add":[`+
		`{"name":"head","type":"A","ttl":60,"data":"192.0.2.20"}]}`)
	receipt, err := manager.Edit(unrelated)
	if err != nil || receipt.Serial != 4294967295 || !receipt.Changed {
		t.Fatalf("unrelated edit: %+v %v", receipt, err)
	}

	guarded := decodeInlineEdit(t, `{"version":1,"origin":"lab.test.","base":4294967294,"next":5,`+
		`"preconditions":[{"name":"www","type":"A","ttl":120,"records":[`+
		`{"name":"www","type":"A","ttl":120,"data":"192.0.2.11"},`+
		`{"name":"www","type":"A","ttl":120,"data":"192.0.2.10"}]}],`+
		`"remove":[],"add":[`+
		`{"name":"guarded","type":"TXT","ttl":120,"data":"\"rrset precondition held\""}]}`)
	receipt, err = manager.Edit(guarded)
	if err != nil || receipt.Serial != 5 || !receipt.Changed {
		t.Fatalf("guarded edit: %+v %v", receipt, err)
	}

	active, err := manager.Export("lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	if len(active.Set("www.lab.test.", zone.A).Records) != 2 {
		t.Fatal("precondition RRset was modified")
	}
	if len(active.Set("guarded.lab.test.", zone.TXT).Records) != 1 ||
		len(active.Set("head.lab.test.", zone.A).Records) != 1 {
		t.Fatal("guarded or unrelated record missing after application")
	}

	statePath := primaryStateFile(t, cfg)
	if count := stateHistoryCount(t, statePath); count != 2 {
		t.Fatalf("retained history = %d, want 2 deltas", count)
	}
	// The committed journal contains exactly the two applied edits.
	plan, err := manager.Transfer(transfer.Request{
		Origin: "lab.test.", Type: zone.IXFR, HasSerial: true, Serial: 4294967294,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind() != transfer.Incremental {
		t.Fatalf("transfer kind = %s, want ixfr", plan.Kind())
	}
}

// TestFailedPreconditionWritesNothing proves a rejected guarded edit leaves
// the active zone, the durable file and the transfer history untouched.
func TestFailedPreconditionWritesNothing(t *testing.T) {
	path, cfg := copyConfig(t)
	manager := managerAt(t, path, cfg, reload.Boundary{})
	statePath := primaryStateFile(t, cfg)

	unrelated := decodeInlineEdit(t, `{"version":1,"origin":"lab.test.","base":4294967294,`+
		`"next":4294967295,"remove":[`+
		`{"name":"www","type":"A","ttl":120,"data":"192.0.2.10"}],`+
		`"add":[{"name":"www","type":"A","ttl":120,"data":"192.0.2.12"}]}`)
	if _, err := manager.Edit(unrelated); err != nil {
		t.Fatal(err)
	}
	before, err := manager.Export("lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	bytesBefore, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	historyBefore := stateHistoryCount(t, statePath)

	guarded := editFromFixture(t, "guarded-www")
	receipt, err := manager.Edit(guarded)
	if err == nil || !strings.Contains(err.Error(), "precondition failed") {
		t.Fatalf("stale precondition was accepted: %+v %v", receipt, err)
	}

	after, err := manager.Export("lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	if !serial.Same(before, after) {
		t.Fatal("rejected edit changed the active zone")
	}
	if bytesAfter, err := os.ReadFile(statePath); err != nil || !strings.EqualFold(
		sha256Hex(bytesBefore), sha256Hex(bytesAfter)) {
		t.Fatalf("rejected edit changed durable state: %v", err)
	}
	if count := stateHistoryCount(t, statePath); count != historyBefore {
		t.Fatalf("rejected edit produced a transfer delta: %d -> %d", historyBefore, count)
	}

	plan, err := manager.Transfer(transfer.Request{
		Origin: "lab.test.", Type: zone.IXFR, HasSerial: true, Serial: 4294967294,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind() != transfer.Incremental {
		t.Fatalf("transfer kind = %s, want ixfr", plan.Kind())
	}
	if plan.Count() == 0 {
		t.Fatal("expected the single earlier delta in the transfer")
	}
	// Repeating the rejected edit must remain rejected and side-effect free.
	if _, err := manager.Edit(editFromFixture(t, "guarded-www")); err == nil {
		t.Fatal("repeat of a failed precondition edit was accepted")
	}
}

// TestFailedPreconditionReturnsConflict checks the HTTP control surface maps
// a precondition failure to 409 Conflict and carries the reason text.
func TestFailedPreconditionReturnsConflict(t *testing.T) {
	path, cfg := copyConfig(t)
	manager := managerAt(t, path, cfg, reload.Boundary{})
	server := testServer(t, manager, nil)
	control := Control{Manager: manager, DNS: server}

	if _, err := manager.Edit(decodeInlineEdit(t, `{"version":1,"origin":"lab.test.",`+
		`"base":4294967294,"next":4294967295,"remove":[`+
		`{"name":"www","type":"A","ttl":120,"data":"192.0.2.10"}],`+
		`"add":[{"name":"www","type":"A","ttl":120,"data":"192.0.2.12"}]}`)); err != nil {
		t.Fatal(err)
	}

	body := strings.NewReader(`{"version":1,"origin":"lab.test.","base":4294967294,"next":5,` +
		`"preconditions":[{"name":"www","type":"A","ttl":120,"records":[` +
		`{"name":"www","type":"A","ttl":120,"data":"192.0.2.11"},` +
		`{"name":"www","type":"A","ttl":120,"data":"192.0.2.10"}]}],` +
		`"remove":[],"add":[]}`)
	r := httptest.NewRequest(http.MethodPost, "/v1/edit", body)
	r.Host, r.RemoteAddr = cfg.Control, "127.0.0.1:50201"
	r.Header.Set(ControlHeader, ControlValue)
	r.Header.Set("Content-Type", "application/json")
	out := httptest.NewRecorder()
	control.ServeHTTP(out, r)
	if out.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", out.Code, http.StatusConflict, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), "precondition failed") {
		t.Fatalf("conflict body missing reason: %s", out.Body.String())
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
