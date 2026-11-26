package serve

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"labelreef/reload"
	"labelreef/serial"
	"labelreef/transfer"
	"labelreef/zone"
)

func batchFromFixture(t *testing.T, name string) serial.BatchEditV1 {
	t.Helper()
	f, err := os.Open("../examples/edits/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	batch, err := serial.DecodeBatchEdit(f)
	if err != nil {
		t.Fatal(err)
	}
	return batch
}

func probeZone(t *testing.T, server *Server, name string, typ zone.Type) ProbeResult {
	t.Helper()
	result, err := Probe(context.Background(), name, typ, ProbeOptions{
		Address: server.Address(), Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func soaSerial(t *testing.T, server *Server, origin string) uint32 {
	t.Helper()
	result := probeZone(t, server, origin, zone.SOA)
	if len(result.Answer) != 1 {
		t.Fatalf("SOA query for %s: %+v", origin, result)
	}
	rr, err := result.Answer[0].Record(origin)
	if err != nil {
		t.Fatal(err)
	}
	return rr.Data.SOA.Serial
}

func controlRequest(t *testing.T, control Control, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = control.Manager.Runtime().Control.String()
	r.RemoteAddr = "127.0.0.1:50200"
	r.Header.Set(ControlHeader, ControlValue)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	out := httptest.NewRecorder()
	control.ServeHTTP(out, r)
	return out
}

func TestBatchPublicationActivatesParentAndChildTogether(t *testing.T) {
	path, cfg := copyConfig(t)
	manager := managerAt(t, path, cfg, reload.Boundary{})
	server := testServer(t, manager, nil)

	beforeParent := soaSerial(t, server, "lab.test.")
	beforeChild := soaSerial(t, server, "child.lab.test.")
	if beforeParent != 4294967294 || beforeChild != 17 {
		t.Fatalf("unexpected starting serials: %d %d", beforeParent, beforeChild)
	}

	receipt, err := manager.PublishBatch(batchFromFixture(t, "batch-parent-child"))
	if err != nil {
		t.Fatal(err)
	}
	if !receipt.Changed || receipt.Parent.Origin != "lab.test." || receipt.Child.Origin != "child.lab.test." {
		t.Fatalf("unexpected batch receipt: %+v", receipt)
	}
	if receipt.Parent.Serial != 4294967295 || receipt.Child.Serial != 18 {
		t.Fatalf("each member must keep its own serial: %+v", receipt)
	}
	if got := soaSerial(t, server, "lab.test."); got != 4294967295 {
		t.Fatalf("parent serial after batch: %d", got)
	}
	if got := soaSerial(t, server, "child.lab.test."); got != 18 {
		t.Fatalf("child serial after batch: %d", got)
	}
	// The batch adds a second parent referral target and a child answer in one
	// activity, so both the referral glue and the new owner resolve.
	if added := probeZone(t, server, "static.child.lab.test.", zone.A); len(added.Answer) != 1 {
		t.Fatalf("child edit not active: %+v", added)
	}
	parentZone, err := manager.Export("lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	if len(parentZone.Set("ns2.lab.test.", zone.A).Records) != 1 {
		t.Fatal("parent referral glue not active")
	}
	childZone, err := manager.Export("child.lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	if childZone.Serial() != 18 || len(childZone.Set("static.child.lab.test.", zone.A).Records) != 1 {
		t.Fatalf("child candidate not active: %+v", childZone.V1())
	}
	if status := manager.Status(); status.Epoch < 2 {
		t.Fatalf("batch did not advance the epoch: %d", status.Epoch)
	}
}

func TestBatchBaseMismatchRejectsBothZones(t *testing.T) {
	path, cfg := copyConfig(t)
	manager := managerAt(t, path, cfg, reload.Boundary{})
	server := testServer(t, manager, nil)

	beforeParent := soaSerial(t, server, "lab.test.")
	beforeChild := soaSerial(t, server, "child.lab.test.")
	// The parent base is valid; the child base names serial 16 while 17 is
	// active. The whole batch must be refused.
	if _, err := manager.PublishBatch(batchFromFixture(t, "batch-stale-child")); err == nil {
		t.Fatal("accepted a batch whose child base disagrees")
	}
	if got := soaSerial(t, server, "lab.test."); got != beforeParent {
		t.Fatalf("parent advanced despite a rejected batch: %d", got)
	}
	if got := soaSerial(t, server, "child.lab.test."); got != beforeChild {
		t.Fatalf("child advanced despite a rejected batch: %d", got)
	}
	if leaked := probeZone(t, server, "static.child.lab.test.", zone.A); len(leaked.Answer) != 0 {
		t.Fatalf("rejected batch leaked a child record: %+v", leaked)
	}
}

func TestBatchRejectsSyntaxAndMembership(t *testing.T) {
	path, cfg := copyConfig(t)
	manager := managerAt(t, path, cfg, reload.Boundary{})
	edit := serial.EditV1{Version: 1, Origin: "lab.test.", Base: 4294967294, Next: 4294967295}
	if _, err := manager.PublishBatch(serial.BatchEditV1{Version: 1,
		Edits: []serial.EditV1{edit, edit}}); err == nil {
		t.Fatal("accepted a batch with a repeated origin")
	}
	other := serial.EditV1{Version: 1, Origin: "unrelated.test.", Base: 0, Next: 1}
	if _, err := manager.PublishBatch(serial.BatchEditV1{Version: 1,
		Edits: []serial.EditV1{edit, other}}); err == nil {
		t.Fatal("accepted a batch whose members are not a parent and child")
	}
	if _, err := manager.PublishBatch(serial.BatchEditV1{Version: 1,
		Edits: []serial.EditV1{edit}}); err == nil {
		t.Fatal("accepted a batch with a single member")
	}
}

// TestBatchKeepsInFlightTransferPin verifies that a transfer started before a
// batch publication continues to deliver the prior snapshot, including its old
// SOA serial and the absence of the child candidate.
func TestBatchKeepsInFlightTransferPin(t *testing.T) {
	path, cfg := copyConfig(t)
	primary := managerAt(t, path, cfg, reload.Boundary{})
	blocked := make(chan struct{})
	resume := make(chan struct{})
	var resumed atomic.Bool
	release := func() {
		if resumed.CompareAndSwap(false, true) {
			close(resume)
		}
	}
	source := testServer(t, primary, func(point FramePoint) error {
		if point.Position.Frames == 1 {
			close(blocked)
			<-resume
		}
		return nil
	})
	defer release()
	type outcome struct {
		candidate transfer.Candidate
		err       error
	}
	done := make(chan outcome, 1)
	go func() {
		client := Client{IOTimeout: 5 * time.Second}
		candidate, err := client.Fetch(context.Background(), source.Address(), "child.lab.test.", nil)
		done <- outcome{candidate, err}
	}()
	select {
	case <-blocked:
	case got := <-done:
		t.Fatalf("transfer stopped before the batch: %v", got.err)
	case <-time.After(3 * time.Second):
		t.Fatal("did not reach the second frame")
	}

	receipt, err := primary.PublishBatch(batchFromFixture(t, "batch-parent-child"))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Child.Serial != 18 {
		t.Fatalf("unexpected child serial: %+v", receipt)
	}
	view := source.TransferStatus()
	if len(view.Active) != 1 || view.Active[0].Origin != "child.lab.test." || view.Active[0].Serial != 17 {
		t.Fatalf("in-flight transfer lost its pinned snapshot: %+v", view)
	}

	release()
	got := <-done
	if got.err != nil || got.candidate.Zone == nil {
		t.Fatalf("in-flight transfer failed: %v", got.err)
	}
	if got.candidate.Zone.Serial() != 17 {
		t.Fatalf("in-flight transfer delivered the new serial: %d", got.candidate.Zone.Serial())
	}
	if len(got.candidate.Zone.Set("static.child.lab.test.", zone.A).Records) != 0 {
		t.Fatal("in-flight transfer observed the child candidate")
	}
}

// TestBatchInterruptedBeforeJournalRollsBackOnOpen models a crash after a
// candidate file was written but before the journal became durable. No journal
// exists, so the active state files remain authoritative and the abandoned
// candidate is never adopted.
func TestBatchInterruptedBeforeJournalRollsBackOnOpen(t *testing.T) {
	path, cfg := copyConfig(t)
	manager := managerAt(t, path, cfg, reload.Boundary{})
	server := testServer(t, manager, nil)
	before := soaSerial(t, server, "lab.test.")

	// Leave a candidate and a backup behind with no journal.
	for _, name := range []string{".labelreef-orphan", ".labelreef-prev-orphan"} {
		if err := os.WriteFile(filepath.Join(cfg.StateDir, name), []byte(`{"version":1}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := reload.Open(path, reload.Boundary{})
	if err != nil {
		t.Fatal(err)
	}
	if got := soaSerial(t, testServer(t, reopened, nil), "lab.test."); got != before {
		t.Fatalf("restart adopted an orphaned candidate: %d", got)
	}
}

// TestBatchJournalCompletionSurvivesRestart models a restart after both
// candidate files were installed. Reopening resolves the journal forward.
func TestBatchJournalCompletionSurvivesRestart(t *testing.T) {
	path, cfg := copyConfig(t)
	manager := managerAt(t, path, cfg, reload.Boundary{})
	if _, err := manager.PublishBatch(batchFromFixture(t, "batch-parent-child")); err != nil {
		t.Fatal(err)
	}
	reopened, err := reload.Open(path, reload.Boundary{})
	if err != nil {
		t.Fatal(err)
	}
	server := testServer(t, reopened, nil)
	if got := soaSerial(t, server, "lab.test."); got != 4294967295 {
		t.Fatalf("parent serial after restart: %d", got)
	}
	if got := soaSerial(t, server, "child.lab.test."); got != 18 {
		t.Fatalf("child serial after restart: %d", got)
	}
	entries, err := os.ReadDir(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".labelreef") {
			t.Fatalf("restart left temporary state %s", entry.Name())
		}
	}
}

func TestBatchControlEndpoint(t *testing.T) {
	path, cfg := copyConfig(t)
	manager := managerAt(t, path, cfg, reload.Boundary{})
	server := testServer(t, manager, nil)
	control := Control{Manager: manager, DNS: server}

	body := `{"version":1,"edits":[` +
		`{"version":1,"origin":"lab.test.","base":4294967294,"next":4294967295},` +
		`{"version":1,"origin":"child.lab.test.","base":17,"next":18}]}`
	out := controlRequest(t, control, http.MethodPost, "/v1/batch", body)
	if out.Code != http.StatusOK {
		t.Fatalf("batch endpoint returned %d: %s", out.Code, out.Body.String())
	}
	var receipt reload.BatchReceipt
	if err := zone.DecodeJSON(out.Body, 1<<20, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Parent.Serial != 4294967295 || receipt.Child.Serial != 18 {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}

	// A conflicting base must reach the client as a conflict, not 200.
	stale := `{"version":1,"edits":[` +
		`{"version":1,"origin":"lab.test.","base":4294967294,"next":4294967295},` +
		`{"version":1,"origin":"child.lab.test.","base":17,"next":18}]}`
	out = controlRequest(t, control, http.MethodPost, "/v1/batch", stale)
	if out.Code != http.StatusConflict {
		t.Fatalf("conflicting batch returned %d: %s", out.Code, out.Body.String())
	}
	if !strings.Contains(out.Body.String(), "lab.test.") || !strings.Contains(out.Body.String(), "differs") {
		t.Fatalf("conflict did not name the stale member: %s", out.Body.String())
	}
}

func TestBatchControlRejectsWrongMedia(t *testing.T) {
	path, cfg := copyConfig(t)
	manager := managerAt(t, path, cfg, reload.Boundary{})
	server := testServer(t, manager, nil)
	control := Control{Manager: manager, DNS: server}
	r := httptest.NewRequest(http.MethodPost, "/v1/batch", strings.NewReader(`{"version":1,"edits":[]}`))
	r.Host = manager.Runtime().Control.String()
	r.RemoteAddr = "127.0.0.1:50200"
	r.Header.Set(ControlHeader, ControlValue)
	r.Header.Set("Content-Type", "text/plain")
	out := httptest.NewRecorder()
	control.ServeHTTP(out, r)
	if out.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("batch without JSON media returned %d", out.Code)
	}
}
