package serve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"labelreef/lookup"
	"labelreef/reload"
	"labelreef/serial"
	"labelreef/transfer"
	"labelreef/zone"
)

func copyConfig(t *testing.T) (string, reload.Config) {
	t.Helper()
	cfg, err := reload.ReadConfig("../examples/primary.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg.StateDir = t.TempDir()
	for i := range cfg.Zones {
		cfg.Zones[i].Seed, err = filepath.Abs("../examples/" + cfg.Zones[i].Seed)
		if err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(t.TempDir(), "config.json"), cfg
}

func writeConfig(t *testing.T, path string, cfg reload.Config) {
	t.Helper()
	tmp := path + ".new"
	f, err := os.Create(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if err := zone.EncodeJSON(f, cfg); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func managerAt(t *testing.T, path string, cfg reload.Config, hooks reload.Boundary) *reload.Manager {
	t.Helper()
	writeConfig(t, path, cfg)
	manager, err := reload.Open(path, hooks)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func editFromFixture(t *testing.T, name string) serial.EditV1 {
	t.Helper()
	f, err := os.Open("../examples/edits/" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	edit, err := serial.DecodeEdit(f)
	if err != nil {
		t.Fatal(err)
	}
	return edit
}

func queriedSerial(t *testing.T, server *Server) uint32 {
	t.Helper()
	result, err := Probe(context.Background(), "lab.test.", zone.SOA, ProbeOptions{
		Address: server.Address(), Timeout: 3 * time.Second,
	})
	if err != nil || len(result.Answer) != 1 {
		t.Fatalf("SOA query: %+v %v", result, err)
	}
	rr, err := result.Answer[0].Record("lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	return rr.Data.SOA.Serial
}

func TestInterruptedTCPTransferRetainsLiveSecondary(t *testing.T) {
	path, cfg := copyConfig(t)
	primary := managerAt(t, path, cfg, reload.Boundary{})
	var disrupt atomic.Bool
	source := testServer(t, primary, func(point FramePoint) error {
		if disrupt.Load() && point.Position.Frames == 1 {
			return fmt.Errorf("controlled interruption before second frame")
		}
		return nil
	})
	path, cfg = copyConfig(t)
	cfg.Zones = []reload.ZoneConfig{{
		Origin: "lab.test.", Role: reload.Secondary, Source: source.Address().String(), Retain: 2,
	}}
	secondary := managerAt(t, path, cfg, reload.Boundary{})
	mirror := testServer(t, secondary, nil)
	client := Client{IOTimeout: 2 * time.Second}
	ctx := context.Background()
	bootstrap, err := secondary.Sync(ctx, "lab.test.", client)
	if err != nil || bootstrap.Kind != transfer.Full || bootstrap.Serial != 4294967294 {
		t.Fatalf("bootstrap: %+v %v", bootstrap, err)
	}
	for _, name := range []string{"to-4294967295", "to-0"} {
		if _, err := primary.Edit(editFromFixture(t, name)); err != nil {
			t.Fatal(err)
		}
	}
	beforeFrames := source.Stats().TransferFrames
	disrupt.Store(true)
	if _, err := secondary.Sync(ctx, "lab.test.", client); err == nil || !strings.Contains(err.Error(), "frame 2") {
		t.Fatalf("expected second-frame transfer failure, got %v", err)
	}
	if got := queriedSerial(t, mirror); got != 4294967294 {
		t.Fatalf("secondary activated partial zone: %d", got)
	}
	if after := source.Stats(); after.TransferFrames != beforeFrames+1 || after.TransfersInterrupted != 1 {
		t.Fatalf("unexpected source progress: %+v", after)
	}
	progress := source.TransferStatus()
	if len(progress.Active) != 0 || len(progress.Recent) != 2 {
		t.Fatalf("unexpected transfer monitor history: %+v", progress)
	}
	failed := progress.Recent[0]
	if failed.State != Interrupted || failed.Kind != transfer.Incremental ||
		failed.Serial != 0 || failed.Written != 3 || failed.Frames != 1 {
		t.Fatalf("second frame incorrectly marked written: %+v", failed)
	}
	disrupt.Store(false)
	receipt, err := secondary.Sync(ctx, "lab.test.", client)
	if err != nil || receipt.Kind != transfer.Incremental || receipt.Serial != 0 || receipt.Generation != 2 {
		t.Fatalf("IXFR retry: %+v %v", receipt, err)
	}
	if got := queriedSerial(t, mirror); got != 0 {
		t.Fatalf("secondary did not activate serial 0: %d", got)
	}
	reopened, err := reload.Open(path, reload.Boundary{})
	if err != nil {
		t.Fatal(err)
	}
	if status := reopened.Status().Zones[0]; status.Serial == nil || *status.Serial != 0 || status.Retained != 2 {
		t.Fatalf("unexpected state after reopen: %+v", status)
	}
}

func TestClientPeerCloseInFrame(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	finished := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err = readFrame(conn); err == nil {
				_, err = conn.Write([]byte{0, 90, 0, 1})
			}
		}
		finished <- err
	}()
	client := Client{IOTimeout: time.Second}
	got, err := client.Fetch(context.Background(), listener.Addr().(*net.TCPAddr).AddrPort(), "lab.test.", nil)
	if err == nil || !errors.Is(err, io.ErrUnexpectedEOF) || got.Zone != nil {
		t.Fatalf("partially read frame produced a candidate: %+v %v", got, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestInFlightTransferSurvivesRouteReplacement(t *testing.T) {
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
		candidate, err := client.Fetch(context.Background(), source.Address(), "lab.test.", nil)
		done <- outcome{candidate, err}
	}()
	select {
	case <-blocked:
	case got := <-done:
		t.Fatalf("transfer stopped before replacement: %v", got.err)
	case <-time.After(3 * time.Second):
		t.Fatal("did not reach second frame")
	}
	cfg.Zones = nil
	writeConfig(t, path, cfg)
	if _, err := primary.Reload(); err != nil {
		t.Fatal(err)
	}
	q := lookup.Question{Name: "lab.test.", Type: zone.SOA, Class: zone.ClassIN}
	if answer := primary.Resolve(q); answer.Code != lookup.Refused {
		t.Fatalf("removed zone still routes for new requests: %+v", answer)
	}
	view := source.TransferStatus()
	if len(view.Active) != 1 || view.Active[0].Frames != 1 || view.Active[0].Written != 3 {
		t.Fatalf("replacement disturbed cursor: %+v", view)
	}
	release()
	got := <-done
	if got.err != nil || got.candidate.Zone == nil || got.candidate.Zone.Serial() != 4294967294 {
		t.Fatalf("in-flight transfer lost its pinned snapshot: %+v", got)
	}
}

func TestConfigReplacementWhileServing(t *testing.T) {
	path, cfg := copyConfig(t)
	began, proceed := make(chan struct{}), make(chan struct{})
	var hold atomic.Bool
	hooks := reload.Boundary{BeforeReplace: func(epoch uint64) error {
		if hold.Load() {
			close(began)
			<-proceed
		}
		return nil
	}}
	manager := managerAt(t, path, cfg, hooks)
	server := testServer(t, manager, nil)
	probe := func(name string, typ zone.Type) ProbeResult {
		t.Helper()
		result, err := Probe(context.Background(), name, typ, ProbeOptions{
			Address: server.Address(), Timeout: time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	child := func() ProbeResult { return probe("www.child.lab.test.", zone.A) }
	first := child()
	if !first.Authoritative || len(first.Answer) != 1 || first.Answer[0].Data != "192.0.2.162" {
		t.Fatalf("child should be authoritative before reload: %+v", first)
	}
	if ds := probe("child.lab.test.", zone.DS); !ds.Authoritative || len(ds.Answer) != 1 {
		t.Fatalf("parent DS is lost with active child: %+v", ds)
	}
	hold.Store(true)
	cfg.Zones = cfg.Zones[:1]
	writeConfig(t, path, cfg)
	done := make(chan error, 1)
	go func() {
		_, err := manager.Reload()
		done <- err
	}()
	select {
	case <-began:
	case err := <-done:
		t.Fatalf("reload returned before replacement: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("did not reach replacement boundary")
	}
	during := child()
	close(proceed)
	if !during.Authoritative || len(during.Answer) != 1 || during.Answer[0] != first.Answer[0] {
		t.Fatalf("query crossed activation boundary: %+v", during)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	after := child()
	if after.Authoritative || len(after.Answer) != 0 || len(after.Authority) != 2 || len(after.Additional) != 2 {
		t.Fatalf("parent cut missing after reload: %+v", after)
	}
	invalid := cfg
	invalid.Zones = append(append([]reload.ZoneConfig(nil), cfg.Zones...), reload.ZoneConfig{
		Origin: "bad.test.", Role: reload.Primary, Seed: filepath.Join(t.TempDir(), "missing"),
	})
	writeConfig(t, path, invalid)
	epoch := manager.Status().Epoch
	if _, err := manager.Reload(); err == nil || manager.Status().Epoch != epoch {
		t.Fatalf("invalid configuration activated: %v", err)
	}
}

func TestControlContract(t *testing.T) {
	path, cfg := copyConfig(t)
	manager := managerAt(t, path, cfg, reload.Boundary{})
	server := testServer(t, manager, nil)
	control := Control{Manager: manager, DNS: server}
	cases := []struct {
		method, path, host, key, origin, media string
		status                                 int
	}{
		{"GET", "/v1/status", cfg.Control, "1", "", "", http.StatusOK},
		{"GET", "/v1/status", "other.example", "1", "", "", http.StatusForbidden},
		{"POST", "/v1/reload", cfg.Control, "", "", "", http.StatusForbidden},
		{"POST", "/v1/reload", cfg.Control, "1", "http://evil.example", "", http.StatusForbidden},
		{"POST", "/v1/sync?origin=a&origin=b", cfg.Control, "1", "", "", http.StatusBadRequest},
		{"PUT", "/v1/status", cfg.Control, "1", "", "", http.StatusMethodNotAllowed},
		{"POST", "/v1/edit", cfg.Control, "1", "", "text/plain", http.StatusUnsupportedMediaType},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.Host, r.RemoteAddr = tc.host, "127.0.0.1:50200"
		r.Header.Set(ControlHeader, tc.key)
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Content-Type", tc.media)
		out := httptest.NewRecorder()
		control.ServeHTTP(out, r)
		if out.Code != tc.status {
			t.Errorf("%s %s returned %d, want %d: %s", tc.method, tc.path, out.Code, tc.status, out.Body.String())
		}
	}
	q := lookup.Question{Name: "lab.test.", Class: zone.ClassIN, Type: zone.SOA}
	if reply := manager.Resolve(q); len(reply.Answer) != 1 {
		t.Fatal("control failures modified the DNS view")
	}
}
