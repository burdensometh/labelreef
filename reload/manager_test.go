package reload

import (
	"os"
	"path/filepath"
	"testing"

	"labelreef/serial"
	"labelreef/transfer"
	"labelreef/zone"
)

func testConfig(t *testing.T) (string, Config) {
	t.Helper()
	cfg, err := ReadConfig("../examples/primary.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg.StateDir = t.TempDir()
	cfg.Zones = []ZoneConfig{cfg.Zones[0]}
	cfg.Zones[0].Seed, err = filepath.Abs("../examples/" + cfg.Zones[0].Seed)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(t.TempDir(), "config.json"), cfg
}

func writeTestConfig(t *testing.T, path string, cfg Config) {
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

func applyEdit(t *testing.T, m *Manager, name string) Receipt {
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
	receipt, err := m.Edit(edit)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}

func onlyZone(t *testing.T, m *Manager) ZoneStatus {
	t.Helper()
	status := m.Status()
	if len(status.Zones) != 1 {
		t.Fatalf("expected one zone, got %+v", status)
	}
	return status.Zones[0]
}

func seedZone(t *testing.T) *zone.ZoneVersion {
	t.Helper()
	f, err := os.Open("../examples/zones/lab-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := zone.DecodeV1(f)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

// A retained-history shrink is an eviction. Widening the window afterwards or
// restarting must not offer deltas the shrink discarded, and pure retention
// changes must not alter the served SOA serial or publication generation.
func TestRetentionShrinkSurvivesExpandAndRestart(t *testing.T) {
	path, cfg := testConfig(t)
	writeTestConfig(t, path, cfg)
	m, err := Open(path, Boundary{})
	if err != nil {
		t.Fatal(err)
	}
	applyEdit(t, m, "to-4294967295")
	applyEdit(t, m, "to-0")
	before := onlyZone(t, m)
	if before.Retained != 2 || before.Serial == nil || *before.Serial != 0 {
		t.Fatalf("expected two retained deltas at serial 0: %+v", before)
	}

	cfg.Zones[0].Retain = 0
	writeTestConfig(t, path, cfg)
	if _, err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	shrunk := onlyZone(t, m)
	if shrunk.Retained != 0 || shrunk.Serial == nil || *shrunk.Serial != *before.Serial ||
		shrunk.Generation != before.Generation {
		t.Fatalf("shrink changed served identity or kept history: %+v", shrunk)
	}

	cfg.Zones[0].Retain = 2
	writeTestConfig(t, path, cfg)
	if _, err := m.Reload(); err != nil {
		t.Fatal(err)
	}
	if expanded := onlyZone(t, m); expanded.Retained != 0 {
		t.Fatalf("expand restored evicted history: %+v", expanded)
	}

	reopened, err := Open(path, Boundary{})
	if err != nil {
		t.Fatal(err)
	}
	after := onlyZone(t, reopened)
	if after.Retained != 0 || after.Serial == nil || *after.Serial != *before.Serial ||
		after.Generation != before.Generation {
		t.Fatalf("restart restored evicted history or changed served identity: %+v", after)
	}

	evicted := seedZone(t).Serial()
	plan, err := reopened.Transfer(transfer.Request{
		Origin: "lab.test.", Type: zone.IXFR, HasSerial: true, Serial: evicted,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind() != transfer.Fallback {
		t.Fatalf("evicted base serial %d was served %s instead of AXFR fallback", evicted, plan.Kind())
	}
	current, err := reopened.Export("lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Serial() != current.Serial() {
		t.Fatalf("fallback serial %d differs from current %d", plan.Serial(), current.Serial())
	}
}
