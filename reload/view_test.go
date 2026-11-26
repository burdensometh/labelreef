package reload

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"labelreef/lookup"
	"labelreef/serial"
	"labelreef/transfer"
	"labelreef/zone"
)

func configAt(t *testing.T, source string) (string, Config) {
	t.Helper()
	cfg, err := ReadConfig(source)
	if err != nil {
		t.Fatal(err)
	}
	cfg.StateDir = t.TempDir()
	for i := range cfg.Zones {
		if cfg.Zones[i].Seed != "" {
			cfg.Zones[i].Seed, err = filepath.Abs(filepath.Join(filepath.Dir(source), cfg.Zones[i].Seed))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	return filepath.Join(t.TempDir(), "config.json"), cfg
}

func writeConfig(t *testing.T, path string, cfg Config) {
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

func openManager(t *testing.T, path string, cfg Config, hooks Boundary) *Manager {
	t.Helper()
	writeConfig(t, path, cfg)
	manager, err := Open(path, hooks)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func editFixture(t *testing.T, name string) serial.EditV1 {
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

func decodeZone(t *testing.T, path string) *zone.ZoneVersion {
	t.Helper()
	f, err := os.Open(path)
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

func question(name string, typ zone.Type) lookup.Question {
	return lookup.Question{Name: name, Type: typ, Class: zone.ClassIN}
}

func TestViewSelectionsAgreeOnOneTable(t *testing.T) {
	path, cfg := configAt(t, "../examples/primary.json")
	manager := openManager(t, path, cfg, Boundary{})
	view := manager.View()

	parent, err := view.Export("lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	child, err := view.Export("child.lab.test.")
	if err != nil {
		t.Fatal(err)
	}

	// Longest suffix: the child zone answers inside its own origin.
	answer := view.Resolve(question("www.child.lab.test.", zone.A))
	if !answer.Authoritative || len(answer.Answer) != 1 {
		t.Fatalf("child zone did not answer: %+v", answer)
	}
	apex := view.Resolve(question("child.lab.test.", zone.SOA))
	if len(apex.Answer) != 1 || apex.Answer[0].Records[0].Data.SOA.Serial != child.Serial() {
		t.Fatalf("apex query did not select the child zone: %+v", apex)
	}
	// Parent-zone DS: the parent answers DS at the delegation.
	ds := view.Resolve(question("child.lab.test.", zone.DS))
	if !ds.Authoritative || len(ds.Answer) != 1 || ds.Answer[0].Type != zone.DS {
		t.Fatalf("parent did not answer DS at the delegation: %+v", ds)
	}
	if cut := parent.Set("child.lab.test.", zone.DS); len(cut.Records) != 1 || cut.Records[0] != ds.Answer[0].Records[0] {
		t.Fatalf("DS answer did not come from the parent zone: %+v", ds)
	}

	// Export and transfer require an exact active origin.
	if _, err := view.Export("www.lab.test."); !errors.Is(err, ErrUnknown) {
		t.Fatalf("export accepted a non-origin name: %v", err)
	}
	if _, err := view.Transfer(transfer.Request{Origin: "www.lab.test.", Type: zone.AXFR}); !errors.Is(err, ErrUnknown) {
		t.Fatalf("transfer accepted a non-origin name: %v", err)
	}
	plan, err := view.Transfer(transfer.Request{Origin: "lab.test.", Type: zone.AXFR})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Kind() != transfer.Full || plan.Serial() != parent.Serial() {
		t.Fatalf("unexpected transfer plan: %s at serial %d", plan.Kind(), plan.Serial())
	}

	// The read-only check agrees with every selection on this table.
	if err := view.Check(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestViewSkipsInactiveZone(t *testing.T) {
	path, cfg := configAt(t, "../examples/secondary.json")
	manager := openManager(t, path, cfg, Boundary{})
	view := manager.View()

	if _, err := view.Export("lab.test."); !errors.Is(err, ErrUnknown) {
		t.Fatalf("inactive zone exported: %v", err)
	}
	if _, err := view.Transfer(transfer.Request{Origin: "lab.test.", Type: zone.AXFR}); !errors.Is(err, ErrUnknown) {
		t.Fatalf("inactive zone transferred: %v", err)
	}
	if answer := view.Resolve(question("lab.test.", zone.SOA)); answer.Code != lookup.Refused {
		t.Fatalf("inactive zone routed: %+v", answer)
	}
	if err := view.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestViewPinsOpenSelectionsAcrossReload(t *testing.T) {
	path, cfg := configAt(t, "../examples/primary.json")
	manager := openManager(t, path, cfg, Boundary{})
	old := manager.View()

	// Open a transfer before the table changes.
	plan, err := old.Transfer(transfer.Request{Origin: "lab.test.", Type: zone.AXFR})
	if err != nil || plan.Serial() != 4294967294 {
		t.Fatalf("open transfer: %+v %v", plan, err)
	}

	// Advance the primary serial and drop the child zone.
	if _, err := manager.Edit(editFixture(t, "to-4294967295")); err != nil {
		t.Fatal(err)
	}
	cfg.Zones = cfg.Zones[:1]
	writeConfig(t, path, cfg)
	if _, err := manager.Reload(); err != nil {
		t.Fatal(err)
	}

	// The old view still resolves, exports and transfers the old table.
	if z, err := old.Export("lab.test."); err != nil || z.Serial() != 4294967294 {
		t.Fatalf("open view followed the edit: %+v %v", z, err)
	}
	if _, err := old.Export("child.lab.test."); err != nil {
		t.Fatalf("open view lost the removed zone: %v", err)
	}
	if answer := old.Resolve(question("www.child.lab.test.", zone.A)); !answer.Authoritative || len(answer.Answer) != 1 {
		t.Fatalf("open query followed the new table: %+v", answer)
	}
	if records := plan.Cursor().Offer(plan.Count()); records[0].Data.SOA.Serial != 4294967294 {
		t.Fatalf("open transfer followed the edit: %+v", records[0])
	}
	if err := old.Check(); err != nil {
		t.Fatal(err)
	}

	// A fresh view follows the new table.
	fresh := manager.View()
	if _, err := fresh.Export("child.lab.test."); !errors.Is(err, ErrUnknown) {
		t.Fatalf("fresh view kept the removed zone: %v", err)
	}
	if z, err := fresh.Export("lab.test."); err != nil || z.Serial() != 4294967295 {
		t.Fatalf("fresh view missed the edit: %+v %v", z, err)
	}
	if answer := fresh.Resolve(question("www.child.lab.test.", zone.A)); answer.Authoritative {
		t.Fatalf("fresh view did not follow the new table: %+v", answer)
	}
	if err := fresh.Check(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Check(); err != nil {
		t.Fatal(err)
	}
}

func TestCheckObservesWholeTableDuringReload(t *testing.T) {
	path, cfg := configAt(t, "../examples/primary.json")
	began, proceed := make(chan struct{}), make(chan struct{})
	var hold atomic.Bool
	hooks := Boundary{BeforeReplace: func(epoch uint64) error {
		if hold.Load() {
			close(began)
			<-proceed
		}
		return nil
	}}
	manager := openManager(t, path, cfg, hooks)
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
	// While the replacement is blocked, every check observes the complete old table.
	for i := 0; i < 8; i++ {
		view := manager.View()
		if err := view.Check(); err != nil {
			t.Fatalf("check during replacement: %v", err)
		}
		if _, err := view.Export("child.lab.test."); err != nil {
			t.Fatalf("check straddled tables: %v", err)
		}
	}
	close(proceed)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// After the replacement, every check observes the complete new table.
	for i := 0; i < 8; i++ {
		view := manager.View()
		if err := view.Check(); err != nil {
			t.Fatalf("check after replacement: %v", err)
		}
		if _, err := view.Export("child.lab.test."); !errors.Is(err, ErrUnknown) {
			t.Fatalf("check straddled tables: %v", err)
		}
	}
}

func TestCheckDetectsMismatchedZone(t *testing.T) {
	z := decodeZone(t, "../examples/zones/lab-v1.json")
	mismatched := &table{epoch: 1, entries: map[string]*entry{
		"other.test.": {specification: specification{origin: "other.test."}, snapshot: serial.Seed(z)},
	}}
	err := (&View{table: mismatched}).Check()
	if err == nil || !strings.Contains(err.Error(), "other.test.") {
		t.Fatalf("check accepted a mismatched zone: %v", err)
	}
	empty := &View{table: &table{epoch: 1, entries: map[string]*entry{}}}
	if err := empty.Check(); err != nil {
		t.Fatalf("check rejected an empty table: %v", err)
	}
}
