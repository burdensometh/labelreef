package serial

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"labelreef/zone"
)

func initial(t testing.TB) *zone.ZoneVersion {
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

func next(t testing.TB, z *zone.ZoneVersion, path string) *zone.ZoneVersion {
	t.Helper()
	f, err := os.Open(filepath.Join("../examples/edits", path+".json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	edit, err := DecodeEdit(f)
	if err != nil {
		t.Fatal(err)
	}
	result, err := edit.Apply(z)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func advance(t testing.TB, base *Snapshot, target *zone.ZoneVersion, retain int) *Snapshot {
	t.Helper()
	got, err := Advance(base, target, nil, retain)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestSerialArithmetic(t *testing.T) {
	for _, tc := range []struct {
		a, b uint32
		want Ordering
	}{
		{0, ^uint32(0), Newer},
		{^uint32(0), 0, Older},
		{1 << 31, 0, Undefined},
		{0, 1 << 31, Undefined},
		{10, 10, Equal},
	} {
		if found := Compare(tc.a, tc.b); found != tc.want {
			t.Errorf("Compare(%d,%d)=%d, want %d", tc.a, tc.b, found, tc.want)
		}
	}
}

func TestEditRequiresExplicitSerials(t *testing.T) {
	for _, input := range []string{
		`{"version":1,"origin":"lab.test.","next":1}`,
		`{"version":1,"origin":"lab.test.","base":4294967295}`,
		`{"version":1,"origin":"lab.test.","base":null,"next":1}`,
	} {
		if _, err := DecodeEdit(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted incomplete edit %s", input)
		}
	}
	edit, err := DecodeEdit(strings.NewReader(`{"version":1,"origin":"lab.test.","base":4294967295,"next":0}`))
	if err != nil || edit.Base != ^uint32(0) || edit.Next != 0 {
		t.Fatalf("explicit wrap serials were lost: %+v %v", edit, err)
	}
}

func TestSnapshotDurabilityAndHistory(t *testing.T) {
	base := initial(t)
	updated := next(t, base, "to-4294967295")
	wrap := next(t, updated, "to-0")
	snapshot := advance(t, advance(t, Seed(base), updated, 2), wrap, 2)
	path := filepath.Join(t.TempDir(), "state.json")
	store := Store{Path: path}
	before := store.Save(snapshot)
	if !before.Published || before.Err != nil {
		t.Fatalf("persist snapshot: %+v", before)
	}
	loaded, err := store.Load(base.Origin())
	if err != nil || !Same(loaded.Current(), wrap) || loaded.Generation() != 3 {
		t.Fatalf("reopen snapshot: %v %+v", err, loaded)
	}
	history, ok := loaded.History(base.Serial())
	if !ok || len(history) != 2 || history[0].To() != ^uint32(0) || history[1].To() != 0 {
		t.Fatalf("wrap history: %+v %t", history, ok)
	}
	history[0].Adds[0] = zone.Record{}
	r := NewReplay(base)
	history, _ = loaded.History(base.Serial())
	for _, d := range history {
		if err := r.Apply(d); err != nil {
			t.Fatal(err)
		}
	}
	replayed, err := r.Zone()
	if err != nil || !Same(wrap, replayed) {
		t.Fatalf("replay after copied history mutation: %v", err)
	}
	trimmed := advance(t, loaded, next(t, wrap, "to-1"), 2)
	if _, ok := trimmed.History(base.Serial()); ok {
		t.Fatal("evicted serial still available")
	}
}

func TestPublishFailureKeepsPriorBytes(t *testing.T) {
	base := initial(t)
	old := Seed(base)
	new := advance(t, old, next(t, base, "to-4294967295"), 2)
	store := Store{Path: filepath.Join(t.TempDir(), "state.json")}
	if result := store.Save(old); !result.Published || result.Err != nil {
		t.Fatalf("save seed: %+v", result)
	}
	oldBytes, _ := os.ReadFile(store.Path)
	fault := errors.New("controlled persistence interruption")
	store.BeforePublish = func(point PublishPoint) error {
		if point.Serial != ^uint32(0) || point.Generation != 2 {
			t.Fatalf("unexpected publish point %+v", point)
		}
		return fault
	}
	if result := store.Save(new); result.Published || !errors.Is(result.Err, fault) {
		t.Fatalf("failed to abort before rename: %+v", result)
	}
	newBytes, _ := os.ReadFile(store.Path)
	if !bytes.Equal(oldBytes, newBytes) {
		t.Fatal("aborted publication changed active state")
	}
	names, err := os.ReadDir(filepath.Dir(store.Path))
	if err != nil || len(names) != 1 {
		t.Fatalf("temporary file left after failure: %v %v", names, err)
	}
}

func TestInvalidIntermediateRRsetIsNeverApplied(t *testing.T) {
	base := initial(t)
	record, err := zone.ParseRecord(base.Origin(), "www", 180, zone.A, "192.0.2.40")
	if err != nil {
		t.Fatal(err)
	}
	delta := JournalDelta{Before: base.SOA(), After: base.SOA().WithSerial(base.Serial() + 1), Adds: []zone.Record{record}}
	replay := NewReplay(base)
	if err := replay.Apply(delta); err == nil {
		t.Fatal("journal accepted an invalid intermediate TTL")
	}
	current, err := replay.Zone()
	if err != nil || !Same(current, base) {
		t.Fatalf("failed application changed replay state: %v", err)
	}
}
