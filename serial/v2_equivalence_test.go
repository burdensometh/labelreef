package serial

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"labelreef/zone"
)

func loadV2Initial(t testing.TB) *zone.ZoneVersion {
	t.Helper()
	f, err := os.Open("../examples/zones/lab-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, format, err := zone.DecodeZone(f)
	if err != nil {
		t.Fatal(err)
	}
	if format != 2 {
		t.Fatalf("v2 seed reported format %d", format)
	}
	return z
}

// Publishing the same content through the v1 and v2 envelopes must converge on
// the same zone, fingerprint and journal delta, so transfers and their diffs
// are independent of the source file format.
func TestV1AndV2PublishEquivalentZonesAndDeltas(t *testing.T) {
	v1 := initial(t)
	v2 := loadV2Initial(t)
	if !zoneSame(t, v1, v2) {
		t.Fatal("v1 and v2 seeds decode to different zones")
	}

	updated := next(t, v1, "to-4294967295")
	// Render the target through the v2 envelope, then decode it back, so the
	// publish path genuinely crosses the v2 serializer rather than reusing
	// objects in memory.
	var encoded bytes.Buffer
	if err := zone.EncodeV2(&encoded, updated); err != nil {
		t.Fatal(err)
	}
	target, _, err := zone.DecodeZone(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	fromV1, err := Advance(Seed(v1), updated, nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	fromV2, err := Advance(Seed(v2), target, nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !zoneSame(t, fromV1.Current(), fromV2.Current()) {
		t.Fatal("published zones diverge by source format")
	}
	if fromV1.Generation() != fromV2.Generation() || fromV1.Current().Serial() != fromV2.Current().Serial() {
		t.Fatal("generation/serial accounting diverges")
	}
	historyV1, ok1 := fromV1.History(v1.Serial())
	historyV2, ok2 := fromV2.History(v2.Serial())
	if !ok1 || !ok2 || len(historyV1) != 1 || len(historyV2) != 1 {
		t.Fatalf("retained history missing: %t %t", ok1, ok2)
	}
	if !reflect.DeepEqual(historyV1[0], historyV2[0]) {
		t.Fatalf("journal delta differs across formats:\nv1=%+v\nv2=%+v", historyV1[0], historyV2[0])
	}

	// Persisted snapshots reload identically and their durable bytes stay v1.
	path := filepath.Join(t.TempDir(), "state.json")
	store := Store{Path: path}
	if result := store.Save(fromV2); !result.Published || result.Err != nil {
		t.Fatalf("save v2-published snapshot: %+v", result)
	}
	reloaded, err := store.Load(v2.Origin())
	if err != nil || !Same(reloaded.Current(), fromV1.Current()) {
		t.Fatalf("reload after v2 publish: %v", err)
	}
}

func zoneSame(t *testing.T, left, right *zone.ZoneVersion) bool {
	t.Helper()
	if !left.Equal(right) || left.Fingerprint() != right.Fingerprint() {
		return false
	}
	diff, err := zone.Diff(left, right)
	if err != nil {
		t.Fatal(err)
	}
	return len(diff.Adds) == 0 && len(diff.Removes) == 0
}
