package transfer

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"labelreef/serial"
	"labelreef/zone"
)

func loadStages(t testing.TB) (*zone.ZoneVersion, *serial.Snapshot) {
	t.Helper()
	seed, err := os.Open("../examples/zones/lab-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Close()
	start, err := zone.DecodeV1(seed)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := serial.Seed(start)
	for _, path := range []string{"to-4294967295.json", "to-0.json"} {
		file, err := os.Open(filepath.Join("../examples/edits", path))
		if err != nil {
			t.Fatal(err)
		}
		edit, err := serial.DecodeEdit(file)
		file.Close()
		if err != nil {
			t.Fatal(err)
		}
		z, err := edit.Apply(snapshot.Current())
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err = serial.Advance(snapshot, z, nil, 2)
		if err != nil {
			t.Fatal(err)
		}
	}
	return start, snapshot
}

func applyPlan(snapshot *serial.Snapshot, req Request, base *zone.ZoneVersion, chunk int) (Candidate, error) {
	plan, err := Build(snapshot, req)
	if err != nil {
		return Candidate{}, err
	}
	recv, err := NewReceiver(req, base)
	if err != nil {
		return Candidate{}, err
	}
	cursor := plan.Cursor()
	for !cursor.Done() {
		records := cursor.Offer(chunk)
		if err := recv.Feed(records); err != nil {
			return Candidate{}, err
		}
		if err := cursor.Commit(len(records)); err != nil {
			return Candidate{}, err
		}
	}
	return recv.Finish()
}

func TestTransferChunkingAndSerialWrap(t *testing.T) {
	base, final := loadStages(t)
	axfr := Request{Origin: base.Origin(), Type: zone.AXFR}
	ixfr := Request{Origin: base.Origin(), Type: zone.IXFR, HasSerial: true, Serial: base.Serial()}
	none := ixfr
	none.Serial = final.Current().Serial()
	restricted, err := serial.Advance(serial.Seed(base), final.Current(), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		from    *zone.ZoneVersion
		source  *serial.Snapshot
		request Request
		kind    Kind
	}{
		{nil, final, axfr, Full},
		{base, final, ixfr, Incremental},
		{base, restricted, ixfr, Fallback},
		{final.Current(), final, none, Unchanged},
	} {
		for _, chunk := range []int{1, 3, 32} {
			result, err := applyPlan(tc.source, tc.request, tc.from, chunk)
			if err != nil || result.Kind != tc.kind || !serial.Same(result.Zone, final.Current()) {
				t.Fatalf("%s chunk=%d: %v %+v", tc.kind, chunk, err, result)
			}
		}
	}
}

func TestCursorAndReceiverStopAtPublishedBoundaries(t *testing.T) {
	base, final := loadStages(t)
	req := Request{Origin: base.Origin(), Type: zone.IXFR, HasSerial: true, Serial: base.Serial()}
	plan, err := Build(final, req)
	if err != nil {
		t.Fatal(err)
	}
	c := plan.Cursor()
	initial := c.Offer(3)
	retry := c.Offer(3)
	if initial[0] != retry[0] || c.Position() != (Position{}) {
		t.Fatal("reoffering advanced position")
	}
	if err := c.Commit(4); err == nil || c.Position() != (Position{}) {
		t.Fatal("commit accepted unoffered records")
	}
	if err := c.Commit(2); err != nil || c.Position() != (Position{NextRecord: 2, Frames: 1}) {
		t.Fatalf("incorrect acknowledged position: %+v %v", c.Position(), err)
	}
	r, err := NewReceiver(req, base)
	if err != nil {
		t.Fatal(err)
	}
	p := plan.Cursor()
	if err := r.Feed(p.Offer(plan.Count() - 1)); err != nil {
		t.Fatal(err)
	}
	if result, err := r.Finish(); err == nil || result.Zone != nil {
		t.Fatal("incomplete IXFR exposes data")
	}
	p = plan.Cursor()
	extra := append(p.Offer(plan.Count()), base.SOA())
	r, _ = NewReceiver(req, base)
	if err := r.Feed(extra); err == nil || r.Done() {
		t.Fatal("same frame trailing after terminal SOA accepted")
	}
}

func BenchmarkLargeSync(b *testing.B) {
	template, _ := loadStages(b)
	records := template.Records()
	for i := range 8000 {
		name := fmt.Sprintf("node%06d.rack%02d.sample.%s", i, i%30, template.Origin())
		r, err := zone.ParseRecord(template.Origin(), name, 60, zone.A, "192.0.2.40")
		if err != nil {
			b.Fatal(err)
		}
		records = append(records, r)
	}
	base, err := zone.New(template.Origin(), records)
	if err != nil {
		b.Fatal(err)
	}
	for i := range records {
		if records[i].Type == zone.SOA {
			records[i] = records[i].WithSerial(template.Serial() + 1)
		}
	}
	target, err := zone.New(template.Origin(), records[:len(records)-200])
	if err != nil {
		b.Fatal(err)
	}
	newer, err := serial.Advance(serial.Seed(base), target, nil, 1)
	if err != nil {
		b.Fatal(err)
	}
	for _, typ := range []zone.Type{zone.AXFR, zone.IXFR} {
		b.Run(typ.String(), func(b *testing.B) {
			req := Request{Origin: base.Origin(), Type: typ, HasSerial: typ == zone.IXFR, Serial: base.Serial()}
			var current *zone.ZoneVersion
			if typ == zone.IXFR {
				current = base
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				candidate, err := applyPlan(newer, req, current, 128)
				if err != nil || candidate.Zone.RecordCount() != target.RecordCount() {
					b.Fatalf("large sync failed: %v", err)
				}
			}
		})
	}
}
