package serial

import (
	"strings"
	"testing"

	"labelreef/zone"
)

func dnameEditRecord(t *testing.T, owner, target string) zone.Record {
	t.Helper()
	r, err := zone.ParseRecord("lab.test.", owner, 120, zone.DNAME, target)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReplayAcceptsDNameAndEnforcesShape(t *testing.T) {
	base := initial(t)
	dname := dnameEditRecord(t, "map", "target.example.")
	delta := JournalDelta{
		Before: base.SOA(), After: base.SOA().WithSerial(base.Serial() + 1),
		Adds: []zone.Record{dname},
	}
	replay := NewReplay(base)
	if err := replay.Apply(delta); err != nil {
		t.Fatalf("DNAME add rejected: %v", err)
	}
	z, err := replay.Zone()
	if err != nil || z.Set("map.lab.test.", zone.DNAME).Records[0] != dname {
		t.Fatalf("DNAME missing after replay: %v %+v", err, z)
	}
	// The reverse delta must also validate, covering the journal's two-way check.
	if err := replay.apply(delta, true); err != nil {
		t.Fatalf("DNAME delete rejected: %v", err)
	}
}

func TestReplayRejectsInvalidDNameShapes(t *testing.T) {
	base := initial(t)
	soa := base.SOA()
	for _, tc := range []struct {
		name    string
		adds    []zone.Record
		wantSub string
	}{
		{
			"apex",
			[]zone.Record{dnameEditRecord(t, "@", "root-target.example.")},
			"apex",
		},
		{
			"cname-coexistence",
			[]zone.Record{
				dnameEditRecord(t, "mapx", "target.example."),
				func() zone.Record {
					r, err := zone.ParseRecord("lab.test.", "mapx", 120, zone.CNAME, "other.lab.test.")
					if err != nil {
						t.Fatal(err)
					}
					return r
				}(),
			},
			"coexist",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			delta := JournalDelta{Before: soa, After: soa.WithSerial(soa.Data.SOA.Serial + 1), Adds: tc.adds}
			err := NewReplay(base).Apply(delta)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected %q, got %v", tc.wantSub, err)
			}
		})
	}
}
