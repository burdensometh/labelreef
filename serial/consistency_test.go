package serial

import (
	"testing"

	"labelreef/zone"
)

// The consistency suite pins the convergence of the owner and RRset rules:
// applying one journal delta with Replay must reach the same verdict as a
// full zone load of the resulting records, and a rejected delta must leave
// the replay state untouched.

func parseRecord(t *testing.T, origin, owner string, ttl uint32, typ zone.Type, data string) zone.Record {
	t.Helper()
	record, err := zone.ParseRecord(origin, owner, ttl, typ, data)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func consistencyBase(t *testing.T, extra ...zone.Record) *zone.ZoneVersion {
	t.Helper()
	records := []zone.Record{
		parseRecord(t, "lab.test.", "@", 600, zone.SOA, "ns admin 100 60 20 3600 45"),
		parseRecord(t, "lab.test.", "@", 600, zone.NS, "ns"),
		parseRecord(t, "lab.test.", "ns", 300, zone.A, "192.0.2.53"),
	}
	z, err := zone.New("lab.test.", append(records, extra...))
	if err != nil {
		t.Fatalf("base zone rejected: %v", err)
	}
	return z
}

func step(base *zone.ZoneVersion, next uint32, deletes, adds []zone.Record) JournalDelta {
	return JournalDelta{
		Before:  base.SOA(),
		After:   base.SOA().WithSerial(next),
		Deletes: deletes,
		Adds:    adds,
	}
}

// prospective applies a delta to a record multiset with no validation, so the
// full-load path judges the same final state the journal path was offered.
func prospective(base *zone.ZoneVersion, d JournalDelta) []zone.Record {
	final := []zone.Record{base.SOA().WithSerial(d.To())}
	for _, record := range base.Records() {
		if record.Type != zone.SOA {
			final = append(final, record)
		}
	}
	for _, record := range d.Deletes {
		for i, have := range final {
			if have == record {
				final = append(final[:i], final[i+1:]...)
				break
			}
		}
	}
	return append(final, d.Adds...)
}

func TestReplayAndFullLoadAgree(t *testing.T) {
	rec := func(owner string, ttl uint32, typ zone.Type, data string) zone.Record {
		return parseRecord(t, "lab.test.", owner, ttl, typ, data)
	}
	dsData := "18889 13 2 E06D44B80B55EDF1D4AA75BBEF7D9D6146F5429D4D5640EC2F726D9D20332285"
	for _, tc := range []struct {
		name    string
		extra   []zone.Record
		deletes []zone.Record
		adds    []zone.Record
	}{
		{"expose-illegal-subdelegation",
			[]zone.Record{rec("sub", 600, zone.NS, "ns"), rec("deep.sub", 600, zone.NS, "ns"), rec("deep.sub", 600, zone.TXT, `"hidden"`)},
			[]zone.Record{rec("sub", 600, zone.NS, "ns")}, nil},
		{"expose-legal-subdelegation",
			[]zone.Record{rec("sub", 600, zone.NS, "ns"), rec("deep.sub", 600, zone.NS, "ns"), rec("deep.sub", 600, zone.DS, dsData)},
			[]zone.Record{rec("sub", 600, zone.NS, "ns")}, nil},
		{"expose-wildcard-subdelegation",
			[]zone.Record{rec("sub", 600, zone.NS, "ns"), rec("*.sub", 600, zone.NS, "ns")},
			[]zone.Record{rec("sub", 600, zone.NS, "ns")}, nil},
		{"nested-exposure",
			[]zone.Record{rec("a", 600, zone.NS, "ns"), rec("b.a", 600, zone.NS, "ns"), rec("c.b.a", 600, zone.NS, "ns"), rec("c.b.a", 600, zone.TXT, `"hidden"`)},
			[]zone.Record{rec("a", 600, zone.NS, "ns"), rec("b.a", 600, zone.NS, "ns")}, nil},
		{"nested-remove-middle-stays-hidden",
			[]zone.Record{rec("a", 600, zone.NS, "ns"), rec("b.a", 600, zone.NS, "ns"), rec("c.b.a", 600, zone.NS, "ns"), rec("c.b.a", 600, zone.TXT, `"hidden"`)},
			[]zone.Record{rec("b.a", 600, zone.NS, "ns")}, nil},
		{"cut-moved-onto-illegal-owner",
			[]zone.Record{rec("a", 600, zone.NS, "ns"), rec("b.a", 600, zone.TXT, `"data"`)},
			[]zone.Record{rec("a", 600, zone.NS, "ns")},
			[]zone.Record{rec("b.a", 600, zone.NS, "ns")}},
		{"cut-and-hidden-data-removed",
			[]zone.Record{rec("sub", 600, zone.NS, "ns"), rec("deep.sub", 600, zone.NS, "ns"), rec("deep.sub", 600, zone.TXT, `"hidden"`)},
			[]zone.Record{rec("sub", 600, zone.NS, "ns"), rec("deep.sub", 600, zone.TXT, `"hidden"`)}, nil},
		{"txt-at-delegation",
			[]zone.Record{rec("sub", 600, zone.NS, "ns")},
			nil, []zone.Record{rec("sub", 600, zone.TXT, `"bad"`)}},
		{"mx-at-delegation",
			[]zone.Record{rec("sub", 600, zone.NS, "ns")},
			nil, []zone.Record{rec("sub", 600, zone.MX, "10 ns")}},
		{"txt-below-cut",
			[]zone.Record{rec("sub", 600, zone.NS, "ns")},
			nil, []zone.Record{rec("deep.sub", 600, zone.TXT, `"ok"`)}},
		{"address-at-exposed-subdelegation",
			[]zone.Record{rec("sub", 600, zone.NS, "ns"), rec("deep.sub", 600, zone.NS, "ns"), rec("deep.sub", 600, zone.A, "192.0.2.77")},
			[]zone.Record{rec("sub", 600, zone.NS, "ns")}, nil},
		{"cname-coexist",
			[]zone.Record{rec("www", 120, zone.A, "192.0.2.10")},
			nil, []zone.Record{rec("www", 120, zone.CNAME, "ns")}},
		{"cname-added-at-cut",
			[]zone.Record{rec("sub", 600, zone.NS, "ns")},
			nil, []zone.Record{rec("sub", 600, zone.CNAME, "ns")}},
		{"mixed-ttl",
			[]zone.Record{rec("www", 120, zone.A, "192.0.2.10")},
			nil, []zone.Record{rec("www", 999, zone.A, "192.0.2.11")}},
		{"ttl-change-at-cut",
			[]zone.Record{rec("sub", 600, zone.NS, "ns")},
			[]zone.Record{rec("sub", 600, zone.NS, "ns")},
			[]zone.Record{rec("sub", 300, zone.NS, "ns")}},
		{"remove-apex-ns",
			nil,
			[]zone.Record{rec("@", 600, zone.NS, "ns")}, nil},
		{"wildcard-delegation",
			nil,
			nil, []zone.Record{rec("*", 600, zone.NS, "ns")}},
		{"soa-in-adds",
			nil,
			nil, []zone.Record{rec("sub", 600, zone.SOA, "ns admin 1 2 3 4 5")}},
		{"duplicate-add",
			nil,
			nil, []zone.Record{rec("www", 120, zone.A, "192.0.2.10"), rec("www", 120, zone.A, "192.0.2.10")}},
		{"add-existing",
			[]zone.Record{rec("www", 120, zone.A, "192.0.2.10")},
			nil, []zone.Record{rec("www", 120, zone.A, "192.0.2.10")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := consistencyBase(t, tc.extra...)
			d := step(base, 101, tc.deletes, tc.adds)

			replay := NewReplay(base)
			replayErr := replay.Apply(d)
			if replayErr != nil {
				current, err := replay.Zone()
				if err != nil || !Same(current, base) {
					t.Fatalf("rejected delta changed replay state: %v", err)
				}
			}
			loaded, loadErr := zone.New(base.Origin(), prospective(base, d))
			if (replayErr == nil) != (loadErr == nil) {
				t.Fatalf("verdicts diverge: replay %v, full load %v", replayErr, loadErr)
			}
			if replayErr == nil {
				applied, err := replay.Zone()
				if err != nil || !Same(applied, loaded) {
					t.Fatalf("accepted delta disagrees with full load: %v", err)
				}
			}
			t.Logf("agree: rejected=%t (%v)", replayErr != nil, replayErr)
		})
	}
}

// A rejected segment neither advances the replay nor blocks a later legal
// segment, and the exposure of a hidden delegation is rechecked per segment.
func TestReplayRejectsPerSegment(t *testing.T) {
	rec := func(owner string, ttl uint32, typ zone.Type, data string) zone.Record {
		return parseRecord(t, "lab.test.", owner, ttl, typ, data)
	}
	subNS := rec("sub", 600, zone.NS, "ns")
	deepTXT := rec("deep.sub", 600, zone.TXT, `"hidden"`)
	base := consistencyBase(t, subNS, rec("deep.sub", 600, zone.NS, "ns"), deepTXT)

	replay := NewReplay(base)
	first := step(base, 101, nil, []zone.Record{rec("www", 120, zone.A, "192.0.2.10")})
	if err := replay.Apply(first); err != nil {
		t.Fatalf("legal first segment rejected: %v", err)
	}
	afterFirst, err := replay.Zone()
	if err != nil {
		t.Fatal(err)
	}

	// Removing the upper delegation alone exposes the illegal hidden cut.
	expose := step(afterFirst, 102, []zone.Record{subNS}, nil)
	if err := replay.Apply(expose); err == nil {
		t.Fatal("exposure of an illegal sub-delegation was accepted")
	}
	current, err := replay.Zone()
	if err != nil || !Same(current, afterFirst) {
		t.Fatalf("rejected segment changed replay state: %v", err)
	}

	// Removing the hidden TXT in the same segment makes the exposure legal.
	clean := step(afterFirst, 102, []zone.Record{subNS, deepTXT}, nil)
	if err := replay.Apply(clean); err != nil {
		t.Fatalf("legal exposure rejected: %v", err)
	}
	final, err := replay.Zone()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := zone.New(base.Origin(), prospective(afterFirst, clean))
	if err != nil || !Same(final, loaded) {
		t.Fatalf("final state disagrees with full load: %v", err)
	}
}
