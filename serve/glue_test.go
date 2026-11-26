package serve

import (
	"context"
	"fmt"
	"testing"
	"time"

	"labelreef/zone"
)

// glueZone extends the example zone with a "big" delegation. ns.big is glue
// inside that delegation and therefore required. ns.child is the sibling
// child.lab.test. delegation, so the parent zone's addresses for it are
// optional. ns.external.example. is out of zone and never gets glue.
func glueZone(t *testing.T, bulk int) *zone.ZoneVersion {
	t.Helper()
	origin := exampleZone(t).Origin()
	var records []zone.Record
	add := func(name, typ, data string, ttl uint32) {
		t.Helper()
		parsed, err := zone.ParseType(typ)
		if err != nil {
			t.Fatal(err)
		}
		record, err := zone.ParseRecord(origin, name, ttl, parsed, data)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	records = append(records, exampleZone(t).Records()...)
	for _, row := range []struct {
		name, typ, data string
		ttl             uint32
	}{
		{"big", "NS", "ns.big", 300},
		{"big", "NS", "ns.child", 300},
		{"big", "NS", "ns.external.example.", 300},
		{"ns.big", "A", "192.0.2.80", 300},
	} {
		add(row.name, row.typ, row.data, row.ttl)
	}
	for i := 0; i < bulk; i++ {
		add("ns.child", "A", fmt.Sprintf("192.0.2.%d", 150+i), 600)
	}
	version, err := zone.New(origin, records)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

// hugeZone gives the "huge" delegation one required glue RRset of forty A
// records, which is too large for a plain UDP reply.
func hugeZone(t *testing.T) *zone.ZoneVersion {
	t.Helper()
	origin := exampleZone(t).Origin()
	records := append([]zone.Record(nil), exampleZone(t).Records()...)
	for _, row := range []struct{ name, typ, data string }{
		{"huge", "NS", "ns.huge"},
		{"huge", "NS", "ns.external.example."},
	} {
		record, err := zone.ParseRecord(origin, row.name, 300, zone.NS, row.data)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	for i := 0; i < 40; i++ {
		record, err := zone.ParseRecord(origin, "ns.huge", 300, zone.A, fmt.Sprintf("192.0.2.%d", 180+i))
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	version, err := zone.New(origin, records)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

func TestOptionalGlueDropDoesNotTruncate(t *testing.T) {
	// The bulk sibling RRset exceeds the plain UDP budget on its own, while the
	// required ns.big address fits comfortably.
	s := testServer(t, fixtureResolver{glueZone(t, 40)}, nil)
	plain, err := Probe(context.Background(), "www.big.lab.test.", zone.A, ProbeOptions{
		Address: s.Address(), Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Truncated || plain.Authoritative || len(plain.Answer) != 0 || plain.Bytes > 512 {
		t.Fatalf("optional glue drop truncated the referral: %+v", plain)
	}
	if len(plain.Authority) != 3 {
		t.Fatalf("referral authority is not a complete NS RRset: %+v", plain.Authority)
	}
	if len(plain.Additional) == 0 || plain.Additional[0].Name != "ns.big.lab.test." ||
		plain.Additional[0].Type != "A" {
		t.Fatalf("required glue not written first: %+v", plain.Additional)
	}
	for _, record := range plain.Additional {
		if record.Name == "ns.external.example." {
			t.Fatalf("out-of-zone glue was attached: %+v", record)
		}
		if record.Name == "ns.child.lab.test." && record.Type == "A" {
			t.Fatalf("oversized optional RRset was partially written: %+v", plain.Additional)
		}
	}
	// A complete EDNS budget carries the optional sibling RRset too.
	wide, err := Probe(context.Background(), "www.big.lab.test.", zone.A, ProbeOptions{
		Address: s.Address(), Timeout: 2 * time.Second, EDNSSize: 1232,
	})
	if err != nil {
		t.Fatal(err)
	}
	if wide.Truncated {
		t.Fatalf("EDNS referral truncated: %+v", wide)
	}
	// The sibling RRset is the seed's own 192.0.2.61 A record plus the forty
	// added above, and must arrive whole or not at all.
	want := len(glueZone(t, 40).Set("ns.child.lab.test.", zone.A).Records)
	var optional int
	for _, record := range wide.Additional {
		if record.Name == "ns.child.lab.test." && record.Type == "A" {
			optional++
		}
	}
	if optional != want {
		t.Fatalf("optional glue RRset split: %d of %d records", optional, want)
	}
}

func TestMissingRequiredGlueTruncates(t *testing.T) {
	// The only required glue is one forty-record A RRset that cannot fit in a
	// plain UDP reply, so the referral must be marked truncated.
	s := testServer(t, fixtureResolver{hugeZone(t)}, nil)
	plain, err := Probe(context.Background(), "www.huge.lab.test.", zone.A, ProbeOptions{
		Address: s.Address(), Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plain.Truncated {
		t.Fatalf("dropping required glue did not set TC: %+v", plain)
	}
	// A larger EDNS budget carries the complete required RRset in full.
	wide, err := Probe(context.Background(), "www.huge.lab.test.", zone.A, ProbeOptions{
		Address: s.Address(), Timeout: 2 * time.Second, EDNSSize: 1232,
	})
	if err != nil {
		t.Fatal(err)
	}
	if wide.Truncated {
		t.Fatalf("EDNS referral still truncated: %+v", wide)
	}
	var required int
	for _, record := range wide.Additional {
		if record.Name == "ns.huge.lab.test." {
			required++
		}
	}
	if required != 40 {
		t.Fatalf("required glue RRset split: %d of 40 records", required)
	}
}
