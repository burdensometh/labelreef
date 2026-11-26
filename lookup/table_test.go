package lookup

import (
	"testing"

	"labelreef/zone"
)

// staticTable is an in-memory routing table for lookup tests. It mirrors the
// longest-suffix routing performed by the reload manager, including the DS
// exception at an exact delegation point.
type staticTable struct {
	zones map[string]*zone.ZoneVersion
}

func (s staticTable) Route(name string, typ zone.Type) *zone.ZoneVersion {
	var closest *zone.ZoneVersion
	for current := name; ; current = zone.Parent(current) {
		if z := s.zones[current]; z != nil {
			if closest == nil {
				closest = z
				if typ != zone.DS || current != name {
					return closest
				}
			} else if match := z.Find(name); match.Kind == zone.Cut && match.Cut == name {
				return z
			} else {
				return closest
			}
		}
		if current == zone.Root {
			return closest
		}
	}
}

func testZone(t *testing.T, origin string, rows [][]string) *zone.ZoneVersion {
	t.Helper()
	records := make([]zone.Record, 0, len(rows))
	for _, row := range rows {
		typ, err := zone.ParseType(row[1])
		if err != nil {
			t.Fatal(err)
		}
		record, err := zone.ParseRecord(origin, row[0], 60, typ, row[2])
		if err != nil {
			t.Fatalf("%s: %v", origin, err)
		}
		records = append(records, record)
	}
	z, err := zone.New(origin, records)
	if err != nil {
		t.Fatalf("%s: %v", origin, err)
	}
	return z
}

func twoZoneTable(t *testing.T) staticTable {
	t.Helper()
	parent := testZone(t, "lab.test.", [][]string{
		{"@", "SOA", "ns hostmaster 1 60 20 3600 45"},
		{"@", "NS", "ns.lab.test."},
		{"ns", "A", "192.0.2.53"},
		{"jump", "CNAME", "target.child.lab.test."},
		{"home", "CNAME", "back.lab.test."},
		{"back", "A", "192.0.2.77"},
		{"gone", "CNAME", "absent.child.lab.test."},
		{"empty", "CNAME", "nodata.child.lab.test."},
		{"loop", "CNAME", "loopa.child.lab.test."},
		{"child", "NS", "ns.child.lab.test."},
		{"ns.child", "A", "192.0.2.61"},
		{"ns.child", "AAAA", "2001:db8::61"},
	})
	child := testZone(t, "child.lab.test.", [][]string{
		{"@", "SOA", "ns hostmaster 9 90 30 3600 60"},
		{"@", "NS", "ns.child.lab.test."},
		{"ns", "A", "192.0.2.161"},
		{"target", "A", "192.0.2.162"},
		{"nodata", "TXT", "\"present\""},
		{"loopa", "CNAME", "loopb"},
		{"loopb", "CNAME", "loop.lab.test."},
	})
	return staticTable{zones: map[string]*zone.ZoneVersion{
		"lab.test.":       parent,
		"child.lab.test.": child,
	}}
}

func question(name string, typ zone.Type) Question {
	return Question{Name: name, Type: typ, Class: zone.ClassIN}
}

func TestCrossZoneAliasFollowsIntoLocalZone(t *testing.T) {
	table := twoZoneTable(t)
	reply := ResolveTable(table, question("jump.lab.test.", zone.A))
	if reply.Code != Success || !reply.Authoritative {
		t.Fatalf("cross-zone alias failed: %+v", reply)
	}
	if len(reply.Answer) != 2 {
		t.Fatalf("expected CNAME plus target A, got %+v", reply.Answer)
	}
	if reply.Answer[0].Type != zone.CNAME || reply.Answer[1].Type != zone.A ||
		reply.Answer[1].Records[0].Data.Addr.String() != "192.0.2.162" {
		t.Fatalf("unexpected chain content: %+v", reply.Answer)
	}
}

func TestCrossZoneAliasReturnsThroughParentZone(t *testing.T) {
	table := twoZoneTable(t)
	reply := ResolveTable(table, question("home.lab.test.", zone.A))
	if reply.Code != Success || !reply.Authoritative || len(reply.Answer) != 2 {
		t.Fatalf("alias returning to parent failed: %+v", reply)
	}
	last := reply.Answer[1]
	if last.Type != zone.A || last.Records[0].Data.Addr.String() != "192.0.2.77" {
		t.Fatalf("parent zone answer missing: %+v", last)
	}
}

func TestCrossZoneNegativeUsesTargetZoneSOA(t *testing.T) {
	table := twoZoneTable(t)
	nxdomain := ResolveTable(table, question("gone.lab.test.", zone.A))
	if nxdomain.Code != NameError || !nxdomain.Authoritative || len(nxdomain.Answer) != 1 {
		t.Fatalf("expected CNAME then NXDOMAIN, got %+v", nxdomain)
	}
	if nxdomain.Answer[0].Type != zone.CNAME {
		t.Fatalf("chain was not retained: %+v", nxdomain.Answer)
	}
	if len(nxdomain.Authority) != 1 || nxdomain.Authority[0].Type != zone.SOA {
		t.Fatalf("missing negative SOA: %+v", nxdomain.Authority)
	}
	soa := nxdomain.Authority[0].Records[0]
	if soa.Name != "child.lab.test." || soa.Data.SOA.Serial != 9 {
		t.Fatalf("negative answer must carry the child SOA, got %+v", soa)
	}

	nodata := ResolveTable(table, question("empty.lab.test.", zone.A))
	if nodata.Code != Success || !nodata.Authoritative || len(nodata.Answer) != 1 {
		t.Fatalf("expected CNAME then NODATA, got %+v", nodata)
	}
	soaSet := nodata.Authority
	if len(soaSet) != 1 || soaSet[0].Records[0].Name != "child.lab.test." ||
		soaSet[0].Records[0].TTL != 60 {
		t.Fatalf("NODATA must use the child zone minimum TTL SOA, got %+v", soaSet)
	}
}

func TestCrossZoneAliasCycleIsServfail(t *testing.T) {
	table := twoZoneTable(t)
	reply := ResolveTable(table, question("loop.lab.test.", zone.A))
	if reply.Code != Failure || len(reply.Answer) != 0 {
		t.Fatalf("cross-zone cycle must end in SERVFAIL, got %+v", reply)
	}
}

func TestDelegationOnlyZoneKeepsChainAndReferral(t *testing.T) {
	// The child zone is absent from the table, so child.lab.test. is only a
	// delegation within the parent zone.
	parent := testZone(t, "lab.test.", [][]string{
		{"@", "SOA", "ns hostmaster 1 60 20 3600 45"},
		{"@", "NS", "ns.lab.test."},
		{"ns", "A", "192.0.2.53"},
		{"jump", "CNAME", "target.child.lab.test."},
		{"child", "NS", "ns.child.lab.test."},
		{"ns.child", "A", "192.0.2.61"},
		{"ns.child", "AAAA", "2001:db8::61"},
	})
	table := staticTable{zones: map[string]*zone.ZoneVersion{"lab.test.": parent}}

	direct := ResolveTable(table, question("www.child.lab.test.", zone.A))
	if direct.Code != Success || direct.Authoritative || direct.GlueRequired != true {
		t.Fatalf("expected non-authoritative referral, got %+v", direct)
	}
	if len(direct.Answer) != 0 || len(direct.Authority) != 1 ||
		direct.Authority[0].Name != "child.lab.test." {
		t.Fatalf("unexpected referral sections: %+v", direct)
	}
	if len(direct.Additional) != 2 {
		t.Fatalf("referral must keep parent glue, got %+v", direct.Additional)
	}

	chained := ResolveTable(table, question("jump.lab.test.", zone.A))
	if chained.Code != Success || chained.Authoritative || !chained.GlueRequired {
		t.Fatalf("chained delegation must stay non-authoritative: %+v", chained)
	}
	if len(chained.Answer) != 1 || chained.Answer[0].Type != zone.CNAME {
		t.Fatalf("CNAME chain must be retained, got %+v", chained.Answer)
	}
	if len(chained.Authority) != 1 || chained.Authority[0].Name != "child.lab.test." {
		t.Fatalf("referral lost after chain: %+v", chained.Authority)
	}
	if len(chained.Additional) != 2 {
		t.Fatalf("referral glue lost after chain: %+v", chained.Additional)
	}
}

func TestOutsideTargetPreservesChain(t *testing.T) {
	parent := testZone(t, "lab.test.", [][]string{
		{"@", "SOA", "ns hostmaster 1 60 20 3600 45"},
		{"@", "NS", "ns.lab.test."},
		{"ns", "A", "192.0.2.53"},
		{"remote", "CNAME", "site.example."},
	})
	table := staticTable{zones: map[string]*zone.ZoneVersion{"lab.test.": parent}}
	reply := ResolveTable(table, question("remote.lab.test.", zone.A))
	if reply.Code != Success || !reply.Authoritative || len(reply.Answer) != 1 ||
		reply.Answer[0].Type != zone.CNAME {
		t.Fatalf("outside target must retain the local chain: %+v", reply)
	}
}

func TestUnknownQuestionNameIsRefused(t *testing.T) {
	table := twoZoneTable(t)
	reply := ResolveTable(table, question("unrelated.example.", zone.A))
	if reply.Code != Refused {
		t.Fatalf("name outside every hosted zone must be REFUSED, got %+v", reply)
	}
}

func TestSingleZoneEntryBehavesThroughTable(t *testing.T) {
	table := twoZoneTable(t)
	parent := table.zones["lab.test."]
	direct := Resolve(parent, question("home.lab.test.", zone.A))
	viaTable := ResolveTable(singleZone{zone: parent}, question("home.lab.test.", zone.A))
	if len(direct.Answer) != len(viaTable.Answer) || direct.Code != viaTable.Code {
		t.Fatalf("single-zone and table paths diverge: %+v vs %+v", direct, viaTable)
	}
	outside := Resolve(parent, question("far.away.example.", zone.A))
	if outside.Code != Refused {
		t.Fatalf("single-zone lookup must refuse names outside its zone: %+v", outside)
	}
	cut := Resolve(parent, question("target.child.lab.test.", zone.A))
	if cut.Authoritative || !cut.GlueRequired || len(cut.Additional) != 2 {
		t.Fatalf("single-zone lookup must keep the in-zone delegation referral: %+v", cut)
	}
}

func TestCrossZoneCycleDropsPartialChain(t *testing.T) {
	// The loop visits loop -> loopa -> loopb -> loop across two hosted zones.
	// It must terminate in SERVFAIL without leaking the accumulated CNAMEs;
	// out-of-zone targets keep their own chain-preserving behavior instead
	// (see TestOutsideTargetPreservesChain).
	table := twoZoneTable(t)
	reply := ResolveTable(table, question("loop.lab.test.", zone.A))
	if reply.Code != Failure || len(reply.Answer) != 0 || len(reply.Authority) != 0 {
		t.Fatalf("SERVFAIL must not leak a partial chain: %+v", reply)
	}
}

func TestChainReachingCutIsNonAuthoritativeWithGlue(t *testing.T) {
	// Host only the parent: the CNAME target lies below the parent's cut.
	parent := testZone(t, "lab.test.", [][]string{
		{"@", "SOA", "ns hostmaster 1 60 20 3600 45"},
		{"@", "NS", "ns.lab.test."},
		{"ns", "A", "192.0.2.53"},
		{"jump", "CNAME", "www.child.lab.test."},
		{"child", "NS", "ns.child.lab.test."},
		{"ns.child", "A", "192.0.2.61"},
		{"ns.child", "AAAA", "2001:db8::61"},
	})
	table := staticTable{zones: map[string]*zone.ZoneVersion{"lab.test.": parent}}
	reply := ResolveTable(table, question("jump.lab.test.", zone.A))
	if reply.Authoritative || !reply.GlueRequired {
		t.Fatalf("chain ending at a cut must be a non-authoritative referral: %+v", reply)
	}
	if len(reply.Answer) != 1 || reply.Answer[0].Type != zone.CNAME {
		t.Fatalf("chain missing before the cut: %+v", reply.Answer)
	}
	if len(reply.Additional) != 2 {
		t.Fatalf("cut glue missing along the chain: %+v", reply.Additional)
	}
}

func TestDirectQuestionAtCutIsNonAuthoritative(t *testing.T) {
	table := twoZoneTable(t)
	// With the child hosted, a name inside it is answered authoritatively.
	if reply := ResolveTable(table, question("www.child.lab.test.", zone.A)); !reply.Authoritative {
		t.Fatalf("hosted child must answer authoritatively: %+v", reply)
	}
	parentOnly := staticTable{zones: map[string]*zone.ZoneVersion{"lab.test.": table.zones["lab.test."]}}
	reply := ResolveTable(parentOnly, question("www.child.lab.test.", zone.A))
	if reply.Authoritative || reply.Code != Success || len(reply.Additional) != 2 {
		t.Fatalf("delegated cut must produce a referral with glue: %+v", reply)
	}
}
