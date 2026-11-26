package lookup

import (
	"os"
	"testing"

	"labelreef/zone"
)

func fixture(t *testing.T) *zone.ZoneVersion {
	t.Helper()
	f, err := os.Open("../examples/zones/lab-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	version, err := zone.DecodeV1(f)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

func TestAliasAndNegativeAuthority(t *testing.T) {
	version := fixture(t)
	for _, test := range []struct {
		name string
		typ  zone.Type
		code Code
		n    int
		soa  bool
	}{
		{"alias", zone.A, Success, 2, false},
		{"remote", zone.A, Success, 1, false},
		{"alias", zone.AAAA, Success, 1, true},
		{"branch", zone.A, Success, 0, true},
		{"gone.branch", zone.A, NameError, 0, true},
		{"random", zone.A, Success, 1, false},
		{"random", zone.AAAA, Success, 0, true},
		{"www", zone.Type(65400), Success, 0, true},
	} {
		t.Run(test.name+"/"+test.typ.String(), func(t *testing.T) {
			q := Question{Name: test.name + ".lab.test.", Type: test.typ, Class: zone.ClassIN}
			reply := Resolve(version, q)
			if reply.Code != test.code || !reply.Authoritative || len(reply.Answer) != test.n {
				t.Fatalf("unexpected response %+v", reply)
			}
			if test.soa {
				r := reply.Authority[0].Records[0]
				if r.Type != zone.SOA || r.TTL != 45 || r.Data.SOA.Serial != version.Serial() {
					t.Fatalf("invalid negative SOA %+v", r)
				}
			}
			if test.name == "random" && test.n > 0 && reply.Answer[0].Name != q.Name {
				t.Fatalf("wildcard owner not synthesized: %s", reply.Answer[0].Name)
			}
		})
	}
}

func TestDelegatedData(t *testing.T) {
	version := fixture(t)
	q := Question{Name: "www.child.lab.test.", Type: zone.A, Class: zone.ClassIN}
	reply := Resolve(version, q)
	if reply.Authoritative || len(reply.Answer) != 0 || len(reply.Authority) != 1 ||
		len(reply.Authority[0].Records) != 2 || len(reply.Additional) != 2 || reply.RequiredAdditional != 2 {
		t.Fatalf("unexpected referral %+v", reply)
	}
	for _, s := range reply.Additional {
		if s.Name != "ns.child.lab.test." {
			t.Fatalf("unrelated glue: %s", s.Name)
		}
	}
	q.Name = "child.lab.test."
	q.Type = zone.DS
	reply = Resolve(version, q)
	if !reply.Authoritative || len(reply.Answer) != 1 || reply.Answer[0].Type != zone.DS {
		t.Fatalf("expected parent DS authority, got %+v", reply)
	}
}

// siblingZone adds a second delegation beside child.lab.test. One name server
// is glue inside that delegation. Another points into the sibling
// child.lab.test. delegation, whose addresses the parent zone holds. A third is
// outside the zone.
func siblingZone(t *testing.T) *zone.ZoneVersion {
	t.Helper()
	base := fixture(t)
	for _, row := range []struct {
		name, typ, data string
		ttl             uint32
	}{
		{"second", "NS", "ns.second", 600},
		{"second", "NS", "ns.child", 600},
		{"second", "NS", "ns.external.example.", 600},
		{"ns.second", "A", "192.0.2.71", 600},
	} {
		typ, err := zone.ParseType(row.typ)
		if err != nil {
			t.Fatal(err)
		}
		record, err := zone.ParseRecord(base.Origin(), row.name, row.ttl, typ, row.data)
		if err != nil {
			t.Fatal(err)
		}
		version, err := zone.New(base.Origin(), append(base.Records(), record))
		if err != nil {
			t.Fatal(err)
		}
		base = version
	}
	return base
}

func TestSiblingDelegationGlueIsOptional(t *testing.T) {
	version := siblingZone(t)
	q := Question{Name: "www.second.lab.test.", Type: zone.A, Class: zone.ClassIN}
	reply := Resolve(version, q)
	if reply.Authoritative || len(reply.Answer) != 0 || len(reply.Authority) != 1 ||
		reply.Authority[0].Name != "second.lab.test." || len(reply.Authority[0].Records) != 3 {
		t.Fatalf("unexpected referral %+v", reply)
	}
	// ns.second.lab.test. sits directly in the target delegation, so its address
	// is required. ns.child.lab.test. belongs to a sibling cut, so the parent
	// zone's addresses for it are optional. ns.external.example. gets no glue.
	if reply.RequiredAdditional != 1 || len(reply.Additional) != 3 {
		t.Fatalf("glue classification: required=%d additional=%d", reply.RequiredAdditional, len(reply.Additional))
	}
	wanted := []string{
		"ns.second.lab.test.|A",
		"ns.child.lab.test.|A", "ns.child.lab.test.|AAAA",
	}
	for i, s := range reply.Additional {
		if got := s.Name + "|" + s.Type.String(); got != wanted[i] {
			t.Fatalf("additional %d = %s, want %s", i, got, wanted[i])
		}
	}
	if s := reply.Additional[0]; s.Name != "ns.second.lab.test." || s.Name == reply.Authority[0].Name {
		t.Fatalf("required glue should be inside the target delegation: %s", s.Name)
	}
	for _, s := range reply.Additional[reply.RequiredAdditional:] {
		if !zone.Within(s.Name, "child.lab.test.") {
			t.Fatalf("optional glue should be the sibling's: %s", s.Name)
		}
	}
}
