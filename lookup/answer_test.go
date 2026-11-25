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
		len(reply.Authority[0].Records) != 2 || len(reply.Additional) != 2 || !reply.GlueRequired {
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
