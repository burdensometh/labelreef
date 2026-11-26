package lookup

import (
	"testing"

	"labelreef/zone"
)

func dnameFixture(t *testing.T, records ...zone.Record) *zone.ZoneVersion {
	t.Helper()
	base := fixture(t)
	z, err := zone.New(base.Origin(), append(base.Records(), records...))
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func dnameRecord(t *testing.T, owner, target string, ttl uint32) zone.Record {
	t.Helper()
	r, err := zone.ParseRecord("lab.test.", owner, ttl, zone.DNAME, target)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func aRecord(t *testing.T, owner, addr string, ttl uint32) zone.Record {
	t.Helper()
	r, err := zone.ParseRecord("lab.test.", owner, ttl, zone.A, addr)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDNameStrictDescendantSynthesis(t *testing.T) {
	dname := dnameRecord(t, "map", "target.lab.test.", 130)
	// The synthesized name is host.target.lab.test., so the chain continues
	// by looking that name up; seed an A record at the rewritten owner.
	targetA := aRecord(t, "host.target", "192.0.2.77", 140)
	z := dnameFixture(t, dname, targetA)

	reply := Resolve(z, Question{Name: "host.map.lab.test.", Type: zone.A, Class: zone.ClassIN})
	if reply.Code != Success || !reply.Authoritative || len(reply.Answer) != 3 {
		t.Fatalf("unexpected DNAME answer: %+v", reply)
	}
	cname := reply.Answer[0].Records[0]
	if cname.Type != zone.CNAME || cname.Name != "host.map.lab.test." ||
		cname.Data.Target != "host.target.lab.test." || cname.TTL != 130 {
		t.Fatalf("synthesized CNAME wrong: %+v", cname)
	}
	if got := reply.Answer[1].Records[0]; got != dname {
		t.Fatalf("original DNAME missing or altered: %+v want %+v", got, dname)
	}
	if final := reply.Answer[2].Records[0]; final.Type != zone.A ||
		final.Name != "host.target.lab.test." {
		t.Fatalf("chain did not continue under target suffix: %+v", final)
	}
}

func TestDNameExactOwnerNoSynthesis(t *testing.T) {
	dname := dnameRecord(t, "map", "target.lab.test.", 130)
	txt, err := zone.ParseRecord("lab.test.", "map", 130, zone.TXT, `"note"`)
	if err != nil {
		t.Fatal(err)
	}
	z := dnameFixture(t, dname, txt)

	for _, tc := range []struct {
		name string
		typ  zone.Type
	}{
		{"map.lab.test.", zone.DNAME},
		{"map.lab.test.", zone.TXT},
		{"map.lab.test.", zone.A},
		{"map.lab.test.", zone.ANY},
	} {
		reply := Resolve(z, Question{Name: tc.name, Type: tc.typ, Class: zone.ClassIN})
		for _, set := range reply.Answer {
			if set.Type == zone.CNAME {
				t.Fatalf("%s query synthesized a CNAME at the DNAME owner: %+v", tc.typ, reply.Answer)
			}
		}
		if tc.typ == zone.DNAME && (reply.Code != Success || len(reply.Answer) != 1 ||
			reply.Answer[0].Records[0] != dname) {
			t.Fatalf("DNAME owner query did not return the stored DNAME: %+v", reply)
		}
		if tc.typ == zone.TXT && (len(reply.Answer) != 1 || reply.Answer[0].Type != zone.TXT) {
			t.Fatalf("coexisting TXT not served at DNAME owner: %+v", reply)
		}
	}
}

func TestDNameReferralPrecedence(t *testing.T) {
	// The existing child cut must win over a DNAME above or at the subtree.
	dname := dnameRecord(t, "x", "elsewhere.example.", 100)
	z := dnameFixture(t, dname)
	reply := Resolve(z, Question{Name: "www.child.lab.test.", Type: zone.A, Class: zone.ClassIN})
	if reply.Authoritative || reply.Code != Success || len(reply.Authority) != 1 ||
		reply.Authority[0].Type != zone.NS {
		t.Fatalf("DNAME overrode the earlier delegation: %+v", reply)
	}
}

func TestDNameWildcard(t *testing.T) {
	dname := dnameRecord(t, "*.wild", "target.lab.test.", 110)
	z := dnameFixture(t, dname, aRecord(t, "a.target", "192.0.2.88", 110))
	reply := Resolve(z, Question{Name: "a.wild.lab.test.", Type: zone.A, Class: zone.ClassIN})
	if reply.Code != Success || len(reply.Answer) != 3 {
		t.Fatalf("wildcard DNAME answer: %+v", reply)
	}
	cname := reply.Answer[0].Records[0]
	if cname.Name != "a.wild.lab.test." || cname.Data.Target != "a.target.lab.test." {
		t.Fatalf("wildcard synthesis wrong: %+v", cname)
	}
	if reply.Answer[1].Records[0] != dname {
		t.Fatalf("wildcard DNAME record not returned verbatim: %+v", reply.Answer[1])
	}
	if reply.Answer[2].Records[0].Name != "a.target.lab.test." {
		t.Fatalf("wildcard chain did not continue: %+v", reply.Answer[2])
	}
}

func TestDNameOversizedSynthesisIsProtocolError(t *testing.T) {
	longTarget := repeat(60, "a") + ".example."
	dname := dnameRecord(t, "map", longTarget, 100)
	z := dnameFixture(t, dname)
	qname := repeat(40, "label") + ".map.lab.test."
	reply := Resolve(z, Question{Name: qname, Type: zone.A, Class: zone.ClassIN})
	if reply.Code != YXDomain || !reply.Authoritative {
		t.Fatalf("expected authoritative YXDOMAIN, got %+v", reply)
	}
	for _, set := range reply.Answer {
		if set.Type == zone.CNAME {
			t.Fatalf("illegal over-long CNAME produced: %+v", reply.Answer)
		}
	}
	if len(reply.Authority) != 1 || reply.Authority[0].Type != zone.DNAME ||
		reply.Authority[0].Records[0] != dname {
		t.Fatalf("YXDOMAIN must carry the original DNAME in authority: %+v", reply.Authority)
	}
}

func TestDNameOutOfZoneChain(t *testing.T) {
	dname := dnameRecord(t, "map", "remote.example.", 120)
	z := dnameFixture(t, dname)
	reply := Resolve(z, Question{Name: "host.map.lab.test.", Type: zone.A, Class: zone.ClassIN})
	if reply.Code != Success || len(reply.Answer) != 2 {
		t.Fatalf("out-of-zone DNAME chain: %+v", reply)
	}
	if reply.Answer[0].Type != zone.CNAME || reply.Answer[1].Type != zone.DNAME {
		t.Fatalf("expected CNAME then DNAME, got %+v", reply.Answer)
	}
	if reply.Answer[0].Records[0].Data.Target != "host.remote.example." {
		t.Fatalf("wrong external target: %+v", reply.Answer[0].Records[0])
	}
}

func TestDNameLoopFailsSafe(t *testing.T) {
	// Two DNAMEs pointing at each other's subtrees must terminate as SERVFAIL.
	first := dnameRecord(t, "left", "right.lab.test.", 60)
	second := dnameRecord(t, "right", "left.lab.test.", 60)
	z := dnameFixture(t, first, second)
	reply := Resolve(z, Question{Name: "x.left.lab.test.", Type: zone.A, Class: zone.ClassIN})
	if reply.Code != Failure || len(reply.Answer) > maxAliases+1 {
		t.Fatalf("DNAME loop did not fail safely: %+v", reply)
	}
}

func repeat(n int, label string) string {
	out := ""
	for range n {
		out += label + "."
	}
	return out[:len(out)-1]
}
