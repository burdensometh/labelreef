package serve

import (
	"context"
	"testing"
	"time"

	"labelreef/lookup"
	"labelreef/transfer"
	"labelreef/zone"
)

// TestDNameTransferConvergence builds a primary zone containing a DNAME,
// transfers it to a secondary over real TCP frames, and proves both nodes
// return the same synthesized chain for the same legal question.
func TestDNameTransferConvergence(t *testing.T) {
	base := exampleZone(t)
	dname, err := zone.ParseRecord(base.Origin(), "map", 130, zone.DNAME, "target.lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := zone.ParseRecord(base.Origin(), "host.target", 140, zone.A, "192.0.2.77")
	if err != nil {
		t.Fatal(err)
	}
	primaryZone, err := zone.New(base.Origin(), append(base.Records(), dname, leaf))
	if err != nil {
		t.Fatal(err)
	}
	primaryResolver := fixtureResolver{primaryZone}
	primary := testServer(t, primaryResolver, nil)

	// Drive the same framed AXFR path a real secondary uses.
	client := Client{IOTimeout: 2 * time.Second}
	candidate, err := client.Fetch(context.Background(), primary.Address(), base.Origin(), nil)
	if err != nil || candidate.Kind != transfer.Full {
		t.Fatalf("AXFR of DNAME zone failed: %+v %v", candidate, err)
	}
	if got := candidate.Zone.Set("map.lab.test.", zone.DNAME); len(got.Records) != 1 ||
		got.Records[0] != dname {
		t.Fatalf("DNAME did not survive the transfer: %+v", got)
	}
	secondary := testServer(t, fixtureResolver{candidate.Zone}, nil)

	question := "host.map.lab.test."
	primaryReply, err := Probe(context.Background(), question, zone.A, ProbeOptions{
		Address: primary.Address(), TCP: true, Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondaryReply, err := Probe(context.Background(), question, zone.A, ProbeOptions{
		Address: secondary.Address(), TCP: true, Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if primaryReply.Code != "NOERROR" || len(primaryReply.Answer) != 3 {
		t.Fatalf("primary chain wrong: %+v", primaryReply)
	}
	if len(secondaryReply.Answer) != len(primaryReply.Answer) {
		t.Fatalf("answer chain length differs: primary=%d secondary=%d",
			len(primaryReply.Answer), len(secondaryReply.Answer))
	}
	for i := range primaryReply.Answer {
		if primaryReply.Answer[i] != secondaryReply.Answer[i] {
			t.Fatalf("record %d diverged after transfer:\n primary=%+v\nsecondary=%+v",
				i, primaryReply.Answer[i], secondaryReply.Answer[i])
		}
	}
	wantOrder := []zone.Type{zone.CNAME, zone.DNAME, zone.A}
	for i, typ := range wantOrder {
		if got := primaryReply.Answer[i].Type; got != typ.String() {
			t.Fatalf("answer %d is %s, want %s", i, got, typ)
		}
	}

	// The DNAME owner query must not synthesize a CNAME on either node.
	for _, server := range []*Server{primary, secondary} {
		ownerReply, err := Probe(context.Background(), "map.lab.test.", zone.DNAME, ProbeOptions{
			Address: server.Address(), TCP: true, Timeout: 2 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(ownerReply.Answer) != 1 || ownerReply.Answer[0].Type != "DNAME" {
			t.Fatalf("DNAME owner query synthesized records: %+v", ownerReply.Answer)
		}
	}
}

// TestDNameYXDOMAINOverWire confirms the protocol error reaches clients and
// no illegal over-long CNAME appears in any section.
func TestDNameYXDOMAINOverWire(t *testing.T) {
	base := exampleZone(t)
	dname, err := zone.ParseRecord(base.Origin(), "map", 100, zone.DNAME,
		repeatLabel(60, "a")+".example.")
	if err != nil {
		t.Fatal(err)
	}
	z, err := zone.New(base.Origin(), append(base.Records(), dname))
	if err != nil {
		t.Fatal(err)
	}
	server := testServer(t, fixtureResolver{z}, nil)
	reply, err := Probe(context.Background(), repeatLabel(40, "label")+".map.lab.test.",
		zone.A, ProbeOptions{Address: server.Address(), TCP: true, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if reply.Code != lookup.YXDomain.String() || !reply.Authoritative {
		t.Fatalf("wire YXDOMAIN mismatch: %+v", reply)
	}
	for _, section := range [][]zone.RecordV1{reply.Answer, reply.Authority, reply.Additional} {
		for _, rr := range section {
			if rr.Type == "CNAME" {
				t.Fatalf("illegal CNAME on the wire: %+v", rr)
			}
		}
	}
	if len(reply.Authority) != 1 || reply.Authority[0].Type != "DNAME" {
		t.Fatalf("YXDOMAIN authority must carry the DNAME: %+v", reply.Authority)
	}
}

func repeatLabel(n int, label string) string {
	out := ""
	for range n {
		out += label + "."
	}
	return out[:len(out)-1]
}
