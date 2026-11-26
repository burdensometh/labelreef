package serve

import (
	"fmt"
	"net/netip"
	"testing"

	"labelreef/lookup"
	"labelreef/zone"
)

func labelreefSharedSuffixRRset(n int) zone.RRset {
	records := make([]zone.Record, n)
	for i := range records {
		records[i] = zone.Record{
			Name: "large.lab.test.",
			Type: zone.MX,
			TTL:  60,
			Data: zone.RData{
				Priority: 10,
				Target:   fmt.Sprintf("mx-%04d.pool.shared-suffix.lab.test.", i),
			},
		}
	}
	return zone.NewRRset(records)
}

func labelreefBudgetQuery(size uint16) query {
	q := query{
		header:  header{id: 0x1234},
		rawName: "large.lab.test.",
		question: lookup.Question{
			Name:  "large.lab.test.",
			Type:  zone.MX,
			Class: zone.ClassIN,
		},
	}
	if size != 0 {
		q.opt = &edns{size: size}
	}
	return q
}

func labelreefDecodeBudgetPacket(t *testing.T, packet []byte, q query, budget int) ProbeResult {
	t.Helper()
	decoded, err := decodeProbe(packet, q.id, q.question)
	if err != nil {
		t.Fatalf("decoder rejected budget response: %v", err)
	}
	if decoded.Bytes != len(packet) || decoded.Bytes > budget {
		t.Fatalf("response used %d bytes, budget %d", len(packet), budget)
	}
	return decoded
}

func TestLabelreefLargeRRsetPlainAndEDNSBudget(t *testing.T) {
	big := labelreefSharedSuffixRRset(256)
	reply := lookup.Answer{
		Code:          lookup.Success,
		Authoritative: true,
		Answer:        []zone.RRset{big},
	}

	for _, tc := range []struct {
		name   string
		edns   uint16
		budget int
	}{
		{name: "plain", budget: plainUDP},
		{name: "edns", edns: 1232, budget: 1232},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := labelreefBudgetQuery(tc.edns)
			packet := encodeAnswer(q, reply, false, 1232)
			decoded := labelreefDecodeBudgetPacket(t, packet, q, tc.budget)
			if !decoded.Truncated || len(decoded.Answer) != 0 {
				t.Fatalf("complete RRset was not omitted as a unit: tc=%v answers=%d",
					decoded.Truncated, len(decoded.Answer))
			}
			if tc.edns != 0 && decoded.AdvertisedUDP != 1232 {
				t.Fatalf("EDNS advertisement = %d, want 1232", decoded.AdvertisedUDP)
			}
		})
	}
}

func TestLabelreefPlainAndEDNSDifferentBudgetOutcomes(t *testing.T) {
	set := labelreefSharedSuffixRRset(32)
	reply := lookup.Answer{Code: lookup.Success, Authoritative: true, Answer: []zone.RRset{set}}

	plainQ := labelreefBudgetQuery(0)
	plain := encodeAnswer(plainQ, reply, false, 1232)
	decodedPlain := labelreefDecodeBudgetPacket(t, plain, plainQ, plainUDP)
	if !decodedPlain.Truncated || len(decodedPlain.Answer) != 0 {
		t.Fatalf("plain DNS did not omit the complete RRset: tc=%v answers=%d",
			decodedPlain.Truncated, len(decodedPlain.Answer))
	}

	ednsQ := labelreefBudgetQuery(1232)
	edns := encodeAnswer(ednsQ, reply, false, 1232)
	decodedEDNS := labelreefDecodeBudgetPacket(t, edns, ednsQ, 1232)
	if decodedEDNS.Truncated || len(decodedEDNS.Answer) != len(set.Records) {
		t.Fatalf("EDNS did not preserve the complete RRset: tc=%v answers=%d want=%d",
			decodedEDNS.Truncated, len(decodedEDNS.Answer), len(set.Records))
	}
	if decodedEDNS.AdvertisedUDP != 1232 {
		t.Fatalf("EDNS advertisement = %d, want 1232", decodedEDNS.AdvertisedUDP)
	}
}

func TestLabelreefRRsetBudgetMatchesWireEncoding(t *testing.T) {
	q := labelreefBudgetQuery(1232)
	prefix := zone.NewRRset([]zone.Record{{
		Name: "prefix.shared-suffix.lab.test.",
		Type: zone.A,
		TTL:  60,
		Data: zone.RData{Addr: netip.MustParseAddr("198.51.100.1")},
	}})
	candidate := zone.RRset{Records: []zone.Record{
		{Name: "large.lab.test.", Type: zone.A, TTL: 60, Data: zone.RData{Addr: netip.MustParseAddr("192.0.2.1")}},
		{Name: "large.lab.test.", Type: zone.AAAA, TTL: 60, Data: zone.RData{Addr: netip.MustParseAddr("2001:db8::1")}},
		{Name: "delegated.lab.test.", Type: zone.NS, TTL: 60, Data: zone.RData{Target: "ns1.names.shared-suffix.lab.test."}},
		{Name: "alias.lab.test.", Type: zone.CNAME, TTL: 60, Data: zone.RData{Target: "target.shared-suffix.lab.test."}},
		{Name: "ptr.lab.test.", Type: zone.PTR, TTL: 60, Data: zone.RData{Target: "host.shared-suffix.lab.test."}},
		{Name: "large.lab.test.", Type: zone.MX, TTL: 60, Data: zone.RData{Priority: 10, Target: "mx1.mail.shared-suffix.lab.test."}},
		{Name: "large.lab.test.", Type: zone.MX, TTL: 60, Data: zone.RData{Priority: 20, Target: "mx2.mail.shared-suffix.lab.test."}},
		{Name: "lab.test.", Type: zone.SOA, TTL: 60, Data: zone.RData{SOA: zone.SOAData{
			Primary: "ns1.lab.test.", Mailbox: "admin.lab.test.", Serial: 42,
			Refresh: 1, Retry: 2, Expire: 3, Minimum: 4,
		}}},
		{Name: "srv.lab.test.", Type: zone.SRV, TTL: 60, Data: zone.RData{
			Priority: 1, Weight: 2, Port: 3, Target: "srv.target.shared-suffix.lab.test.",
		}},
		{Name: "txt.lab.test.", Type: zone.TXT, TTL: 60, Data: zone.RData{Text: "\x03abc\x04wxyz"}},
		{Name: "ds.lab.test.", Type: zone.DS, TTL: 60, Data: zone.RData{
			KeyTag: 1234, Algorithm: 13, DigestType: 2, Digest: "digest-bytes",
		}},
		{Name: "caa.lab.test.", Type: zone.CAA, TTL: 60, Data: zone.RData{
			Flags: 0, Tag: "issue", Value: "letsencrypt.org",
		}},
		{Name: "bin\\001label.shared-suffix.lab.test.", Type: zone.TXT, TTL: 60, Data: zone.RData{Text: "\x02ok"}},
	}}

	newCommittedWriter := func() *wireWriter {
		w := newWriter(4096)
		h := q.responseHeader(lookup.Success)
		q.addQuestion(w, &h)
		for _, rr := range prefix.Records {
			w.record(rr)
		}
		return w
	}

	encoded := newCommittedWriter()
	committedLen := len(encoded.data)
	measured := getReefBudget(encoded.dict, committedLen)
	defer putReefBudget(measured)
	for _, rr := range candidate.Records {
		before := measured.written
		measured.record(rr)
		actualSize := measured.written - before
		if upper := reefMaxRecordSize(rr); upper < actualSize {
			t.Fatalf("record %s %s upper bound %d < compressed size %d",
				rr.Name, rr.Type, upper, actualSize)
		}
		encoded.record(rr)
		if measured.written != len(encoded.data)-committedLen {
			t.Fatalf("record %s %s measured %d, encoded %d",
				rr.Name, rr.Type, measured.written, len(encoded.data)-committedLen)
		}
	}
	fullLen := len(encoded.data)

	for limit := committedLen; limit <= fullLen; limit++ {
		w := newCommittedWriter()
		got := w.rrsetFits(candidate, limit, 7)
		want := fullLen <= limit
		if got != want {
			t.Fatalf("limit %d: rrsetFits=%t, want %t (full=%d committed=%d)",
				limit, got, want, fullLen, committedLen)
		}
	}

	w := newCommittedWriter()
	if w.rrsetFits(candidate, maxWire, ^uint16(0)) {
		t.Fatal("RRset unexpectedly fit uint16 count overflow")
	}
}

func TestLabelreefRolledBackRRsetCompression(t *testing.T) {
	tooBig := labelreefSharedSuffixRRset(256)
	glue := zone.NewRRset([]zone.Record{{
		// This exact name also appears in the omitted MX RRset. After the
		// failed budget decision it must be encoded as a new in-message name,
		// not as a pointer into the omitted attempt.
		Name: "mx-0000.pool.shared-suffix.lab.test.",
		Type: zone.A,
		TTL:  60,
		Data: zone.RData{Addr: netip.MustParseAddr("192.0.2.7")},
	}})

	for _, edns := range []uint16{0, 1232} {
		q := labelreefBudgetQuery(edns)
		w := newWriter(q.budget(false, 1232))
		h := q.responseHeader(lookup.Success)
		q.addQuestion(w, &h)
		limit := q.budget(false, 1232)
		if q.opt != nil {
			limit -= optSize
		}

		if !writeSets(w, []zone.RRset{tooBig, glue}, limit, &h.additional, false) {
			t.Fatal("optional section budget check stopped instead of continuing")
		}
		q.addOPT(w, &h, 1232, lookup.Success)
		packet := w.finish(h)

		budget := plainUDP
		if edns != 0 {
			budget = 1232
		}
		decoded := labelreefDecodeBudgetPacket(t, packet, q, budget)
		if len(decoded.Additional) != 1 {
			t.Fatalf("post-rollback RRset was not encoded: %+v", decoded.Additional)
		}
		if got := decoded.Additional[0].Name; got != "mx-0000.pool.shared-suffix.lab.test." {
			t.Fatalf("compression after rollback decoded %q", got)
		}
	}
}

func BenchmarkLabelreefLargeRRsetBudget(b *testing.B) {
	big := labelreefSharedSuffixRRset(256)
	reply := lookup.Answer{
		Code:          lookup.Success,
		Authoritative: true,
		Answer:        []zone.RRset{big},
	}

	for _, tc := range []struct {
		name string
		edns uint16
	}{
		{name: "plain", edns: 0},
		{name: "edns1232", edns: 1232},
	} {
		b.Run(tc.name, func(b *testing.B) {
			q := labelreefBudgetQuery(tc.edns)
			packet := encodeAnswer(q, reply, false, 1232)
			h, err := readHeader(packet)
			if err != nil || h.answers != 0 || h.flags&flagTC == 0 {
				b.Fatalf("unexpected budget packet: %+v %v", h, err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				packet = encodeAnswer(q, reply, false, 1232)
			}
			b.StopTimer()
			if len(packet) == 0 {
				b.Fatal("empty packet")
			}
		})
	}
}
