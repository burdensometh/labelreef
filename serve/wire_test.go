package serve

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"labelreef/lookup"
	"labelreef/serial"
	"labelreef/transfer"
	"labelreef/zone"
)

type fixtureResolver struct {
	version *zone.ZoneVersion
}

func (f fixtureResolver) Resolve(q lookup.Question) lookup.Answer {
	return lookup.Resolve(f.version, q)
}

func (f fixtureResolver) Transfer(req transfer.Request) (*transfer.Plan, error) {
	return transfer.Build(serial.Seed(f.version), req)
}

func exampleZone(t testing.TB) *zone.ZoneVersion {
	t.Helper()
	f, err := os.Open("../examples/zones/lab-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := zone.DecodeV1(f)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func testServer(t *testing.T, resolver Resolver, hook func(FramePoint) error) *Server {
	t.Helper()
	s, err := Listen(resolver, Options{
		Address: netip.MustParseAddrPort("127.0.0.1:0"), MaxUDP: 1232, FrameRecords: 3,
		IOTimeout: 2 * time.Second, BeforeTransferFrame: hook,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestWireGolden(t *testing.T) {
	readHex := func(path string) []byte {
		b, err := os.ReadFile("testdata/" + path + ".hex")
		if err != nil {
			t.Fatal(err)
		}
		wire, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	s := &Server{service: fixtureResolver{exampleZone(t)}, opts: Options{MaxUDP: 1232}}
	q, code, ok := parseQuery(readHex("www-query"))
	if !ok || code != lookup.Success {
		t.Fatalf("rejecting legal golden query: %s", code)
	}
	if reply, expected := s.answer(q, false), readHex("www-answer"); !bytes.Equal(reply, expected) {
		t.Fatalf("golden wire mismatch:\n got %x\nwant %x", reply, expected)
	}
}

type goldenCase struct {
	Case       string   `json:"case"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Code       string   `json:"code"`
	AA         bool     `json:"aa"`
	Answer     []string `json:"answer"`
	Authority  []string `json:"authority"`
	Additional []string `json:"additional"`
}

func rows(records []zone.RecordV1) []string {
	s := make([]string, 0, len(records))
	for _, r := range records {
		s = append(s, fmt.Sprintf("%s|%s|%d|%s", r.Name, r.Type, r.TTL, r.Data))
	}
	return s
}

func TestGoldenQueriesOnUDPAndTCP(t *testing.T) {
	data, err := os.ReadFile("testdata/lookup-golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected []goldenCase
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	s := testServer(t, fixtureResolver{exampleZone(t)}, nil)
	for _, tc := range expected {
		t.Run(tc.Case, func(t *testing.T) {
			typ, err := zone.ParseType(tc.Type)
			if err != nil {
				t.Fatal(err)
			}
			for _, tcp := range []bool{false, true} {
				got, err := Probe(context.Background(), tc.Name, typ, ProbeOptions{
					Address: s.Address(), TCP: tcp, Timeout: 2 * time.Second,
				})
				if err != nil {
					t.Fatal(err)
				}
				actual := goldenCase{Case: tc.Case, Name: got.Name, Type: got.Type, Code: got.Code,
					AA: got.Authoritative, Answer: rows(got.Answer),
					Authority: rows(got.Authority), Additional: rows(got.Additional)}
				if !reflect.DeepEqual(actual, tc) || got.Truncated {
					t.Errorf("tcp=%t: got %+v, want %+v", tcp, actual, tc)
				}
			}
		})
	}
}

func TestUDPBudgetEDNSAndTCPFallback(t *testing.T) {
	s := testServer(t, fixtureResolver{exampleZone(t)}, nil)
	opts := ProbeOptions{Address: s.Address(), Timeout: 2 * time.Second}
	q := "bulletin.lab.test."
	plain, err := Probe(context.Background(), q, zone.TXT, opts)
	if err != nil || !plain.Truncated || len(plain.Answer) != 0 || plain.Bytes > 512 {
		t.Fatalf("plain UDP split its RRset: %+v %v", plain, err)
	}
	opts.RetryTCP = true
	fallback, err := Probe(context.Background(), q, zone.TXT, opts)
	if err != nil || fallback.Truncated || !fallback.RetriedTCP || fallback.Transport != "tcp" || len(fallback.Answer) != 6 {
		t.Fatalf("TCP fallback did not deliver RRset: %+v %v", fallback, err)
	}
	opts.EDNSSize = 4096
	full, err := Probe(context.Background(), q, zone.TXT, opts)
	if err != nil || full.Truncated || full.RetriedTCP || full.Transport != "udp" ||
		full.AdvertisedUDP != 1232 || len(full.Answer) != 6 || full.Bytes > 1232 {
		t.Fatalf("EDNS budget mismatch: %+v %v", full, err)
	}
	if !reflect.DeepEqual(full.Answer, fallback.Answer) {
		t.Fatal("EDNS UDP and full TCP returned different data")
	}
}

func TestQuestionErrorsAndEDNSVersion(t *testing.T) {
	q := lookup.Question{Name: "www.lab.test.", Type: zone.A, Class: zone.ClassIN}
	makePacket := func(flags, questions uint16, raw []byte) []byte {
		w := newWriter(512)
		if raw == nil {
			w.question(q, "")
		} else {
			w.data = append(w.data, raw...)
		}
		return w.finish(header{id: 131, flags: flags, questions: questions})
	}
	for _, tc := range []struct {
		packet []byte
		code   lookup.Code
		send   bool
	}{
		{makePacket(flagResponse, 1, nil), lookup.Format, false},
		{makePacket(0x0800, 1, nil), lookup.NotImpl, true},
		{makePacket(0, 2, nil), lookup.Format, true},
		{makePacket(0, 1, []byte{0xc0, 12, 0, 1, 0, 1}), lookup.Format, true},
		{makePacket(0, 1, []byte{3, 'w'}), lookup.Format, true},
		{makePacket(0, 1, nil), lookup.Success, true},
	} {
		_, code, send := parseQuery(tc.packet)
		if code != tc.code || send != tc.send {
			t.Errorf("packet %x: %s %t, want %s %t", tc.packet, code, send, tc.code, tc.send)
		}
	}
	e := probePacket(131, q, ProbeOptions{EDNSSize: 1232})
	e[len(e)-5] = 1
	request, code, ok := parseQuery(e)
	if !ok || code != lookup.BadVersion {
		t.Fatalf("EDNS version did not produce BADVERS: %s", code)
	}
	reply := encodeAnswer(request, lookup.Answer{Code: code}, false, 1232)
	decoded, err := decodeProbe(reply, 131, q)
	if err != nil || decoded.Code != "BADVERS" {
		t.Fatalf("expected extended RCODE: %+v %v", decoded, err)
	}
}

func BenchmarkRRsetEncoding(b *testing.B) {
	z := exampleZone(b)
	q := query{question: lookup.Question{Name: "bulletin.lab.test.", Type: zone.TXT, Class: zone.ClassIN},
		rawName: "bulletin.lab.test.", opt: &edns{size: 1232}}
	response := lookup.Resolve(z, q.question)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		packet := encodeAnswer(q, response, false, 1232)
		h, err := readHeader(packet)
		if err != nil || h.answers != 6 || h.flags&flagTC != 0 {
			b.Fatal("invalid RRset encoding")
		}
	}
}
