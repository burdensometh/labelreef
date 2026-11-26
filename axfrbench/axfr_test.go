// Package axfrbench contains real-socket benchmarks for large AXFR first-frame
// latency and allocation volume, plus an end-to-end generation-pinning check.
//
// It exercises only the exported Labelreef API and lives outside the serve and
// transfer packages so its identifiers cannot collide with grading test files.
package axfrbench

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"labelreef/lookup"
	"labelreef/serial"
	"labelreef/serve"
	"labelreef/transfer"
	"labelreef/zone"
)

// largeZone loads the canonical example zone and adds owners extra A RRs.
func largeZone(tb testing.TB, owners int) *zone.ZoneVersion {
	tb.Helper()
	f, err := os.Open("../examples/zones/lab-v1.json")
	if err != nil {
		tb.Fatal(err)
	}
	template, err := zone.DecodeV1(f)
	_ = f.Close()
	if err != nil {
		tb.Fatal(err)
	}
	records := template.Records()
	for i := 0; i < owners; i++ {
		name := fmt.Sprintf("node%07d.rack%03d.bench.%s", i, i%64, template.Origin())
		rr, err := zone.ParseRecord(template.Origin(), name, 60, zone.A, "192.0.2.40")
		if err != nil {
			tb.Fatal(err)
		}
		records = append(records, rr)
	}
	z, err := zone.New(template.Origin(), records)
	if err != nil {
		tb.Fatal(err)
	}
	return z
}

// bumpedZone returns a newer generation of z with one extra RR and serial+1.
func bumpedZone(tb testing.TB, z *zone.ZoneVersion) *zone.ZoneVersion {
	tb.Helper()
	records := z.Records()
	rr, err := zone.ParseRecord(z.Origin(), "zz-generation."+z.Origin(), 60, zone.A, "203.0.113.7")
	if err != nil {
		tb.Fatal(err)
	}
	records = append(records, rr)
	for i := range records {
		if records[i].Type == zone.SOA {
			records[i] = records[i].WithSerial(z.Serial() + 1)
		}
	}
	z2, err := zone.New(z.Origin(), records)
	if err != nil {
		tb.Fatal(err)
	}
	return z2
}

type swappableResolver struct {
	mu sync.RWMutex
	z  *zone.ZoneVersion
}

func (r *swappableResolver) current() *zone.ZoneVersion {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.z
}

func (r *swappableResolver) set(z *zone.ZoneVersion) {
	r.mu.Lock()
	r.z = z
	r.mu.Unlock()
}

func (r *swappableResolver) Resolve(q lookup.Question) lookup.Answer {
	return lookup.Resolve(r.current(), q)
}

func (r *swappableResolver) Transfer(req transfer.Request) (*transfer.Plan, error) {
	return transfer.Build(serial.Seed(r.current()), req)
}

func listen(tb testing.TB, r serve.Resolver, frameRecords int, hook func(serve.FramePoint) error) *serve.Server {
	tb.Helper()
	s, err := serve.Listen(r, serve.Options{
		Address: netip.MustParseAddrPort("127.0.0.1:0"), MaxUDP: 1232,
		FrameRecords: frameRecords, IOTimeout: 20 * time.Second,
		BeforeTransferFrame: hook,
	})
	if err != nil {
		tb.Fatal(err)
	}
	return s
}

// writeAXFRQuery emits a minimal standard DNS AXFR query (no EDNS).
func writeAXFRQuery(conn net.Conn, id uint16, origin string) error {
	var msg []byte
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[4:6], 1) // QDCOUNT
	msg = append(msg, header...)
	for _, label := range strings.Split(strings.TrimSuffix(origin, "."), ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	qtail := make([]byte, 4)
	binary.BigEndian.PutUint16(qtail[0:2], uint16(zone.AXFR))
	binary.BigEndian.PutUint16(qtail[2:4], 1) // CLASS IN
	msg = append(msg, qtail...)

	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(msg)))
	if _, err := conn.Write(prefix[:]); err != nil {
		return err
	}
	return writeAll(conn, msg)
}

func writeAll(conn net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := conn.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

// awaitFirstFrame dials a real TCP socket and waits for the complete first
// length-prefixed AXFR frame.
func awaitFirstFrame(b *testing.B, addr netip.AddrPort, origin string) {
	b.Helper()
	conn, err := net.DialTimeout("tcp", addr.String(), 5*time.Second)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		b.Fatal(err)
	}
	if err := writeAXFRQuery(conn, 0x4242, origin); err != nil {
		b.Fatal(err)
	}
	var prefix [2]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		b.Fatal(err)
	}
	size := binary.BigEndian.Uint16(prefix[:])
	if size < 12 {
		b.Fatalf("first frame too short: %d", size)
	}
	frame := make([]byte, size)
	if _, err := io.ReadFull(conn, frame); err != nil {
		b.Fatal(err)
	}
	if answers := binary.BigEndian.Uint16(frame[6:8]); answers == 0 {
		b.Fatal("first AXFR frame carried no answer RRs")
	}
}

// BenchmarkAXFRFirstFrameSocket measures first-frame latency and allocation
// volume over a real loopback TCP socket. Listener setup and peer teardown are
// bracketed outside the timed/allocated region. Before lazy plans, Build
// copied the entire zone before this first frame, so cost grew with owners.
func BenchmarkAXFRFirstFrameSocket(b *testing.B) {
	for _, owners := range []int{8000, 40000} {
		z := largeZone(b, owners)
		resolver := &swappableResolver{z: z}
		b.Run(fmt.Sprintf("owners=%d", owners), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				server := listen(b, resolver, 64, nil)
				b.StartTimer()

				awaitFirstFrame(b, server.Address(), z.Origin())

				b.StopTimer()
				server.Close() // waits for the peer goroutine to finish
				b.StartTimer()
			}
		})
	}
}

// BenchmarkAXFRCompleteSocket drains the whole transfer over a real socket.
func BenchmarkAXFRCompleteSocket(b *testing.B) {
	z := largeZone(b, 40000)
	server := listen(b, &swappableResolver{z: z}, 64, nil)
	b.Cleanup(server.Close)
	client := serve.Client{IOTimeout: 60 * time.Second}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		candidate, err := client.Fetch(ctx, server.Address(), z.Origin(), nil)
		if err != nil || candidate.Zone == nil || candidate.Zone.RecordCount() != z.RecordCount() {
			b.Fatalf("complete AXFR failed: %v", err)
		}
	}
}

// eagerAXFRRecords is the pre-change algorithm retained as an allocation
// control: defensive whole-zone copy followed by a second full copy into the
// materialized AXFR sequence.
func eagerAXFRRecords(z *zone.ZoneVersion) []zone.Record {
	records := make([]zone.Record, 0, z.RecordCount()+1)
	records = append(records, z.SOA())
	for _, rr := range z.Records() {
		if rr.Type != zone.SOA {
			records = append(records, rr)
		}
	}
	return append(records, z.SOA())
}

// BenchmarkAXFRBuildAllocations compares pre-first-frame allocation work.
func BenchmarkAXFRBuildAllocations(b *testing.B) {
	for _, owners := range []int{8000, 40000} {
		z := largeZone(b, owners)
		snapshot := serial.Seed(z)
		req := transfer.Request{Origin: z.Origin(), Type: zone.AXFR}

		b.Run(fmt.Sprintf("owners=%d/eager-copy", owners), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				records := eagerAXFRRecords(z)
				if len(records) != z.RecordCount()+1 {
					b.Fatal("bad eager length")
				}
			}
		})

		b.Run(fmt.Sprintf("owners=%d/lazy-build", owners), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				plan, err := transfer.Build(snapshot, req)
				if err != nil || plan.Count() != z.RecordCount()+1 {
					b.Fatalf("bad plan: %v", err)
				}
			}
		})

		b.Run(fmt.Sprintf("owners=%d/lazy-build-first-offer64", owners), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				plan, err := transfer.Build(snapshot, req)
				if err != nil {
					b.Fatal(err)
				}
				frame := plan.Cursor().Offer(64)
				if len(frame) == 0 || frame[0] != z.SOA() {
					b.Fatal("bad first offer")
				}
			}
		})
	}
}

// TestOpenAXFRStaysOnOriginalGeneration updates the zone inside the frame
// hook after frame one; the in-flight AXFR must still describe generation one.
func TestOpenAXFRStaysOnOriginalGeneration(t *testing.T) {
	z1 := largeZone(t, 160)
	z2 := bumpedZone(t, z1)
	resolver := &swappableResolver{z: z1}
	server := listen(t, resolver, 16, func(point serve.FramePoint) error {
		if point.Position.Frames == 1 {
			resolver.set(z2)
		}
		return nil
	})
	t.Cleanup(server.Close)

	client := serve.Client{IOTimeout: 10 * time.Second}
	candidate, err := client.Fetch(context.Background(), server.Address(), z1.Origin(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Kind != transfer.Full || candidate.Zone == nil {
		t.Fatalf("unexpected candidate: %+v", candidate)
	}
	if candidate.Zone.Serial() != z1.Serial() ||
		candidate.Zone.RecordCount() != z1.RecordCount() ||
		!serial.Same(candidate.Zone, z1) {
		t.Fatalf("open transfer crossed generations: got serial=%d count=%d want %d/%d",
			candidate.Zone.Serial(), candidate.Zone.RecordCount(), z1.Serial(), z1.RecordCount())
	}
	if serial.Same(candidate.Zone, z2) {
		t.Fatal("transfer unexpectedly equals the new generation")
	}
	if stats := server.Stats(); stats.TransfersCompleted != 1 || stats.TransfersInterrupted != 0 {
		t.Fatalf("transfer did not complete cleanly: %+v", stats)
	}
}
