package transfer

import (
	"fmt"

	"labelreef/serial"
	"labelreef/zone"
)

type Kind string

const (
	Full        Kind = "axfr"
	Incremental Kind = "ixfr"
	Unchanged   Kind = "unchanged"
	Fallback    Kind = "axfr-fallback"
)

type Request struct {
	Origin    string
	Type      zone.Type
	HasSerial bool
	Serial    uint32
}

type Plan struct {
	kind    Kind
	serial  uint32
	records []zone.Record

	// full serves AXFR and IXFR-fallback windows directly from one pinned,
	// immutable zone generation instead of copying the entire zone into
	// records before the first frame. It is nil for eager IXFR plans.
	stream *fullSequence
}

// fullSequence is the canonical AXFR RR order over a pinned ZoneVersion:
//
//	head SOA, every sorted non-SOA RR, tail SOA (identical to the head).
//
// The sequence has RecordCount()+1 logical records because the zone's own
// sorted slice already contains the SOA once and that physical SOA position
// is skipped between the two emitted bookends.
type fullSequence struct {
	zone     *zone.ZoneVersion
	soa      zone.Record
	soaIndex int
	size     int // logical length: zone.RecordCount()+1
}

func newFullSequence(z *zone.ZoneVersion) *fullSequence {
	return &fullSequence{
		zone:     z,
		soa:      z.SOA(),
		soaIndex: z.SOAIndex(),
		size:     z.RecordCount() + 1,
	}
}

// at maps a logical AXFR position onto the pinned zone.
//
//	logical 0        -> head SOA
//	logical 1..s     -> physical 0..s-1 (records sorting before the SOA)
//	logical s+1..N-1 -> physical s+1..N-1 (records after the SOA)
//	logical N        -> tail SOA
//
// where s is the physical SOA index and N is the physical record count.
func (f *fullSequence) at(logical int) zone.Record {
	n := f.zone.RecordCount()
	switch {
	case logical == 0 || logical == n:
		return f.soa
	case logical <= f.soaIndex:
		return f.zone.RecordAt(logical - 1)
	default:
		return f.zone.RecordAt(logical)
	}
}

// window returns an owned copy of count logical records starting at start.
// The copy is bounded by the offered frame size, never the whole zone.
func (f *fullSequence) window(start, count int) []zone.Record {
	records := make([]zone.Record, count)
	for i := range records {
		records[i] = f.at(start + i)
	}
	return records
}

func Build(snapshot *serial.Snapshot, request Request) (*Plan, error) {
	current := snapshot.Current()
	if current == nil || current.Origin() != request.Origin {
		return nil, fmt.Errorf("no transfer source for %s", request.Origin)
	}
	plan := &Plan{serial: current.Serial()}
	switch request.Type {
	case zone.AXFR:
		plan.full(current, Full)
	case zone.IXFR:
		if !request.HasSerial {
			return nil, fmt.Errorf("IXFR requires a request SOA")
		}
		switch serial.Compare(current.Serial(), request.Serial) {
		case serial.Equal, serial.Older:
			plan.kind = Unchanged
			plan.records = []zone.Record{current.SOA()}
		case serial.Undefined:
			return nil, fmt.Errorf("IXFR serial distance is undefined")
		case serial.Newer:
			history, available := snapshot.History(request.Serial)
			if !available {
				plan.full(current, Fallback)
			} else {
				plan.incremental(current, history)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported transfer type %s", request.Type)
	}
	return plan, nil
}

// full pins the current generation but deliberately does not duplicate its
// record slice up front; Cursor windows read through full.
func (p *Plan) full(z *zone.ZoneVersion, kind Kind) {
	p.kind = kind
	p.stream = newFullSequence(z)
}

func (p *Plan) incremental(z *zone.ZoneVersion, history []serial.JournalDelta) {
	p.kind = Incremental
	p.records = append(p.records, z.SOA())
	for _, delta := range history {
		p.records = append(p.records, delta.Before)
		p.records = append(p.records, delta.Deletes...)
		p.records = append(p.records, delta.After)
		p.records = append(p.records, delta.Adds...)
	}
	p.records = append(p.records, z.SOA())
}

func (p *Plan) Kind() Kind { return p.kind }

func (p *Plan) Serial() uint32 { return p.serial }

func (p *Plan) Count() int {
	if p.stream != nil {
		return p.stream.size
	}
	return len(p.records)
}

type Position struct {
	NextRecord int
	Frames     int
}

type TransferCursor struct {
	plan     *Plan
	position Position
	offered  int
}

func (p *Plan) Cursor() *TransferCursor {
	return &TransferCursor{plan: p}
}

func (c *TransferCursor) Position() Position { return c.position }

func (c *TransferCursor) Done() bool { return c.position.NextRecord == c.plan.Count() }

// Offer can be retried without changing the committed position. The returned
// slice is owned by the caller and stays stable until the next Offer.
func (c *TransferCursor) Offer(maxRecords int) []zone.Record {
	c.offered = 0
	total := c.plan.Count()
	if maxRecords <= 0 || c.Done() {
		return nil
	}
	start := c.position.NextRecord
	count := min(maxRecords, total-start)
	c.offered = count
	if c.plan.stream != nil {
		return c.plan.stream.window(start, count)
	}
	return append([]zone.Record(nil), c.plan.records[start:start+count]...)
}

// Commit records only frames whose complete length prefix and payload were written.
func (c *TransferCursor) Commit(written int) error {
	if written <= 0 || written > c.offered {
		return fmt.Errorf("cannot commit %d transfer records with %d offered", written, c.offered)
	}
	c.position.NextRecord += written
	c.position.Frames++
	c.offered = 0
	return nil
}
