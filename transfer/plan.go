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

func (p *Plan) full(z *zone.ZoneVersion, kind Kind) {
	p.kind = kind
	p.records = make([]zone.Record, 0, z.RecordCount()+1)
	p.records = append(p.records, z.SOA())
	for _, record := range z.Records() {
		if record.Type != zone.SOA {
			p.records = append(p.records, record)
		}
	}
	p.records = append(p.records, z.SOA())
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

func (p *Plan) Count() int { return len(p.records) }

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

// Offer can be retried without changing the committed position.
func (c *TransferCursor) Offer(maxRecords int) []zone.Record {
	c.offered = 0
	if maxRecords <= 0 || c.Done() {
		return nil
	}
	start := c.position.NextRecord
	count := min(maxRecords, len(c.plan.records)-start)
	c.offered = count
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
