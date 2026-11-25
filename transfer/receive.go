package transfer

import (
	"fmt"

	"labelreef/serial"
	"labelreef/zone"
)

const MaxRecords = 500000

type Candidate struct {
	Kind   Kind
	Zone   *zone.ZoneVersion
	Deltas []serial.JournalDelta
}

type phase uint8

const (
	initial phase = iota
	selectMode
	fullBody
	deleteBody
	addBody
	complete
	failed
)

// Receiver consumes RRs in wire order. The parsed zone can be obtained only
// after a terminating SOA, except for a valid single-SOA no-change IXFR.
type Receiver struct {
	request Request
	base    *zone.ZoneVersion
	state   phase
	target  zone.Record
	seen    int
	full    []zone.Record
	delta   serial.JournalDelta
	replay  *serial.Replay
	result  Candidate
}

func NewReceiver(request Request, base *zone.ZoneVersion) (*Receiver, error) {
	if request.Type != zone.AXFR && request.Type != zone.IXFR {
		return nil, fmt.Errorf("not a transfer request")
	}
	if request.Type == zone.IXFR && (!request.HasSerial || base == nil ||
		base.Serial() != request.Serial || base.Origin() != request.Origin) {
		return nil, fmt.Errorf("IXFR receiving base does not match request")
	}
	return &Receiver{request: request, base: base}, nil
}

func (r *Receiver) Feed(records []zone.Record) error {
	if r.state == failed || r.state == complete {
		return fmt.Errorf("transfer receiver already closed")
	}
	if len(records) == 0 || len(records) > MaxRecords-r.seen {
		r.state = failed
		return fmt.Errorf("empty frame or transfer record limit exceeded")
	}
	if r.state == initial && len(records) == 1 && r.request.Type == zone.IXFR &&
		records[0].Type == zone.SOA && records[0].Name == r.request.Origin &&
		serial.Compare(records[0].Data.SOA.Serial, r.base.Serial()) != serial.Newer {
		if records[0] != r.base.SOA() {
			r.state = failed
			return fmt.Errorf("IXFR no-change SOA does not match active serial and data")
		}
		r.result = Candidate{Kind: Unchanged, Zone: r.base}
		r.state = complete
		return nil
	}
	for _, record := range records {
		r.seen++
		if err := r.feedRecord(record); err != nil {
			r.state = failed
			return fmt.Errorf("transfer record %d: %w", r.seen, err)
		}
	}
	return nil
}

func (r *Receiver) feedRecord(record zone.Record) error {
	if !zone.Within(record.Name, r.request.Origin) ||
		(record.Type == zone.SOA && record.Name != r.request.Origin) {
		return fmt.Errorf("record %s %s is outside transfer scope", record.Name, record.Type)
	}
	switch r.state {
	case initial:
		return r.open(record)
	case selectMode:
		return r.selectBody(record)
	case fullBody:
		return r.fullRecord(record)
	case deleteBody:
		if record.Type == zone.SOA {
			r.delta.After = record
			r.state = addBody
		} else {
			r.delta.Deletes = append(r.delta.Deletes, record)
		}
	case addBody:
		if record.Type != zone.SOA {
			r.delta.Adds = append(r.delta.Adds, record)
			return nil
		}
		return r.closeDelta(record)
	case complete:
		return fmt.Errorf("record follows terminal SOA")
	default:
		return fmt.Errorf("invalid receiver state")
	}
	return nil
}

func (r *Receiver) open(record zone.Record) error {
	if record.Type != zone.SOA {
		return fmt.Errorf("transfer does not open with apex SOA")
	}
	if r.base != nil {
		order := serial.Compare(record.Data.SOA.Serial, r.base.Serial())
		if order != serial.Equal && order != serial.Newer {
			return fmt.Errorf("source SOA %d cannot replace %d", record.Data.SOA.Serial, r.base.Serial())
		}
	}
	r.target = record
	if r.request.Type == zone.IXFR {
		r.state = selectMode
	} else {
		r.state = fullBody
		r.full = []zone.Record{record}
	}
	return nil
}

func (r *Receiver) selectBody(record zone.Record) error {
	if record.Type == zone.SOA && record != r.target {
		if record != r.base.SOA() {
			return fmt.Errorf("IXFR first old SOA differs from receiving base")
		}
		r.replay = serial.NewReplay(r.base)
		r.delta.Before = record
		r.state = deleteBody
		return nil
	}
	r.state = fullBody
	r.full = []zone.Record{r.target}
	return r.fullRecord(record)
}

func (r *Receiver) fullRecord(record zone.Record) error {
	if record.Type != zone.SOA {
		r.full = append(r.full, record)
		return nil
	}
	if record != r.target {
		return fmt.Errorf("AXFR closing SOA differs from opener")
	}
	z, err := zone.New(r.request.Origin, r.full)
	if err != nil {
		return fmt.Errorf("AXFR zone: %w", err)
	}
	if r.base != nil && z.Serial() == r.base.Serial() && !serial.Same(r.base, z) {
		return fmt.Errorf("AXFR conflicts with active data at serial %d", z.Serial())
	}
	r.result = Candidate{Kind: Full, Zone: z}
	if r.request.Type == zone.IXFR {
		r.result.Kind = Fallback
	}
	r.state = complete
	return nil
}

func (r *Receiver) closeDelta(next zone.Record) error {
	delta := r.delta
	if delta.After != r.target && serial.Compare(r.target.Data.SOA.Serial, delta.To()) != serial.Newer {
		return fmt.Errorf("IXFR delta does not progress toward target")
	}
	if err := r.replay.Apply(delta); err != nil {
		return err
	}
	r.result.Deltas = append(r.result.Deltas, delta)
	if delta.After == r.target {
		if next != r.target {
			return fmt.Errorf("IXFR closing SOA differs from opener")
		}
		z, err := r.replay.Zone()
		if err != nil {
			return fmt.Errorf("IXFR zone: %w", err)
		}
		r.result.Kind, r.result.Zone = Incremental, z
		r.state = complete
		return nil
	}
	if next != delta.After {
		return fmt.Errorf("IXFR deltas are not contiguous")
	}
	r.delta = serial.JournalDelta{Before: next}
	r.state = deleteBody
	return nil
}

func (r *Receiver) Done() bool { return r.state == complete }

func (r *Receiver) Finish() (Candidate, error) {
	if !r.Done() {
		return Candidate{}, fmt.Errorf("transfer ended before completion after %d records", r.seen)
	}
	return r.result, nil
}
