package serial

import (
	"fmt"
	"io"

	"labelreef/zone"
)

type EditV1 struct {
	Version int             `json:"version"`
	Origin  string          `json:"origin"`
	Base    uint32          `json:"base"`
	Next    uint32          `json:"next"`
	Remove  []zone.RecordV1 `json:"remove"`
	Add     []zone.RecordV1 `json:"add"`
	// Preconditions is optional. Its presence switches the edit into RRset
	// precondition mode, where base no longer has to equal the active serial.
	// A non-nil empty slice is a valid mode that only checks serial ordering.
	Preconditions []RRsetPreconditionV1 `json:"preconditions,omitempty"`
}

// guarded reports whether the edit carries explicit RRset preconditions.
// A nil slice keeps the legacy exact-base-serial behavior; an allocated
// empty slice selects precondition mode with no RRset requirements.
func (e EditV1) guarded() bool { return e.Preconditions != nil }

func DecodeEdit(r io.Reader) (EditV1, error) {
	var fields struct {
		Version       int                   `json:"version"`
		Origin        string                `json:"origin"`
		Base          *uint32               `json:"base"`
		Next          *uint32               `json:"next"`
		Remove        []zone.RecordV1       `json:"remove"`
		Add           []zone.RecordV1       `json:"add"`
		Preconditions []RRsetPreconditionV1 `json:"preconditions"`
	}
	if err := zone.DecodeJSON(r, zone.MaxV1Bytes, &fields); err != nil {
		return EditV1{}, err
	}
	if fields.Version != 1 {
		return EditV1{}, fmt.Errorf("unsupported edit file version %d", fields.Version)
	}
	if fields.Base == nil || fields.Next == nil {
		return EditV1{}, fmt.Errorf("edit requires explicit base and next serials")
	}
	return EditV1{
		Version: fields.Version, Origin: fields.Origin, Base: *fields.Base, Next: *fields.Next,
		Remove: fields.Remove, Add: fields.Add, Preconditions: fields.Preconditions,
	}, nil
}

func (e EditV1) Apply(current *zone.ZoneVersion) (*zone.ZoneVersion, error) {
	if e.Version != 1 {
		return nil, fmt.Errorf("unsupported edit file version %d", e.Version)
	}
	origin, err := zone.Name(e.Origin)
	if err != nil || origin != current.Origin() {
		return nil, fmt.Errorf("edit base %q serial %d differs from active %s serial %d",
			e.Origin, e.Base, current.Origin(), current.Serial())
	}
	if e.guarded() {
		// Precondition edits may land on a zone that advanced through other
		// changes, so the base only needs to remain in the active history.
		switch Compare(current.Serial(), e.Base) {
		case Older, Undefined:
			return nil, fmt.Errorf("edit base serial %d is ahead of active serial %d", e.Base, current.Serial())
		}
		conditions, err := parsePreconditions(origin, e.Preconditions)
		if err != nil {
			return nil, err
		}
		if err := checkPreconditions(current, conditions); err != nil {
			return nil, err
		}
		if Compare(e.Next, current.Serial()) != Newer {
			return nil, fmt.Errorf("edit next serial %d must be newer than active serial %d",
				e.Next, current.Serial())
		}
	} else if e.Base != current.Serial() {
		return nil, fmt.Errorf("edit base %q serial %d differs from active %s serial %d",
			e.Origin, e.Base, current.Origin(), current.Serial())
	}
	deletes, err := parseEditRows(origin, e.Remove)
	if err != nil {
		return nil, err
	}
	adds, err := parseEditRows(origin, e.Add)
	if err != nil {
		return nil, err
	}
	soa := current.SOA()
	d := JournalDelta{Before: soa, After: soa.WithSerial(e.Next), Deletes: deletes, Adds: adds}
	r := NewReplay(current)
	if err := r.Apply(d); err != nil {
		return nil, err
	}
	return r.Zone()
}

func parseEditRows(origin string, rows []zone.RecordV1) ([]zone.Record, error) {
	records := make([]zone.Record, 0, len(rows))
	for i, row := range rows {
		record, err := row.Record(origin)
		if err != nil {
			return nil, fmt.Errorf("edit record %d: %w", i+1, err)
		}
		if record.Type == zone.SOA {
			return nil, fmt.Errorf("SOA record is managed by edit serial")
		}
		records = append(records, record)
	}
	sortRecords(records)
	return records, nil
}
