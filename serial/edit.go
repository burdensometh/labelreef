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
}

func DecodeEdit(r io.Reader) (EditV1, error) {
	var fields struct {
		Version int             `json:"version"`
		Origin  string          `json:"origin"`
		Base    *uint32         `json:"base"`
		Next    *uint32         `json:"next"`
		Remove  []zone.RecordV1 `json:"remove"`
		Add     []zone.RecordV1 `json:"add"`
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
		Remove: fields.Remove, Add: fields.Add,
	}, nil
}

func (e EditV1) Apply(current *zone.ZoneVersion) (*zone.ZoneVersion, error) {
	if e.Version != 1 {
		return nil, fmt.Errorf("unsupported edit file version %d", e.Version)
	}
	origin, err := zone.Name(e.Origin)
	if err != nil || origin != current.Origin() || e.Base != current.Serial() {
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
