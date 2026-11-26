package serial

import (
	"fmt"
	"sort"

	"labelreef/zone"
)

type JournalDelta struct {
	Before  zone.Record
	After   zone.Record
	Deletes []zone.Record
	Adds    []zone.Record
}

func Between(before, after *zone.ZoneVersion) (JournalDelta, error) {
	d := JournalDelta{Before: before.SOA(), After: after.SOA()}
	if err := d.checkSOAs(); err != nil {
		return JournalDelta{}, err
	}
	difference, err := zone.Diff(before, after)
	if err != nil {
		return JournalDelta{}, err
	}
	d.Adds = withoutSOA(difference.Adds)
	d.Deletes = withoutSOA(difference.Removes)
	return d, nil
}

func withoutSOA(records []zone.Record) []zone.Record {
	out := records[:0]
	for _, record := range records {
		if record.Type != zone.SOA {
			out = append(out, record)
		}
	}
	return out
}

func (d JournalDelta) checkSOAs() error {
	if d.Before.Type != zone.SOA || d.After.Type != zone.SOA || d.Before.Name != d.After.Name {
		return fmt.Errorf("delta SOA endpoints disagree")
	}
	if Compare(d.To(), d.From()) != Newer {
		return fmt.Errorf("delta serial %d is not newer than %d", d.To(), d.From())
	}
	return nil
}

func (d JournalDelta) From() uint32 { return d.Before.Data.SOA.Serial }

func (d JournalDelta) To() uint32 { return d.After.Data.SOA.Serial }

func (d JournalDelta) clone() JournalDelta {
	d.Deletes = append([]zone.Record(nil), d.Deletes...)
	d.Adds = append([]zone.Record(nil), d.Adds...)
	return d
}

type Replay struct {
	current zone.Record
	set     map[zone.Record]struct{}
	shapes  map[string]zone.OwnerShape
}

func NewReplay(base *zone.ZoneVersion) *Replay {
	records := base.Records()
	r := &Replay{
		current: base.SOA(), set: make(map[zone.Record]struct{}, len(records)),
		shapes: make(map[string]zone.OwnerShape),
	}
	for _, record := range records {
		if record.Type != zone.SOA {
			r.set[record] = struct{}{}
		}
		shape := r.shapes[record.Name]
		if shape == nil {
			shape = make(zone.OwnerShape)
			r.shapes[record.Name] = shape
		}
		// The base zone passed a full load, so Add cannot fail here.
		_ = shape.Add(record)
	}
	return r
}

func (r *Replay) apply(d JournalDelta, reverse bool) error {
	if err := d.checkSOAs(); err != nil {
		return err
	}
	from, to := d.Before, d.After
	deletes, adds := d.Deletes, d.Adds
	if reverse {
		from, to = to, from
		deletes, adds = adds, deletes
	}
	if r.current != from {
		return fmt.Errorf("delta around serial %d does not match current SOA", from.Data.SOA.Serial)
	}
	if err := to.Validate(); err != nil {
		return err
	}
	removed := make(map[zone.Record]struct{}, len(deletes))
	for _, record := range deletes {
		_, exists := r.set[record]
		_, duplicate := removed[record]
		if !exists || duplicate {
			return fmt.Errorf("delta removes absent or repeated %s %s", record.Name, record.Type)
		}
		removed[record] = struct{}{}
	}
	added := make(map[zone.Record]struct{}, len(adds))
	for _, record := range adds {
		_, exists := r.set[record]
		_, replacing := removed[record]
		_, duplicate := added[record]
		if record.Type == zone.SOA || !zone.Within(record.Name, from.Name) ||
			(exists && !replacing) || duplicate || record.Validate() != nil {
			return fmt.Errorf("delta adds invalid or repeated %s %s", record.Name, record.Type)
		}
		added[record] = struct{}{}
	}
	changes, err := r.checkShapes(deletes, adds)
	if err != nil {
		return err
	}
	for record := range removed {
		delete(r.set, record)
	}
	for record := range added {
		r.set[record] = struct{}{}
	}
	for name, shape := range changes {
		if len(shape) == 0 {
			delete(r.shapes, name)
		} else {
			r.shapes[name] = shape
		}
	}
	r.current = to
	return nil
}

func (r *Replay) Apply(d JournalDelta) error { return r.apply(d, false) }

func (r *Replay) Zone() (*zone.ZoneVersion, error) {
	records := make([]zone.Record, 0, len(r.set)+1)
	records = append(records, r.current)
	for record := range r.set {
		records = append(records, record)
	}
	return zone.New(r.current.Name, records)
}

func Same(left, right *zone.ZoneVersion) bool {
	return left.Equal(right)
}

func sortRecords(records []zone.Record) {
	sort.Slice(records, func(i, j int) bool {
		return zone.Less(records[i], records[j])
	})
}
