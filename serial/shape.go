package serial

import (
	"fmt"
	"maps"

	"labelreef/zone"
)

type rrsetShape struct {
	count int
	ttl   uint32
}

type ownerShape map[zone.Type]rrsetShape

func (s ownerShape) add(record zone.Record) error {
	set := s[record.Type]
	if set.count > 0 && set.ttl != record.TTL {
		return fmt.Errorf("%s %s: mixed RRset TTLs", record.Name, record.Type)
	}
	set.count++
	set.ttl = record.TTL
	s[record.Type] = set
	return nil
}

func (s ownerShape) remove(record zone.Record) {
	set := s[record.Type]
	set.count--
	if set.count == 0 {
		delete(s, record.Type)
	} else {
		s[record.Type] = set
	}
}

// checkShapes validates the prospective owner maps before applying either
// direction of a journal step. A removed cut can expose another delegation.
func (r *Replay) checkShapes(deletes, adds []zone.Record) (map[string]ownerShape, error) {
	changes := make(map[string]ownerShape)
	touch := func(name string) ownerShape {
		if shape, ok := changes[name]; ok {
			return shape
		}
		shape := maps.Clone(r.shapes[name])
		if shape == nil {
			shape = make(ownerShape)
		}
		changes[name] = shape
		return shape
	}
	for _, record := range deletes {
		touch(record.Name).remove(record)
	}
	for _, record := range adds {
		if err := touch(record.Name).add(record); err != nil {
			return nil, err
		}
	}

	origin := r.current.Name
	at := func(name string) ownerShape {
		if change, ok := changes[name]; ok {
			return change
		}
		return r.shapes[name]
	}
	if at(origin)[zone.NS].count == 0 {
		return nil, fmt.Errorf("%s: journal step would remove apex NS", origin)
	}

	hasCutChange := false
	for name, shape := range changes {
		delegation := isDelegation(name, origin, at)
		if err := shape.validate(name, delegation); err != nil {
			return nil, err
		}
		wasNS := r.shapes[name][zone.NS].count != 0
		isNS := shape[zone.NS].count != 0
		hasCutChange = hasCutChange || (name != origin && wasNS != isNS)
	}
	if hasCutChange {
		for name, shape := range r.shapes {
			if _, touched := changes[name]; touched || shape[zone.NS].count == 0 {
				continue
			}
			if isDelegation(name, origin, at) {
				if err := shape.validate(name, true); err != nil {
					return nil, err
				}
			}
		}
	}
	return changes, nil
}

func isDelegation(name, origin string, at func(string) ownerShape) bool {
	if name == origin || at(name)[zone.NS].count == 0 {
		return false
	}
	for ancestor := zone.Parent(name); ancestor != origin; ancestor = zone.Parent(ancestor) {
		if ancestor == zone.Root || at(ancestor)[zone.NS].count > 0 {
			return false
		}
	}
	return true
}

func (s ownerShape) validate(name string, delegation bool) error {
	if !delegation && s[zone.CNAME].count == 0 {
		return nil
	}
	types := make(map[zone.Type]int, len(s))
	for typ, set := range s {
		types[typ] = set.count
	}
	return zone.ValidateOwner(name, types, delegation)
}
