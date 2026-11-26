package serial

import (
	"fmt"
	"maps"

	"labelreef/zone"
)

// checkShapes validates the prospective owner summaries before applying
// either direction of a journal step, using the owner and RRset rules shared
// with a full zone load, and reports the summaries to commit on success. The
// replay state is left untouched when this returns an error. A removed cut
// can expose a hidden delegation, so any change in NS coverage revalidates
// every owner whose visibility changed.
func (r *Replay) checkShapes(deletes, adds []zone.Record) (map[string]zone.OwnerShape, error) {
	changes := make(map[string]zone.OwnerShape)
	touch := func(name string) zone.OwnerShape {
		if shape, ok := changes[name]; ok {
			return shape
		}
		shape := maps.Clone(r.shapes[name])
		if shape == nil {
			shape = make(zone.OwnerShape)
		}
		changes[name] = shape
		return shape
	}
	for _, record := range deletes {
		touch(record.Name).Remove(record)
	}
	for _, record := range adds {
		if err := touch(record.Name).Add(record); err != nil {
			return nil, err
		}
	}

	origin := r.current.Name
	at := func(name string) zone.OwnerShape {
		if change, ok := changes[name]; ok {
			return change
		}
		return r.shapes[name]
	}
	if !at(origin).HasNS() {
		return nil, fmt.Errorf("%s: journal step would remove apex NS", origin)
	}
	exposed := func(name string) bool {
		return zone.IsDelegation(name, origin, func(owner string) bool {
			return at(owner).HasNS()
		})
	}

	hasCutChange := false
	for name, shape := range changes {
		if err := shape.Validate(name, exposed(name)); err != nil {
			return nil, err
		}
		wasNS := r.shapes[name].HasNS()
		hasCutChange = hasCutChange || (name != origin && wasNS != shape.HasNS())
	}
	if hasCutChange {
		for name, shape := range r.shapes {
			if _, touched := changes[name]; touched || !shape.HasNS() {
				continue
			}
			if exposed(name) {
				if err := shape.Validate(name, true); err != nil {
					return nil, err
				}
			}
		}
	}
	return changes, nil
}
