package reload

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sort"

	"labelreef/serial"
	"labelreef/zone"
)

type entry struct {
	specification
	snapshot *serial.Snapshot
	store    serial.Store
}

type table struct {
	epoch   uint64
	entries map[string]*entry
}

type ZoneStatus struct {
	Origin     string  `json:"origin"`
	Role       Role    `json:"role"`
	Source     string  `json:"source,omitempty"`
	Active     bool    `json:"active"`
	Serial     *uint32 `json:"serial,omitempty"`
	Generation uint64  `json:"generation"`
	Retained   int     `json:"retained"`
	Records    int     `json:"records"`
	Nodes      int     `json:"nodes"`
}

type Status struct {
	Epoch uint64       `json:"epoch"`
	Zones []ZoneStatus `json:"zones"`
}

func statePath(dir, origin string) string {
	digest := sha256.Sum256([]byte(origin))
	return filepath.Join(dir, fmt.Sprintf("%x.json", digest))
}

// Route selects the active zone for a name using the longest active suffix.
// A DS question at an exact delegation name stays with the parent so it can
// answer authoritatively; every other question at or below a locally hosted
// child zone is answered by that child. The same table instance serves every
// hop of one lookup, so a resolution never mixes routing generations.
func (t *table) Route(name string, typ zone.Type) *zone.ZoneVersion {
	var closest *zone.ZoneVersion
	for current := name; ; current = zone.Parent(current) {
		if e := t.entries[current]; e != nil {
			if z := e.snapshot.Current(); z != nil {
				if closest == nil {
					closest = z
					if typ != zone.DS || current != name {
						return closest
					}
				} else if match := z.Find(name); match.Kind == zone.Cut && match.Cut == name {
					return z
				} else {
					return closest
				}
			}
		}
		if current == zone.Root {
			return closest
		}
	}
}

func (t *table) status() Status {
	result := Status{Epoch: t.epoch, Zones: make([]ZoneStatus, 0, len(t.entries))}
	for _, e := range t.entries {
		view := ZoneStatus{Origin: e.origin, Role: e.role}
		if e.source.IsValid() {
			view.Source = e.source.String()
		}
		if z := e.snapshot.Current(); z != nil {
			serial := z.Serial()
			view.Serial = &serial
			view.Active = true
			view.Generation = e.snapshot.Generation()
			view.Retained = e.snapshot.Retained()
			view.Records = z.RecordCount()
			view.Nodes = z.NodeCount()
		}
		result.Zones = append(result.Zones, view)
	}
	sort.Slice(result.Zones, func(i, j int) bool { return result.Zones[i].Origin < result.Zones[j].Origin })
	return result
}

func (t *table) replace(target *entry) *table {
	entries := make(map[string]*entry, len(t.entries))
	for name, current := range t.entries {
		entries[name] = current
	}
	entries[target.origin] = target
	return &table{epoch: t.epoch + 1, entries: entries}
}
