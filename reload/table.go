package reload

import (
	"crypto/sha256"
	"fmt"
	"path/filepath"
	"sort"

	"labelreef/lookup"
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

// exact returns the entry for a configured origin while it has an active zone.
func (t *table) exact(origin string) *entry {
	e := t.entries[origin]
	if e == nil || e.snapshot.Current() == nil {
		return nil
	}
	return e
}

// origins lists the configured origins in deterministic order.
func (t *table) origins() []string {
	origins := make([]string, 0, len(t.entries))
	for origin := range t.entries {
		origins = append(origins, origin)
	}
	sort.Strings(origins)
	return origins
}

func (t *table) route(question lookup.Question) *zone.ZoneVersion {
	var closest *zone.ZoneVersion
	for name := question.Name; ; name = zone.Parent(name) {
		if e := t.entries[name]; e != nil {
			if z := e.snapshot.Current(); z != nil {
				if closest == nil {
					closest = z
					if question.Type != zone.DS || name != question.Name {
						return closest
					}
				} else if match := z.Find(question.Name); match.Kind == zone.Cut && match.Cut == question.Name {
					return z
				} else {
					return closest
				}
			}
		}
		if name == zone.Root {
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
