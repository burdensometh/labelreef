package serial

import (
	"fmt"
	"math"

	"labelreef/zone"
)

// Snapshot binds the currently active zone and its immutable retained history.
type Snapshot struct {
	current    *zone.ZoneVersion
	generation uint64
	deltas     []JournalDelta
	bySerial   map[uint32]int
}

func Seed(z *zone.ZoneVersion) *Snapshot {
	return &Snapshot{current: z, generation: 1}
}

func (s *Snapshot) Current() *zone.ZoneVersion {
	if s == nil {
		return nil
	}
	return s.current
}

func (s *Snapshot) Generation() uint64 {
	if s == nil {
		return 0
	}
	return s.generation
}

func (s *Snapshot) Retained() int {
	if s == nil {
		return 0
	}
	return len(s.deltas)
}

// Limit applies the configured retention horizon without altering a served
// zone or a transfer that already holds the old snapshot.
func (s *Snapshot) Limit(limit int) *Snapshot {
	if s == nil || limit >= len(s.deltas) {
		return s
	}
	start := len(s.deltas) - max(limit, 0)
	return makeSnapshot(s.current, s.generation, s.deltas[start:])
}

// History returns an isolated copy of the contiguous retained chain ending at Current.
func (s *Snapshot) History(from uint32) ([]JournalDelta, bool) {
	if s == nil {
		return nil, false
	}
	if s.current.Serial() == from {
		return nil, true
	}
	start, ok := s.bySerial[from]
	if !ok || Compare(s.current.Serial(), from) != Newer {
		return nil, false
	}
	return copyDeltas(s.deltas[start:]), true
}

func copyDeltas(deltas []JournalDelta) []JournalDelta {
	if len(deltas) == 0 {
		return nil
	}
	result := make([]JournalDelta, len(deltas))
	for i, delta := range deltas {
		result[i] = delta.clone()
	}
	return result
}

func Advance(base *Snapshot, target *zone.ZoneVersion, received []JournalDelta, limit int) (*Snapshot, error) {
	if target == nil || limit < 0 {
		return nil, fmt.Errorf("invalid snapshot target or retention")
	}
	if base == nil {
		if len(received) != 0 {
			return nil, fmt.Errorf("incremental commit requires base snapshot")
		}
		return Seed(target), nil
	}
	old := base.Current()
	if old.Origin() != target.Origin() {
		return nil, fmt.Errorf("snapshot origin changed from %s to %s", old.Origin(), target.Origin())
	}
	order := Compare(target.Serial(), old.Serial())
	if order == Equal {
		if len(received) == 0 && Same(old, target) {
			return base, nil
		}
		return nil, fmt.Errorf("conflicting data at serial %d", target.Serial())
	}
	if order != Newer {
		return nil, fmt.Errorf("serial %d cannot advance active %d", target.Serial(), old.Serial())
	}
	if base.generation == math.MaxUint64 {
		return nil, fmt.Errorf("local generation exhausted")
	}
	if len(received) == 0 {
		delta, err := Between(old, target)
		if err != nil {
			return nil, err
		}
		received = []JournalDelta{delta}
	} else if err := validateReceived(old, target, received); err != nil {
		return nil, err
	}
	history := append(append([]JournalDelta(nil), base.deltas...), copyDeltas(received)...)
	from := retainedStart(history, target.Serial(), limit)
	return makeSnapshot(target, base.generation+1, history[from:]), nil
}

func validateReceived(old, target *zone.ZoneVersion, deltas []JournalDelta) error {
	r := NewReplay(old)
	for i, d := range deltas {
		if err := r.Apply(d); err != nil {
			return fmt.Errorf("delta %d: %w", i+1, err)
		}
	}
	applied, err := r.Zone()
	if err != nil {
		return err
	}
	if !Same(applied, target) {
		return fmt.Errorf("received history disagrees with target zone")
	}
	return nil
}

func retainedStart(deltas []JournalDelta, current uint32, limit int) int {
	start := len(deltas)
	seen := map[uint32]bool{current: true}
	for start > 0 && len(deltas)-start < limit {
		from := deltas[start-1].From()
		if seen[from] || Compare(current, from) != Newer {
			break
		}
		seen[from] = true
		start--
	}
	return start
}

func makeSnapshot(target *zone.ZoneVersion, generation uint64, deltas []JournalDelta) *Snapshot {
	index := make(map[uint32]int, len(deltas))
	for i, delta := range deltas {
		index[delta.From()] = i
	}
	return &Snapshot{
		current: target, generation: generation, deltas: append([]JournalDelta(nil), deltas...), bySerial: index,
	}
}
