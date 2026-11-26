package zone

import (
	"fmt"
	"strings"
)

// RRsetShape summarizes one RRset at an owner name: how many records it
// holds and the TTL they must share.
type RRsetShape struct {
	Count int
	TTL   uint32
}

// OwnerShape summarizes the nonempty RRsets at one owner name. Full zone
// construction and journal replay maintain these summaries and check them
// with Validate, so both paths reach the same verdict on the same final
// state without the incremental path rebuilding the whole zone.
type OwnerShape map[Type]RRsetShape

// Add folds one record into the summary, enforcing RRset TTL uniformity.
func (s OwnerShape) Add(record Record) error {
	set := s[record.Type]
	if set.Count > 0 && set.TTL != record.TTL {
		return fmt.Errorf("%s %s: mixed RRset TTLs", record.Name, record.Type)
	}
	set.Count++
	set.TTL = record.TTL
	s[record.Type] = set
	return nil
}

// Remove folds one record out of the summary.
func (s OwnerShape) Remove(record Record) {
	set := s[record.Type]
	set.Count--
	if set.Count > 0 {
		s[record.Type] = set
	} else {
		delete(s, record.Type)
	}
}

// HasNS reports whether the owner carries NS records.
func (s OwnerShape) HasNS() bool { return s[NS].Count != 0 }

// Validate enforces the owner rules at name: a CNAME owner stays a single
// exclusive record, and an exposed delegation is not a wildcard and carries
// only NS, DS and address records. Owners hidden below a delegation are
// checked with delegation false, which leaves their non-CNAME data alone.
func (s OwnerShape) Validate(name string, delegation bool) error {
	if !delegation && s[CNAME].Count == 0 {
		return nil
	}
	if n := s[CNAME].Count; n != 0 && (len(s) != 1 || n != 1) {
		return fmt.Errorf("%s: CNAME requires a single record and cannot coexist with other data", name)
	}
	if delegation {
		if strings.HasPrefix(name, "*.") {
			return fmt.Errorf("%s: wildcard delegation", name)
		}
		for typ := range s {
			if typ != NS && typ != DS && typ != A && typ != AAAA {
				return fmt.Errorf("%s: %s is invalid at a delegation", name, typ)
			}
		}
	}
	return nil
}

// IsDelegation reports whether name is an exposed delegation cut in the zone
// rooted at origin: the owner sits below the apex, carries NS records, and
// no ancestor between the owner and the origin carries NS records. hasNS
// answers whether an owner name carries NS records. The zone tree evaluates
// the same predicate incrementally during its kind walk; see validateNodes.
func IsDelegation(name, origin string, hasNS func(string) bool) bool {
	if name == origin || !hasNS(name) {
		return false
	}
	for ancestor := Parent(name); ancestor != origin; ancestor = Parent(ancestor) {
		if ancestor == Root || hasNS(ancestor) {
			return false
		}
	}
	return true
}
