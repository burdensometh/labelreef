package serial

import (
	"fmt"

	"labelreef/zone"
)

// RRsetPreconditionV1 names a complete RRset that must be present in the
// active zone before an edit applies. An empty records list requires the
// named owner/type RRset to be absent. Member order inside records is ignored.
type RRsetPreconditionV1 struct {
	Name    string          `json:"name"`
	Type    string          `json:"type"`
	TTL     uint32          `json:"ttl"`
	Records []zone.RecordV1 `json:"records"`
}

// rrsetPrecondition is the parsed, origin-relative form. Every member shares
// the owner and type, and members carry the single RRset TTL.
type rrsetPrecondition struct {
	name    string
	typ     zone.Type
	ttl     uint32
	members map[zone.Record]struct{}
}

func parsePreconditions(origin string, rows []RRsetPreconditionV1) ([]rrsetPrecondition, error) {
	result := make([]rrsetPrecondition, 0, len(rows))
	seen := make(map[zone.Key]struct{}, len(rows))
	for i, row := range rows {
		typ, err := zone.ParseType(row.Type)
		if err != nil {
			return nil, fmt.Errorf("precondition %d: %w", i+1, err)
		}
		if typ == zone.SOA {
			return nil, fmt.Errorf("precondition %d: SOA is managed by edit serial", i+1)
		}
		owner, err := zone.Qualify(row.Name, origin)
		if err != nil {
			return nil, fmt.Errorf("precondition %d: %w", i+1, err)
		}
		if !zone.Within(owner, origin) {
			return nil, fmt.Errorf("precondition %d: owner %s is outside zone", i+1, owner)
		}
		key := zone.Key{Name: owner, Type: typ}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("precondition %d: repeated RRset %s %s", i+1, owner, typ)
		}
		seen[key] = struct{}{}

		condition := rrsetPrecondition{
			name: owner, typ: typ, ttl: row.TTL, members: make(map[zone.Record]struct{}, len(row.Records)),
		}
		for j, member := range row.Records {
			record, err := member.Record(origin)
			if err != nil {
				return nil, fmt.Errorf("precondition %d record %d: %w", i+1, j+1, err)
			}
			if record.Type != typ || record.Name != owner {
				return nil, fmt.Errorf("precondition %d record %d: member must belong to %s %s",
					i+1, j+1, owner, typ)
			}
			if record.TTL != row.TTL {
				return nil, fmt.Errorf("precondition %d record %d: member TTL must match RRset TTL",
					i+1, j+1)
			}
			if _, duplicate := condition.members[record]; duplicate {
				return nil, fmt.Errorf("precondition %d record %d: duplicate member", i+1, j+1)
			}
			condition.members[record] = struct{}{}
		}
		result = append(result, condition)
	}
	return result, nil
}

// checkPreconditions confirms every named RRset matches the active zone as a
// complete set: the member identities, the single TTL and the type all count,
// while member ordering does not. An empty member set requires absence.
func checkPreconditions(current *zone.ZoneVersion, conditions []rrsetPrecondition) error {
	for _, condition := range conditions {
		set := current.Set(condition.name, condition.typ)
		if len(condition.members) == 0 {
			if len(set.Records) != 0 {
				return fmt.Errorf("precondition failed: %s %s must be absent", condition.name, condition.typ)
			}
			continue
		}
		if len(set.Records) != len(condition.members) {
			return fmt.Errorf("precondition failed: %s %s has %d records, expected %d",
				condition.name, condition.typ, len(set.Records), len(condition.members))
		}
		if set.Records[0].TTL != condition.ttl {
			return fmt.Errorf("precondition failed: %s %s TTL is %d, expected %d",
				condition.name, condition.typ, set.Records[0].TTL, condition.ttl)
		}
		for _, record := range set.Records {
			if _, ok := condition.members[record]; !ok {
				return fmt.Errorf("precondition failed: %s %s contains unexpected %s",
					condition.name, condition.typ, record.Presentation())
			}
		}
	}
	return nil
}
