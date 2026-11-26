package zone

import (
	"fmt"
	"sort"
	"strings"
)

type NodeKind uint8

const (
	Missing NodeKind = iota
	Empty
	Ordinary
	Apex
	Cut
)

type node struct {
	name     string
	kind     NodeKind
	children map[string]*node
	sets     map[Type]RRset
}

type Delegation struct {
	Owner   string
	Servers RRset
	DS      RRset
}

type Match struct {
	Kind     NodeKind
	Closest  string
	Cut      string
	Wildcard string
}

// ZoneVersion is immutable after New. Collection accessors return copies.
type ZoneVersion struct {
	origin  string
	root    *node
	records []Record
	soa     Record
	count   int
}

func New(origin string, records []Record) (*ZoneVersion, error) {
	origin, err := Name(origin)
	if err != nil || strings.Contains(origin, "*") {
		return nil, fmt.Errorf("invalid zone origin %q", origin)
	}
	z := &ZoneVersion{
		origin: origin,
		root:   &node{name: origin, kind: Apex},
		count:  1,
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%s: empty zone", origin)
	}
	if err := z.load(records); err != nil {
		return nil, err
	}
	if len(z.root.sets[SOA].Records) != 1 || len(z.root.sets[NS].Records) == 0 {
		return nil, fmt.Errorf("%s: apex requires one SOA and at least one NS", origin)
	}
	if err := validateNodes(z.root, false); err != nil {
		return nil, err
	}
	z.soa = z.root.sets[SOA].Records[0]
	return z, nil
}

func (z *ZoneVersion) load(records []Record) error {
	z.records = append([]Record(nil), records...)
	for i, record := range z.records {
		if err := record.Validate(); err != nil {
			return fmt.Errorf("record %d: %w", i+1, err)
		}
		if !Within(record.Name, z.origin) {
			return fmt.Errorf("%s: owner %s is outside zone", z.origin, record.Name)
		}
		if record.Type == SOA && record.Name != z.origin {
			return fmt.Errorf("%s: SOA is restricted to apex", record.Name)
		}
	}
	sort.Slice(z.records, func(i, j int) bool {
		return Less(z.records[i], z.records[j])
	})
	for from := 0; from < len(z.records); {
		owner := z.records[from].Name
		shape := make(OwnerShape)
		n := z.insert(owner)
		for from < len(z.records) && z.records[from].Name == owner {
			r := z.records[from]
			end := from + 1
			for end < len(z.records) && z.records[end].Key() == r.Key() {
				if z.records[end] == z.records[end-1] {
					return fmt.Errorf("%s %s: duplicate record", r.Name, r.Type)
				}
				end++
			}
			for _, record := range z.records[from:end] {
				if err := shape.Add(record); err != nil {
					return err
				}
			}
			if n.sets == nil {
				n.sets = make(map[Type]RRset)
			}
			n.sets[r.Type] = RRset{Key: r.Key(), Records: z.records[from:end]}
			from = end
		}
	}
	return nil
}

// validateNodes assigns each node its kind and checks the owner rules. The
// cutAbove argument is the ancestor half of IsDelegation memoized along the
// walk: it holds exactly when an ancestor between n and the apex carries NS
// records, so an NS-carrying node becomes a Cut exactly when IsDelegation
// would report one.
func validateNodes(n *node, cutAbove bool) error {
	switch {
	case n.kind == Apex:
	case len(n.sets) == 0:
		n.kind = Empty
	case n.sets[NS].Records != nil && !cutAbove:
		n.kind = Cut
	default:
		n.kind = Ordinary
	}

	if len(n.sets) != 0 {
		shape := make(OwnerShape, len(n.sets))
		for typ, set := range n.sets {
			shape[typ] = RRsetShape{Count: len(set.Records)}
		}
		if err := shape.Validate(n.name, n.kind == Cut); err != nil {
			return err
		}
	}
	for _, child := range n.children {
		if err := validateNodes(child, cutAbove || n.kind == Cut); err != nil {
			return err
		}
	}
	return nil
}

func (z *ZoneVersion) relative(name string) []string {
	if name == z.origin {
		return nil
	}
	suffix := z.origin
	if suffix == Root {
		return Labels(name)
	}
	return strings.Split(strings.TrimSuffix(name[:len(name)-len(suffix)], "."), ".")
}

func (z *ZoneVersion) insert(name string) *node {
	n := z.root
	labels := z.relative(name)
	for i := len(labels) - 1; i >= 0; i-- {
		label := labels[i]
		child := n.children[label]
		if child == nil {
			child = &node{name: label + "."}
			if n.name != Root {
				child.name += n.name
			}
			if n.children == nil {
				n.children = make(map[string]*node)
			}
			n.children[label] = child
			z.count++
		}
		n = child
	}
	return n
}

func (z *ZoneVersion) exact(name string) *node {
	if !Within(name, z.origin) {
		return nil
	}
	n := z.root
	labels := z.relative(name)
	for i := len(labels) - 1; i >= 0; i-- {
		n = n.children[labels[i]]
		if n == nil {
			break
		}
	}
	return n
}

func (z *ZoneVersion) Find(name string) Match {
	if !Within(name, z.origin) {
		return Match{}
	}
	n := z.root
	labels := z.relative(name)
	for i := len(labels) - 1; i >= 0; i-- {
		if n.kind == Cut {
			return Match{Kind: Cut, Cut: n.name, Closest: n.name}
		}
		next := n.children[labels[i]]
		if next == nil {
			match := Match{Kind: Missing, Closest: n.name}
			if wildcard := n.children["*"]; wildcard != nil {
				match.Wildcard = wildcard.name
			}
			return match
		}
		n = next
	}
	match := Match{Kind: n.kind, Closest: n.name}
	if n.kind == Cut {
		match.Cut = n.name
	}
	return match
}

func (z *ZoneVersion) Origin() string { return z.origin }

func (z *ZoneVersion) Serial() uint32 { return z.soa.Data.SOA.Serial }

func (z *ZoneVersion) SOA() Record { return z.soa }

func (z *ZoneVersion) NodeCount() int { return z.count }

func (z *ZoneVersion) RecordCount() int { return len(z.records) }

func (z *ZoneVersion) Records() []Record {
	return append([]Record(nil), z.records...)
}

func (z *ZoneVersion) Set(owner string, typ Type) RRset {
	n := z.exact(owner)
	if n == nil {
		return RRset{}
	}
	return NewRRset(n.sets[typ].Records)
}

func (z *ZoneVersion) Sets(owner string) []RRset {
	n := z.exact(owner)
	if n == nil {
		return nil
	}
	sets := make([]RRset, 0, len(n.sets))
	for _, set := range n.sets {
		sets = append(sets, NewRRset(set.Records))
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].Type < sets[j].Type })
	return sets
}

func (z *ZoneVersion) Delegation(owner string) (Delegation, bool) {
	n := z.exact(owner)
	if n == nil || n.kind != Cut {
		return Delegation{}, false
	}
	return Delegation{
		Owner:   owner,
		Servers: NewRRset(n.sets[NS].Records),
		DS:      NewRRset(n.sets[DS].Records),
	}, true
}
