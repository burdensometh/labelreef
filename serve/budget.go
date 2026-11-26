package serve

import (
	"strings"
	"sync"

	"labelreef/zone"
)

// reefBudget measures DNS names with the same suffix compression rules as
// wireWriter. tentative contains names introduced by the RRset currently being
// measured; the writer's dict remains the committed dictionary.
type reefBudget struct {
	base      int
	written   int
	committed map[string]uint16
	tentative map[string]struct{}
}

var reefBudgetPool = sync.Pool{
	New: func() any {
		return &reefBudget{tentative: make(map[string]struct{}, 64)}
	},
}

func getReefBudget(committed map[string]uint16, base int) *reefBudget {
	p := reefBudgetPool.Get().(*reefBudget)
	clear(p.tentative)
	p.base = base
	p.written = 0
	p.committed = committed
	return p
}

func putReefBudget(p *reefBudget) {
	p.committed = nil
	clear(p.tentative)
	reefBudgetPool.Put(p)
}

func (p *reefBudget) name(name string, compress bool) int {
	start := p.written
	for name != zone.Root {
		if compress {
			if _, ok := p.committed[name]; ok {
				p.written += 2
				return p.written - start
			}
			if _, ok := p.tentative[name]; ok {
				p.written += 2
				return p.written - start
			}
			if p.base+p.written < 1<<14 {
				p.tentative[name] = struct{}{}
			}
		}

		end := strings.IndexByte(name, '.')
		label := name[:end]
		// Canonical labels encode every non-plain octet as \DDD, so each
		// four-byte presentation escape contributes one wire octet.
		p.written += 1 + len(label) - 3*strings.Count(label, `\`)
		if end == len(name)-1 {
			break
		}
		name = name[end+1:]
	}
	p.written++ // root label
	return p.written - start
}

func (p *reefBudget) rdata(rr zone.Record) {
	d := rr.Data
	switch rr.Type {
	case zone.A:
		p.written += 4
	case zone.AAAA:
		p.written += 16
	case zone.NS, zone.CNAME, zone.PTR:
		p.name(d.Target, true)
	case zone.MX:
		p.written += 2
		p.name(d.Target, true)
	case zone.SOA:
		p.name(d.SOA.Primary, true)
		p.name(d.SOA.Mailbox, true)
		p.written += 20
	case zone.SRV:
		p.written += 6
		p.name(d.Target, false)
	case zone.TXT:
		p.written += len(d.Text)
	case zone.DS:
		p.written += 4 + len(d.Digest)
	case zone.CAA:
		p.written += 2 + len(d.Tag) + len(d.Value)
	}
}

func (p *reefBudget) record(rr zone.Record) {
	p.name(rr.Name, true)
	p.written += 2 + 2 + 4 + 2 // type, class, TTL, RDLENGTH
	p.rdata(rr)
}

func reefMaxNameSize(name string) int {
	if name == zone.Root {
		return 1
	}
	// A canonical absolute name uses one length octet per label and one
	// terminal zero octet. len(name)+1 is a safe uncompressed upper bound;
	// escape sequences make the wire form shorter than the presentation form.
	return len(name) + 1
}

func reefMaxRecordSize(rr zone.Record) int {
	size := reefMaxNameSize(rr.Name) + 2 + 2 + 4 + 2
	d := rr.Data
	switch rr.Type {
	case zone.A:
		size += 4
	case zone.AAAA:
		size += 16
	case zone.NS, zone.CNAME, zone.PTR:
		size += reefMaxNameSize(d.Target)
	case zone.MX:
		size += 2 + reefMaxNameSize(d.Target)
	case zone.SOA:
		size += reefMaxNameSize(d.SOA.Primary) + reefMaxNameSize(d.SOA.Mailbox) + 20
	case zone.SRV:
		size += 6 + reefMaxNameSize(d.Target)
	case zone.TXT:
		size += len(d.Text)
	case zone.DS:
		size += 4 + len(d.Digest)
	case zone.CAA:
		size += 2 + len(d.Tag) + len(d.Value)
	}
	return size
}

// rrsetFits reports whether the complete RRset can be appended without
// exceeding limit. Compression is measured against both names already in w and
// suffixes that earlier records of this same RRset would add.
func (w *wireWriter) rrsetFits(set zone.RRset, limit int, count uint16) bool {
	if len(set.Records) > int(^uint16(0)-count) {
		return false
	}

	// Fast path: even the conservative uncompressed bound is within budget.
	upper := len(w.data)
	upperBoundOK := true
	for _, rr := range set.Records {
		upper += reefMaxRecordSize(rr)
		if upper > limit {
			upperBoundOK = false
			break
		}
	}
	if upperBoundOK {
		return true
	}

	p := getReefBudget(w.dict, len(w.data))
	defer putReefBudget(p)

	for _, rr := range set.Records {
		p.record(rr)
		if len(w.data)+p.written > limit {
			return false
		}
	}
	return true
}
