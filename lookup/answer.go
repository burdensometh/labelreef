package lookup

import (
	"fmt"

	"labelreef/zone"
)

type Code uint16

const (
	Success    Code = 0
	Format     Code = 1
	Failure    Code = 2
	NameError  Code = 3
	NotImpl    Code = 4
	Refused    Code = 5
	BadVersion Code = 16
)

func (c Code) String() string {
	switch c {
	case Success:
		return "NOERROR"
	case Format:
		return "FORMERR"
	case Failure:
		return "SERVFAIL"
	case NameError:
		return "NXDOMAIN"
	case NotImpl:
		return "NOTIMP"
	case Refused:
		return "REFUSED"
	case BadVersion:
		return "BADVERS"
	default:
		return fmt.Sprintf("RCODE%d", c)
	}
}

type Question struct {
	Name  string
	Type  zone.Type
	Class uint16
}

type Answer struct {
	Code          Code
	Authoritative bool
	Answer        []zone.RRset
	Authority     []zone.RRset
	Additional    []zone.RRset
	GlueRequired  bool
}

const maxAliases = 16

// Table exposes the active routing table to a lookup. Every hop of one
// resolution selects its zone through the same Table instance, so an answer
// assembled across zones always reflects one atomically published generation.
type Table interface {
	Route(name string, typ zone.Type) *zone.ZoneVersion
}

// singleZone routes every in-zone name to the same immutable zone. It keeps the
// historical one-zone entry point working through the shared chain engine.
type singleZone struct {
	zone *zone.ZoneVersion
}

func (s singleZone) Route(name string, _ zone.Type) *zone.ZoneVersion {
	if zone.Within(name, s.zone.Origin()) {
		return s.zone
	}
	return nil
}

func Resolve(z *zone.ZoneVersion, q Question) Answer {
	if z == nil {
		return Answer{Code: Refused}
	}
	return ResolveTable(singleZone{zone: z}, q)
}

func ResolveTable(table Table, q Question) Answer {
	if table == nil || q.Class != zone.ClassIN {
		return Answer{Code: Refused}
	}
	if q.Type == zone.AXFR || q.Type == zone.IXFR || q.Type == zone.OPT {
		return Answer{Code: Refused}
	}
	first := table.Route(q.Name, q.Type)
	if first == nil {
		return Answer{Code: Refused}
	}

	answer := Answer{Authoritative: true}
	visited := make(map[string]bool)
	name := q.Name
	for {
		if visited[name] || len(visited) >= maxAliases {
			return Answer{Code: Failure}
		}
		visited[name] = true
		z := table.Route(name, q.Type)
		if z == nil {
			// The chain leaves every locally hosted zone. Whatever was
			// established so far (a CNAME chain, possibly ending at a
			// delegation) is returned without inventing outside data.
			break
		}
		match := z.Find(name)
		if match.Kind == zone.Cut {
			if q.Type == zone.DS && match.Cut == name {
				ds := atCutDS(z, name)
				answer.Answer = append(answer.Answer, ds.Answer...)
				answer.Authority = ds.Authority
			} else {
				edge := referral(z, match.Cut)
				answer.Authority = edge.Authority
				answer.GlueRequired = edge.GlueRequired
				answer.Authoritative = false
			}
			break
		}
		owner := name
		if match.Kind == zone.Missing {
			if match.Wildcard == "" {
				negative(z, &answer, NameError)
				break
			}
			owner = match.Wildcard
		}
		if q.Type == zone.ANY {
			for _, set := range z.Sets(owner) {
				answer.Answer = append(answer.Answer, rewrite(set, name))
			}
			if len(answer.Answer) == 0 {
				negative(z, &answer, Success)
			}
			break
		}
		if data := z.Set(owner, q.Type); len(data.Records) != 0 {
			answer.Answer = append(answer.Answer, rewrite(data, name))
			break
		}
		alias := z.Set(owner, zone.CNAME)
		if len(alias.Records) == 0 {
			negative(z, &answer, Success)
			break
		}
		answer.Answer = append(answer.Answer, rewrite(alias, name))
		name = alias.Records[0].Data.Target
	}
	// Referral glue accompanies the authority NS set rather than any answer RR.
	glueSource := answer.Answer
	if answer.GlueRequired {
		glueSource = answer.Authority
	}
	answer.Additional = answerAddresses(table, glueSource, referralCut(answer))
	return answer
}

// referralCut reports the delegation owner when the answer ended at a cut, so
// glue below that cut remains eligible even though the cut terminates authority.
func referralCut(answer Answer) string {
	if !answer.GlueRequired || len(answer.Authority) == 0 {
		return ""
	}
	return answer.Authority[0].Name
}

func rewrite(set zone.RRset, name string) zone.RRset {
	if set.Name == name {
		return set
	}
	return set.WithOwner(name)
}

func negative(z *zone.ZoneVersion, answer *Answer, code Code) {
	soa := z.SOA()
	if soa.Data.SOA.Minimum < soa.TTL {
		soa.TTL = soa.Data.SOA.Minimum
	}
	answer.Code = code
	answer.Authority = []zone.RRset{zone.NewRRset([]zone.Record{soa})}
}

func atCutDS(z *zone.ZoneVersion, owner string) Answer {
	cut, _ := z.Delegation(owner)
	answer := Answer{Authoritative: true}
	if len(cut.DS.Records) == 0 {
		negative(z, &answer, Success)
	} else {
		answer.Answer = []zone.RRset{cut.DS}
	}
	return answer
}

func referral(z *zone.ZoneVersion, owner string) Answer {
	cut, _ := z.Delegation(owner)
	return Answer{Authority: []zone.RRset{cut.Servers}, GlueRequired: true}
}

// answerAddresses resolves in-zone address records for NS/MX/SRV targets in the
// answer section. Each target is routed through the active table, so chains
// that crossed into another hosted zone still receive that zone's addresses.
// It also supplies glue for a referral: the delegation owner exempts names
// below the cut from the ordinary cut exclusion.
func answerAddresses(table Table, source []zone.RRset, delegation string) []zone.RRset {
	seen := make(map[string]bool)
	var result []zone.RRset
	for _, set := range source {
		for _, record := range set.Records {
			target := record.AdditionalTarget()
			if target == "" || target == zone.Root || seen[target] {
				continue
			}
			z := table.Route(target, zone.A)
			if z == nil || !zone.Within(target, z.Origin()) {
				continue
			}
			match := z.Find(target)
			if delegation == "" && match.Kind == zone.Cut {
				continue
			}
			if delegation != "" && match.Kind == zone.Cut && match.Cut != delegation {
				continue
			}
			if match.Kind == zone.Missing {
				continue
			}
			seen[target] = true
			for _, typ := range []zone.Type{zone.A, zone.AAAA} {
				if address := z.Set(target, typ); len(address.Records) > 0 {
					result = append(result, address)
				}
			}
		}
	}
	return result
}
