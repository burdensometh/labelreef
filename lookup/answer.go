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
	YXDomain   Code = 6
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
	case YXDomain:
		return "YXDOMAIN"
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

func Resolve(z *zone.ZoneVersion, q Question) Answer {
	if z == nil || q.Class != zone.ClassIN || !zone.Within(q.Name, z.Origin()) {
		return Answer{Code: Refused}
	}
	if q.Type == zone.AXFR || q.Type == zone.IXFR || q.Type == zone.OPT {
		return Answer{Code: Refused}
	}
	if match := z.Find(q.Name); match.Kind == zone.Cut {
		if q.Name == match.Cut && q.Type == zone.DS {
			return atCutDS(z, q.Name)
		}
		return referral(z, match.Cut)
	}

	answer := Answer{Authoritative: true}
	visited := make(map[string]bool)
	name := q.Name
	for {
		if visited[name] || len(visited) >= maxAliases {
			return Answer{Code: Failure}
		}
		visited[name] = true
		match := z.Find(name)
		if !zone.Within(name, z.Origin()) {
			break
		}
		if match.Kind == zone.Cut {
			if q.Type == zone.DS && match.Cut == name {
				ds := atCutDS(z, name)
				answer.Answer = append(answer.Answer, ds.Answer...)
				answer.Authority = ds.Authority
			} else {
				edge := referral(z, match.Cut)
				answer.Authority = edge.Authority
				answer.Additional = edge.Additional
				answer.GlueRequired = edge.GlueRequired
			}
			return answer
		}
		if dname, target, ok := z.DNameRedirect(name); ok {
			cname := zone.Record{
				Name: name, Type: zone.CNAME, TTL: dname.Records[0].TTL,
				Data: zone.RData{Target: target},
			}
			// RFC 6672 section 3.1: the synthesized CNAME precedes its DNAME.
			answer.Answer = append(answer.Answer,
				zone.NewRRset([]zone.Record{cname}), dname)
			name = target
			continue
		} else if len(dname.Records) != 0 {
			// The DNAME exists but the synthesized name would exceed the
			// protocol name limit: YXDOMAIN with no illegal CNAME on the wire.
			answer.Code = YXDomain
			answer.Authority = []zone.RRset{dname}
			answer.Additional = addressSets(z, answer.Answer, "")
			return answer
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
	answer.Additional = addressSets(z, answer.Answer, "")
	return answer
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
	authority := []zone.RRset{cut.Servers}
	glue := addressSets(z, authority, owner)
	return Answer{Authority: authority, Additional: glue, GlueRequired: true}
}

func addressSets(z *zone.ZoneVersion, source []zone.RRset, delegation string) []zone.RRset {
	seen := make(map[string]bool)
	var result []zone.RRset
	for _, set := range source {
		for _, record := range set.Records {
			target := record.AdditionalTarget()
			if target == "" || target == zone.Root || seen[target] || !zone.Within(target, z.Origin()) {
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
