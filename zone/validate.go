package zone

import (
	"fmt"
	"strings"
)

// canonicalData validates values without rendering and parsing them again.
// Constructing the expected shape also checks for fields from another RR type.
func canonicalData(typ Type, d RData) (RData, error) {
	switch typ {
	case A, AAAA:
		if d.Addr.Zone() != "" || (typ == A && !d.Addr.Is4()) || (typ == AAAA && !d.Addr.Is6()) {
			return RData{}, fmt.Errorf("address family does not match %s", typ)
		}
		return RData{Addr: d.Addr}, nil
	case NS, CNAME, PTR, MX, SRV:
		target, err := dataName(d.Target, Root)
		if err != nil {
			return RData{}, err
		}
		result := RData{Target: target}
		if typ == MX || typ == SRV {
			result.Priority = d.Priority
		}
		if typ == SRV {
			result.Weight, result.Port = d.Weight, d.Port
		}
		return result, nil
	case SOA:
		s := d.SOA
		primary, err := dataName(s.Primary, Root)
		if err != nil {
			return RData{}, err
		}
		mailbox, err := dataName(s.Mailbox, Root)
		if err != nil {
			return RData{}, err
		}
		s.Primary, s.Mailbox = primary, mailbox
		return RData{SOA: s}, nil
	case TXT:
		if err := checkPackedText(d.Text); err != nil {
			return RData{}, err
		}
		return RData{Text: d.Text}, nil
	case DS:
		if len(d.Digest) == 0 || len(d.Digest) > 4096 {
			return RData{}, fmt.Errorf("invalid DS digest")
		}
		return RData{KeyTag: d.KeyTag, Algorithm: d.Algorithm, DigestType: d.DigestType, Digest: d.Digest}, nil
	case CAA:
		if err := checkCAA(d.Tag, d.Value); err != nil {
			return RData{}, err
		}
		return RData{Flags: d.Flags, Tag: strings.ToLower(d.Tag), Value: d.Value}, nil
	default:
		return RData{}, fmt.Errorf("unsupported record type %s", typ)
	}
}

func checkPackedText(data string) error {
	if len(data) == 0 || len(data) > 4096 {
		return fmt.Errorf("TXT exceeds v1 string limits")
	}
	for len(data) > 0 {
		n := int(data[0]) + 1
		if n > len(data) {
			return fmt.Errorf("truncated TXT string")
		}
		data = data[n:]
	}
	return nil
}

func checkCAA(tag, value string) error {
	if len(tag) == 0 || len(tag) > 15 || len(value) > 4096 {
		return fmt.Errorf("invalid CAA field length")
	}
	for _, c := range tag {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return fmt.Errorf("invalid CAA tag %q", tag)
		}
	}
	return nil
}
