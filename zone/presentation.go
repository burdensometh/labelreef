package zone

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

func ParseRecord(origin, owner string, ttl uint32, typ Type, input string) (Record, error) {
	name, err := Qualify(owner, origin)
	if err != nil {
		return Record{}, err
	}
	r := Record{Name: name, Type: typ, TTL: ttl}
	fields, err := parseFields(input)
	if err != nil {
		return Record{}, err
	}
	r.Data, err = parseData(origin, typ, fields)
	if err != nil {
		return Record{}, err
	}
	return r, nil
}

func parseFields(input string) ([]string, error) {
	var fields []string
	for {
		input = strings.TrimLeft(input, " \t\r\n")
		if input == "" {
			return fields, nil
		}
		var end int
		if input[0] == '"' {
			for end = 1; end < len(input); end++ {
				if input[end] == '\\' {
					end++
				} else if input[end] == '"' {
					break
				}
			}
			if end >= len(input) {
				return nil, fmt.Errorf("unterminated quoted field")
			}
			end++
			s, err := strconv.Unquote(input[:end])
			if err != nil {
				return nil, err
			}
			if end < len(input) && !strings.ContainsRune(" \t\r\n", rune(input[end])) {
				return nil, fmt.Errorf("quoted field requires a separator")
			}
			fields = append(fields, s)
		} else {
			end = strings.IndexAny(input, " \t\r\n")
			if end == -1 {
				end = len(input)
			}
			fields = append(fields, input[:end])
		}
		input = input[end:]
	}
}

func parseData(origin string, typ Type, f []string) (RData, error) {
	count := map[Type]int{
		A: 1, AAAA: 1, NS: 1, CNAME: 1, PTR: 1, MX: 2,
		SOA: 7, SRV: 4, DNAME: 1, DS: 4, CAA: 3,
	}
	n, fixed := count[typ]
	if !fixed && typ != TXT {
		return RData{}, fmt.Errorf("unsupported record type %s", typ)
	}
	if fixed && len(f) != n {
		return RData{}, fmt.Errorf("%s requires %d data fields", typ, n)
	}

	var d RData
	var err error
	switch typ {
	case A, AAAA:
		d.Addr, err = netip.ParseAddr(f[0])
		if err == nil && (d.Addr.Zone() != "" || (typ == A && !d.Addr.Is4()) ||
			(typ == AAAA && !d.Addr.Is6())) {
			err = fmt.Errorf("address family does not match %s", typ)
		}
	case NS, CNAME, PTR, DNAME:
		d.Target, err = dataName(f[0], origin)
	case MX:
		d.Priority, err = uint16Field(f[0])
		if err == nil {
			d.Target, err = dataName(f[1], origin)
		}
	case SOA:
		d.SOA, err = parseSOA(origin, f)
	case SRV:
		d, err = parseSRV(origin, f)
	case TXT:
		d.Text, err = PackText(f)
	case DS:
		d, err = parseDS(f)
	case CAA:
		d, err = parseCAA(f)
	}
	return d, err
}

func dataName(value, origin string) (string, error) {
	n, err := Qualify(value, origin)
	if err == nil && strings.Contains(n, "*") {
		return "", fmt.Errorf("wildcard in record target %q", value)
	}
	return n, err
}

func uint16Field(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	return uint16(n), err
}

func parseSOA(origin string, f []string) (SOAData, error) {
	primary, err := dataName(f[0], origin)
	if err != nil {
		return SOAData{}, err
	}
	mailbox, err := dataName(f[1], origin)
	if err != nil {
		return SOAData{}, err
	}
	var values [5]uint32
	for i, field := range f[2:] {
		n, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return SOAData{}, err
		}
		values[i] = uint32(n)
	}
	return SOAData{primary, mailbox, values[0], values[1], values[2], values[3], values[4]}, nil
}

func parseSRV(origin string, f []string) (RData, error) {
	priority, err := uint16Field(f[0])
	if err != nil {
		return RData{}, err
	}
	weight, err := uint16Field(f[1])
	if err != nil {
		return RData{}, err
	}
	port, err := uint16Field(f[2])
	if err != nil {
		return RData{}, err
	}
	target, err := dataName(f[3], origin)
	return RData{Priority: priority, Weight: weight, Port: port, Target: target}, err
}

func parseDS(f []string) (RData, error) {
	tag, err := uint16Field(f[0])
	if err != nil {
		return RData{}, err
	}
	algorithm, err := strconv.ParseUint(f[1], 10, 8)
	if err != nil {
		return RData{}, err
	}
	typ, err := strconv.ParseUint(f[2], 10, 8)
	if err != nil {
		return RData{}, err
	}
	digest, err := hex.DecodeString(f[3])
	if err != nil || len(digest) == 0 || len(digest) > 4096 {
		return RData{}, fmt.Errorf("invalid DS digest")
	}
	return RData{KeyTag: tag, Algorithm: uint8(algorithm), DigestType: uint8(typ), Digest: string(digest)}, nil
}

func parseCAA(f []string) (RData, error) {
	flags, err := strconv.ParseUint(f[0], 10, 8)
	if err != nil {
		return RData{}, err
	}
	if err := checkCAA(f[1], f[2]); err != nil {
		return RData{}, err
	}
	return RData{Flags: uint8(flags), Tag: strings.ToLower(f[1]), Value: f[2]}, nil
}

func PackText(parts []string) (string, error) {
	if len(parts) == 0 {
		return "", fmt.Errorf("TXT requires at least one string")
	}
	var b strings.Builder
	for _, part := range parts {
		if len(part) > 255 || b.Len()+len(part)+1 > 4096 {
			return "", fmt.Errorf("TXT exceeds v1 string limits")
		}
		b.WriteByte(byte(len(part)))
		b.WriteString(part)
	}
	return b.String(), nil
}

func UnpackText(data string) ([]string, error) {
	var parts []string
	for len(data) > 0 {
		n := int(data[0])
		if n+1 > len(data) {
			return nil, fmt.Errorf("truncated TXT string")
		}
		parts = append(parts, data[1:n+1])
		data = data[n+1:]
	}
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty TXT data")
	}
	return parts, nil
}

func (r Record) Presentation() string {
	d := r.Data
	switch r.Type {
	case A, AAAA:
		return d.Addr.String()
	case NS, CNAME, PTR, DNAME:
		return d.Target
	case MX:
		return fmt.Sprintf("%d %s", d.Priority, d.Target)
	case SOA:
		s := d.SOA
		return fmt.Sprintf("%s %s %d %d %d %d %d", s.Primary, s.Mailbox,
			s.Serial, s.Refresh, s.Retry, s.Expire, s.Minimum)
	case SRV:
		return fmt.Sprintf("%d %d %d %s", d.Priority, d.Weight, d.Port, d.Target)
	case TXT:
		parts, _ := UnpackText(d.Text)
		for i := range parts {
			parts[i] = strconv.Quote(parts[i])
		}
		return strings.Join(parts, " ")
	case DS:
		return fmt.Sprintf("%d %d %d %X", d.KeyTag, d.Algorithm, d.DigestType, d.Digest)
	case CAA:
		return fmt.Sprintf("%d %s %s", d.Flags, d.Tag, strconv.Quote(d.Value))
	}
	return ""
}
