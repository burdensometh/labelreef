package zone

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type Type uint16

const (
	A     Type = 1
	NS    Type = 2
	CNAME Type = 5
	SOA   Type = 6
	PTR   Type = 12
	MX    Type = 15
	TXT   Type = 16
	AAAA  Type = 28
	SRV   Type = 33
	DS    Type = 43
	CAA   Type = 257

	OPT  Type = 41
	IXFR Type = 251
	AXFR Type = 252
	ANY  Type = 255
)

const ClassIN uint16 = 1

var typeNames = map[Type]string{
	A: "A", NS: "NS", CNAME: "CNAME", SOA: "SOA", PTR: "PTR", MX: "MX",
	TXT: "TXT", AAAA: "AAAA", SRV: "SRV", DS: "DS", CAA: "CAA",
	OPT: "OPT", IXFR: "IXFR", AXFR: "AXFR", ANY: "ANY",
}

func (t Type) String() string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return fmt.Sprintf("TYPE%d", t)
}

func ParseType(s string) (Type, error) {
	s = strings.ToUpper(s)
	for typ, name := range typeNames {
		if name == s {
			return typ, nil
		}
	}
	if strings.HasPrefix(s, "TYPE") {
		n, err := strconv.ParseUint(s[4:], 10, 16)
		if err == nil && n > 0 {
			return Type(n), nil
		}
	}
	return 0, fmt.Errorf("unknown DNS type %q", s)
}

type SOAData struct {
	Primary string
	Mailbox string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	Minimum uint32
}

type RData struct {
	Addr       netip.Addr
	Target     string
	Priority   uint16
	Weight     uint16
	Port       uint16
	Text       string
	SOA        SOAData
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string
	Flags      uint8
	Tag        string
	Value      string
}

type Record struct {
	Name string
	Type Type
	TTL  uint32
	Data RData
}

type Key struct {
	Name string
	Type Type
}

// RRset carries records that must stay together for response budgeting.
type RRset struct {
	Key
	Records []Record
}

func (r Record) Key() Key {
	return Key{Name: r.Name, Type: r.Type}
}

func (r Record) WithOwner(name string) Record {
	r.Name = name
	return r
}

func (r Record) WithSerial(serial uint32) Record {
	r.Data.SOA.Serial = serial
	return r
}

func (r Record) Validate() error {
	name, err := Name(r.Name)
	if err != nil || name != r.Name {
		return fmt.Errorf("owner %q is not canonical", r.Name)
	}
	rebuilt, err := canonicalData(r.Type, r.Data)
	if err != nil {
		return fmt.Errorf("%s %s: %w", r.Name, r.Type, err)
	}
	if rebuilt != r.Data {
		return fmt.Errorf("%s %s has noncanonical data", r.Name, r.Type)
	}
	return nil
}

func NewRRset(records []Record) RRset {
	if len(records) == 0 {
		return RRset{}
	}
	return RRset{Key: records[0].Key(), Records: append([]Record(nil), records...)}
}

func (s RRset) WithOwner(name string) RRset {
	records := append([]Record(nil), s.Records...)
	for i := range records {
		records[i] = records[i].WithOwner(name)
	}
	return RRset{Key: Key{Name: name, Type: s.Type}, Records: records}
}

func Less(a, b Record) bool {
	if a.Name != b.Name {
		return a.Name < b.Name
	}
	if a.Type != b.Type {
		return a.Type < b.Type
	}
	if a.TTL != b.TTL {
		return a.TTL < b.TTL
	}
	return a.Presentation() < b.Presentation()
}

func (r Record) Address() bool {
	return r.Type == A || r.Type == AAAA
}

func (r Record) AdditionalTarget() string {
	switch r.Type {
	case NS, MX, SRV:
		return r.Data.Target
	default:
		return ""
	}
}
