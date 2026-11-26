package zone

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// MaxV2Bytes bounds an RRset-grouped zone file exactly like the v1 envelope.
const MaxV2Bytes = MaxV1Bytes

// RRsetV2 carries one owner/type pair. The TTL has a single source for every
// record in the RRset, and each entry in Records is presentation-format data.
type RRsetV2 struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	TTL     *uint32  `json:"ttl"`
	Records []string `json:"records"`
}

// FileV2 is the RRset-grouped zone envelope. Version must be 2.
type FileV2 struct {
	Version int       `json:"version"`
	Origin  string    `json:"origin"`
	RRSets  []RRsetV2 `json:"rrsets"`
}

// Zone expands the grouped envelope into the same validated ZoneVersion that
// v1 produces. Relative owners are qualified with the origin, duplicate
// owner/type pairs are rejected, and TXT strings keep their v1 segmentation.
func (f FileV2) Zone() (*ZoneVersion, error) {
	if f.Version != 2 {
		return nil, fmt.Errorf("unsupported zone file version %d", f.Version)
	}
	origin, err := Name(f.Origin)
	if err != nil {
		return nil, err
	}
	seen := make(map[Key]int, len(f.RRSets))
	records := make([]Record, 0)
	for i, group := range f.RRSets {
		if group.TTL == nil {
			return nil, fmt.Errorf("v2 rrset %d: requires an explicit ttl", i+1)
		}
		if len(group.Records) == 0 {
			return nil, fmt.Errorf("v2 rrset %d: requires at least one record", i+1)
		}
		typ, err := ParseType(group.Type)
		if err != nil {
			return nil, fmt.Errorf("v2 rrset %d: %w", i+1, err)
		}
		owner, err := Qualify(group.Name, origin)
		if err != nil {
			return nil, fmt.Errorf("v2 rrset %d: %w", i+1, err)
		}
		key := Key{Name: owner, Type: typ}
		if first, ok := seen[key]; ok {
			return nil, fmt.Errorf("v2 rrset %d: %s %s conflicts with rrset %d",
				i+1, owner, typ, first)
		}
		seen[key] = i + 1
		for j, data := range group.Records {
			record, err := ParseRecord(origin, group.Name, *group.TTL, typ, data)
			if err != nil {
				return nil, fmt.Errorf("v2 rrset %d record %d: %w", i+1, j+1, err)
			}
			records = append(records, record)
		}
	}
	return New(origin, records)
}

// V2 renders the zone in canonical RRset grouping. The zone records are held
// in canonical order, so the output is deterministic and repeatable.
func (z *ZoneVersion) V2() FileV2 {
	file := FileV2{Version: 2, Origin: z.origin, RRSets: make([]RRsetV2, 0)}
	for start := 0; start < len(z.records); {
		first := z.records[start]
		end := start + 1
		for end < len(z.records) && z.records[end].Key() == first.Key() {
			end++
		}
		ttl := first.TTL
		group := RRsetV2{Name: first.Name, Type: first.Type.String(), TTL: &ttl,
			Records: make([]string, 0, end-start)}
		for _, record := range z.records[start:end] {
			group.Records = append(group.Records, record.Presentation())
		}
		file.RRSets = append(file.RRSets, group)
		start = end
	}
	return file
}

// DecodeV2 reads and validates an RRset-grouped zone file.
func DecodeV2(r io.Reader) (*ZoneVersion, error) {
	var file FileV2
	if err := DecodeJSON(r, MaxV2Bytes, &file); err != nil {
		return nil, fmt.Errorf("v2 zone: %w", err)
	}
	return file.Zone()
}

// EncodeV2 writes the zone as repeatable canonical v2 JSON.
func EncodeV2(w io.Writer, z *ZoneVersion) error {
	return EncodeJSON(w, z.V2())
}

type zoneEnvelope struct {
	Version int `json:"version"`
}

// DecodeZone reads either envelope version and returns the version alongside
// the validated zone, so callers can report or re-emit the source format.
func DecodeZone(r io.Reader) (*ZoneVersion, int, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxV1Bytes+1))
	if err != nil {
		return nil, 0, err
	}
	if int64(len(data)) > MaxV1Bytes {
		return nil, 0, fmt.Errorf("JSON exceeds %d bytes", MaxV1Bytes)
	}
	// The version peek tolerates the other envelope fields; the full decoders
	// still enforce DisallowUnknownFields on their complete schemas.
	var head zoneEnvelope
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, 0, err
	}
	switch head.Version {
	case 1:
		z, err := DecodeV1(bytes.NewReader(data))
		return z, 1, err
	case 2:
		z, err := DecodeV2(bytes.NewReader(data))
		return z, 2, err
	default:
		return nil, head.Version, fmt.Errorf("unsupported zone file version %d", head.Version)
	}
}
