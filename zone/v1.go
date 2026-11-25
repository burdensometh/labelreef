package zone

import (
	"encoding/json"
	"fmt"
	"io"
)

const MaxV1Bytes = 64 << 20

type RecordV1 struct {
	Name string `json:"name"`
	Type string `json:"type"`
	TTL  uint32 `json:"ttl"`
	Data string `json:"data"`
}

type FileV1 struct {
	Version int        `json:"version"`
	Origin  string     `json:"origin"`
	Records []RecordV1 `json:"records"`
}

func RecordToV1(r Record) RecordV1 {
	return RecordV1{
		Name: r.Name,
		Type: r.Type.String(),
		TTL:  r.TTL,
		Data: r.Presentation(),
	}
}

func (r RecordV1) Record(origin string) (Record, error) {
	typ, err := ParseType(r.Type)
	if err != nil {
		return Record{}, err
	}
	return ParseRecord(origin, r.Name, r.TTL, typ, r.Data)
}

func (f FileV1) Zone() (*ZoneVersion, error) {
	if f.Version != 1 {
		return nil, fmt.Errorf("unsupported zone file version %d", f.Version)
	}
	origin, err := Name(f.Origin)
	if err != nil {
		return nil, err
	}
	records := make([]Record, 0, len(f.Records))
	for i, row := range f.Records {
		record, err := row.Record(origin)
		if err != nil {
			return nil, fmt.Errorf("v1 record %d: %w", i+1, err)
		}
		records = append(records, record)
	}
	return New(origin, records)
}

func (z *ZoneVersion) V1() FileV1 {
	file := FileV1{Version: 1, Origin: z.origin, Records: make([]RecordV1, 0, len(z.records))}
	for _, record := range z.records {
		file.Records = append(file.Records, RecordToV1(record))
	}
	return file
}

func DecodeV1(r io.Reader) (*ZoneVersion, error) {
	var file FileV1
	if err := DecodeJSON(r, MaxV1Bytes, &file); err != nil {
		return nil, fmt.Errorf("v1 zone: %w", err)
	}
	return file.Zone()
}

func EncodeV1(w io.Writer, z *ZoneVersion) error {
	return EncodeJSON(w, z.V1())
}

func DecodeJSON(r io.Reader, max int64, v any) error {
	limited := &io.LimitedReader{R: r, N: max + 1}
	d := json.NewDecoder(limited)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var extra json.RawMessage
	trailing := d.Decode(&extra)
	if limited.N == 0 {
		return fmt.Errorf("JSON exceeds %d bytes", max)
	}
	if trailing != io.EOF {
		if trailing == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return trailing
	}
	return nil
}

func EncodeJSON(w io.Writer, v any) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(v)
}
