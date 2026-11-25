package serve

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"labelreef/zone"
)

type wireRecord struct {
	name  string
	typ   zone.Type
	class uint16
	ttl   uint32
	data  wireReader
}

func (r *wireReader) record() (wireRecord, error) {
	name, err := r.name()
	if err != nil {
		return wireRecord{}, err
	}
	fields, err := r.get(10)
	if err != nil {
		return wireRecord{}, err
	}
	start := r.offset
	if _, err := r.get(int(binary.BigEndian.Uint16(fields[8:]))); err != nil {
		return wireRecord{}, err
	}
	return wireRecord{
		name: strings.ToLower(name), typ: zone.Type(binary.BigEndian.Uint16(fields)),
		class: binary.BigEndian.Uint16(fields[2:]), ttl: binary.BigEndian.Uint32(fields[4:]),
		data: wireReader{packet: r.packet, offset: start, end: r.offset},
	}, nil
}

func (rr wireRecord) model() (zone.Record, error) {
	if rr.class != zone.ClassIN {
		return zone.Record{}, fmt.Errorf("unsupported record class %d", rr.class)
	}
	data, err := rr.readData()
	if err != nil {
		return zone.Record{}, err
	}
	record := zone.Record{Name: rr.name, Type: rr.typ, TTL: rr.ttl, Data: data}
	return record, record.Validate()
}

func (rr wireRecord) readData() (zone.RData, error) {
	r := rr.data
	var d zone.RData
	var err error
	switch rr.typ {
	case zone.A:
		var b []byte
		b, err = r.get(4)
		if err == nil {
			d.Addr = netip.AddrFrom4([4]byte(b))
		}
	case zone.AAAA:
		var b []byte
		b, err = r.get(16)
		if err == nil {
			d.Addr = netip.AddrFrom16([16]byte(b))
		}
	case zone.NS, zone.CNAME, zone.PTR:
		d.Target, err = r.target()
	case zone.MX:
		d.Priority, err = r.u16()
		if err == nil {
			d.Target, err = r.target()
		}
	case zone.SOA:
		d.SOA, err = readSOA(&r)
	case zone.SRV:
		d, err = readSRV(&r)
	case zone.TXT:
		d.Text = string(r.packet[r.offset:r.end])
		r.offset = r.end
	case zone.DS:
		d, err = readDS(&r)
	case zone.CAA:
		d, err = readCAA(&r)
	default:
		return zone.RData{}, fmt.Errorf("unsupported RDATA type %s", rr.typ)
	}
	if err != nil {
		return zone.RData{}, err
	}
	if r.offset != r.end {
		return zone.RData{}, fmt.Errorf("trailing data for %s record", rr.typ)
	}
	return d, nil
}

func (r *wireReader) target() (string, error) {
	name, err := r.name()
	return strings.ToLower(name), err
}

func readSOA(r *wireReader) (zone.SOAData, error) {
	primary, err := r.target()
	if err != nil {
		return zone.SOAData{}, err
	}
	mailbox, err := r.target()
	if err != nil {
		return zone.SOAData{}, err
	}
	b, err := r.get(20)
	if err != nil {
		return zone.SOAData{}, err
	}
	return zone.SOAData{
		Primary: primary, Mailbox: mailbox,
		Serial: binary.BigEndian.Uint32(b), Refresh: binary.BigEndian.Uint32(b[4:]),
		Retry: binary.BigEndian.Uint32(b[8:]), Expire: binary.BigEndian.Uint32(b[12:]),
		Minimum: binary.BigEndian.Uint32(b[16:]),
	}, nil
}

func readSRV(r *wireReader) (zone.RData, error) {
	b, err := r.get(6)
	if err != nil {
		return zone.RData{}, err
	}
	target, err := r.target()
	return zone.RData{
		Priority: binary.BigEndian.Uint16(b), Weight: binary.BigEndian.Uint16(b[2:]),
		Port: binary.BigEndian.Uint16(b[4:]), Target: target,
	}, err
}

func readDS(r *wireReader) (zone.RData, error) {
	b, err := r.get(4)
	if err != nil {
		return zone.RData{}, err
	}
	d := zone.RData{
		KeyTag: binary.BigEndian.Uint16(b), Algorithm: b[2], DigestType: b[3],
		Digest: string(r.packet[r.offset:r.end]),
	}
	r.offset = r.end
	return d, nil
}

func readCAA(r *wireReader) (zone.RData, error) {
	prefix, err := r.get(2)
	if err != nil {
		return zone.RData{}, err
	}
	tag, err := r.get(int(prefix[1]))
	if err != nil {
		return zone.RData{}, err
	}
	d := zone.RData{Flags: prefix[0], Tag: strings.ToLower(string(tag)), Value: string(r.packet[r.offset:r.end])}
	r.offset = r.end
	return d, nil
}

func (w *wireWriter) record(rr zone.Record) {
	w.name(rr.Name, true)
	w.u16(uint16(rr.Type))
	w.u16(zone.ClassIN)
	w.u32(rr.TTL)
	length := len(w.data)
	w.u16(0)
	w.rdata(rr)
	binary.BigEndian.PutUint16(w.data[length:], uint16(len(w.data)-length-2))
}

func (w *wireWriter) rdata(rr zone.Record) {
	d := rr.Data
	switch rr.Type {
	case zone.A:
		a := d.Addr.As4()
		w.data = append(w.data, a[:]...)
	case zone.AAAA:
		a := d.Addr.As16()
		w.data = append(w.data, a[:]...)
	case zone.NS, zone.CNAME, zone.PTR:
		w.name(d.Target, true)
	case zone.MX:
		w.u16(d.Priority)
		w.name(d.Target, true)
	case zone.SOA:
		s := d.SOA
		w.name(s.Primary, true)
		w.name(s.Mailbox, true)
		w.u32(s.Serial)
		w.u32(s.Refresh)
		w.u32(s.Retry)
		w.u32(s.Expire)
		w.u32(s.Minimum)
	case zone.SRV:
		w.u16(d.Priority)
		w.u16(d.Weight)
		w.u16(d.Port)
		w.name(d.Target, false)
	case zone.TXT:
		w.data = append(w.data, d.Text...)
	case zone.DS:
		w.u16(d.KeyTag)
		w.data = append(w.data, d.Algorithm, d.DigestType)
		w.data = append(w.data, d.Digest...)
	case zone.CAA:
		w.data = append(w.data, d.Flags, byte(len(d.Tag)))
		w.data = append(w.data, d.Tag...)
		w.data = append(w.data, d.Value...)
	}
}
