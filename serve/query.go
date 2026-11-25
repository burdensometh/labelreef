package serve

import (
	"fmt"

	"labelreef/lookup"
	"labelreef/transfer"
	"labelreef/zone"
)

type edns struct {
	size     uint16
	version  uint8
	extended uint8
	dnssec   bool
}

type query struct {
	header
	question lookup.Question
	rawName  string
	opt      *edns
	request  transfer.Request
}

func parseQuery(packet []byte) (query, lookup.Code, bool) {
	h, err := readHeader(packet)
	if err != nil || h.flags&flagResponse != 0 {
		return query{}, lookup.Format, false
	}
	q := query{header: h}
	if h.flags&flagOpcode != 0 {
		return q, lookup.NotImpl, true
	}
	if h.flags&(flagReserved|flagTC|flagRcode) != 0 || h.questions != 1 || h.answers != 0 || h.additional > 1 {
		return q, lookup.Format, true
	}
	reader := readPacket(packet)
	question, raw, err := reader.question()
	if err != nil || question.Type == 0 {
		return q, lookup.Format, true
	}
	q.question, q.rawName = question, raw
	q.request = transfer.Request{Origin: question.Name, Type: question.Type}
	switch question.Type {
	case zone.IXFR:
		if h.authority != 1 {
			return q, lookup.Format, true
		}
		rawSOA, err := reader.record()
		if err != nil || rawSOA.typ != zone.SOA || rawSOA.name != question.Name || rawSOA.class != question.Class {
			return q, lookup.Format, true
		}
		d, err := rawSOA.readData()
		if err != nil {
			return q, lookup.Format, true
		}
		q.request.HasSerial = true
		q.request.Serial = d.SOA.Serial
	default:
		if h.authority != 0 {
			return q, lookup.Format, true
		}
	}
	if h.additional == 1 {
		rr, err := reader.record()
		if err != nil {
			return q, lookup.Format, true
		}
		o, err := readOPT(rr)
		if err != nil || o.extended != 0 {
			return q, lookup.Format, true
		}
		q.opt = &o
	}
	if reader.offset != reader.end {
		return q, lookup.Format, true
	}
	if q.opt != nil && q.opt.version != 0 {
		return q, lookup.BadVersion, true
	}
	if question.Class != zone.ClassIN {
		return q, lookup.Refused, true
	}
	return q, lookup.Success, true
}

func (q query) isTransfer() bool {
	return q.question.Type == zone.AXFR || q.question.Type == zone.IXFR
}

func readOPT(rr wireRecord) (edns, error) {
	if rr.typ != zone.OPT || rr.name != zone.Root {
		return edns{}, fmt.Errorf("expected root OPT pseudo-record")
	}
	options := rr.data
	for options.offset < options.end {
		if _, err := options.u16(); err != nil {
			return edns{}, err
		}
		length, err := options.u16()
		if err != nil {
			return edns{}, err
		}
		if _, err := options.get(int(length)); err != nil {
			return edns{}, err
		}
	}
	return edns{
		size: rr.class, extended: uint8(rr.ttl >> 24),
		version: uint8(rr.ttl >> 16), dnssec: rr.ttl&0x8000 != 0,
	}, nil
}

func makeTransferQuery(id uint16, request transfer.Request, base *zone.ZoneVersion) ([]byte, lookup.Question) {
	q := lookup.Question{Name: request.Origin, Type: request.Type, Class: zone.ClassIN}
	w := newWriter(512)
	w.question(q, "")
	h := header{id: id, questions: 1}
	if request.Type == zone.IXFR {
		w.record(base.SOA())
		h.authority = 1
	}
	return w.finish(h), q
}
