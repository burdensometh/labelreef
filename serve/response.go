package serve

import (
	"labelreef/lookup"
	"labelreef/zone"
)

const optSize = 11

func (q query) budget(tcp bool, maxUDP int) int {
	if tcp {
		return maxWire
	}
	if q.opt == nil {
		return plainUDP
	}
	return min(max(int(q.opt.size), plainUDP), maxUDP)
}

func (q query) responseHeader(code lookup.Code) header {
	return header{
		id:    q.id,
		flags: flagResponse | q.flags&(flagOpcode|flagRD|flagCD) | uint16(code)&flagRcode,
	}
}

func (q query) addQuestion(w *wireWriter, h *header) {
	if q.rawName != "" {
		w.question(q.question, q.rawName)
		h.questions++
	}
}

func (q query) addOPT(w *wireWriter, h *header, maxUDP int, code lookup.Code) {
	if q.opt == nil {
		return
	}
	w.data = append(w.data, 0)
	w.u16(uint16(zone.OPT))
	w.u16(uint16(maxUDP))
	ttl := uint32(code>>4) << 24
	if q.opt.dnssec {
		ttl |= 0x8000
	}
	w.u32(ttl)
	w.u16(0)
	h.additional++
}

func encodeAnswer(q query, reply lookup.Answer, tcp bool, maxUDP int) []byte {
	budget := q.budget(tcp, maxUDP)
	w := newWriter(min(budget, 1024))
	h := q.responseHeader(reply.Code)
	if reply.Authoritative {
		h.flags |= flagAA
	}
	q.addQuestion(w, &h)
	limit := budget
	if q.opt != nil {
		limit -= optSize
	}
	complete := writeSets(w, reply.Answer, limit, &h.answers, len(reply.Answer)) &&
		writeSets(w, reply.Authority, limit, &h.authority, len(reply.Authority)) &&
		writeSets(w, reply.Additional, limit, &h.additional, reply.RequiredAdditional)
	if !complete {
		h.flags |= flagTC
	}
	q.addOPT(w, &h, maxUDP, reply.Code)
	return w.finish(h)
}

// writeSets appends RRsets in order and reports whether every required set was
// written. Only the first required sets must be present, so trailing optional
// sets are dropped when the wire budget runs out. Dropping optional sets never
// truncates the response, because the fixed sections stay intact.
func writeSets(w *wireWriter, sets []zone.RRset, limit int, count *uint16, required int) bool {
	for i, set := range sets {
		at := w.checkpoint()
		fits := len(set.Records) <= int(^uint16(0)-*count)
		if fits {
			for _, record := range set.Records {
				w.record(record)
				if len(w.data) > limit {
					fits = false
					break
				}
			}
		}
		if !fits {
			w.restore(at)
			if i < required {
				return false
			}
			continue
		}
		*count += uint16(len(set.Records))
	}
	return true
}

func encodeTransfer(q query, records []zone.Record, first bool, maxUDP int) ([]byte, int) {
	w := newWriter(4096)
	h := q.responseHeader(lookup.Success)
	h.flags |= flagAA
	limit := maxWire
	if first {
		q.addQuestion(w, &h)
		if q.opt != nil {
			limit -= optSize
		}
	}
	for _, record := range records {
		at := w.checkpoint()
		w.record(record)
		if len(w.data) > limit {
			w.restore(at)
			break
		}
		h.answers++
	}
	if first {
		q.addOPT(w, &h, maxUDP, lookup.Success)
	}
	return w.finish(h), int(h.answers)
}
