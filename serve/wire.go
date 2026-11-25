package serve

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"labelreef/lookup"
	"labelreef/zone"
)

const (
	headerSize = 12
	maxWire    = 65535
	plainUDP   = 512

	flagResponse = 0x8000
	flagOpcode   = 0x7800
	flagAA       = 0x0400
	flagTC       = 0x0200
	flagRD       = 0x0100
	flagReserved = 0x0040
	flagCD       = 0x0010
	flagRcode    = 0x000f
)

var errShort = errors.New("truncated DNS message")

type header struct {
	id         uint16
	flags      uint16
	questions  uint16
	answers    uint16
	authority  uint16
	additional uint16
}

func readHeader(b []byte) (header, error) {
	if len(b) < headerSize {
		return header{}, errShort
	}
	return header{
		id: binary.BigEndian.Uint16(b[0:]), flags: binary.BigEndian.Uint16(b[2:]),
		questions: binary.BigEndian.Uint16(b[4:]), answers: binary.BigEndian.Uint16(b[6:]),
		authority: binary.BigEndian.Uint16(b[8:]), additional: binary.BigEndian.Uint16(b[10:]),
	}, nil
}

func (h header) write(b []byte) {
	binary.BigEndian.PutUint16(b[0:], h.id)
	binary.BigEndian.PutUint16(b[2:], h.flags)
	binary.BigEndian.PutUint16(b[4:], h.questions)
	binary.BigEndian.PutUint16(b[6:], h.answers)
	binary.BigEndian.PutUint16(b[8:], h.authority)
	binary.BigEndian.PutUint16(b[10:], h.additional)
}

type wireReader struct {
	packet []byte
	offset int
	end    int
}

func readPacket(b []byte) wireReader {
	return wireReader{packet: b, offset: headerSize, end: len(b)}
}

func (r *wireReader) get(n int) ([]byte, error) {
	if n < 0 || n > r.end-r.offset {
		return nil, errShort
	}
	b := r.packet[r.offset : r.offset+n]
	r.offset += n
	return b, nil
}

func (r *wireReader) u16() (uint16, error) {
	b, err := r.get(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (r *wireReader) name() (string, error) {
	pos, limit := r.offset, r.end
	next := -1
	expanded := 1
	var result strings.Builder
	for hops := 0; hops < 128; hops++ {
		if pos >= limit {
			return "", errShort
		}
		n := int(r.packet[pos])
		switch {
		case n == 0:
			if next < 0 {
				next = pos + 1
			}
			r.offset = next
			if result.Len() == 0 {
				return zone.Root, nil
			}
			return result.String(), nil
		case n&0xc0 == 0xc0:
			if pos+1 >= limit {
				return "", errShort
			}
			ref := (n&0x3f)<<8 | int(r.packet[pos+1])
			if ref >= pos || ref < headerSize {
				return "", fmt.Errorf("invalid DNS compression pointer")
			}
			if next < 0 {
				next = pos + 2
			}
			pos, limit = ref, pos
		case n <= 63:
			pos++
			expanded += n + 1
			if n > limit-pos || expanded > 255 {
				return "", fmt.Errorf("invalid DNS label length")
			}
			result.WriteString(zone.LabelText(r.packet[pos:pos+n], false))
			result.WriteByte('.')
			pos += n
		default:
			return "", fmt.Errorf("unsupported DNS label form")
		}
	}
	return "", fmt.Errorf("too many DNS compression hops")
}

func (r *wireReader) question() (lookup.Question, string, error) {
	raw, err := r.name()
	if err != nil {
		return lookup.Question{}, "", err
	}
	data, err := r.get(4)
	if err != nil {
		return lookup.Question{}, "", err
	}
	name := strings.ToLower(raw)
	return lookup.Question{
		Name: name, Type: zone.Type(binary.BigEndian.Uint16(data)), Class: binary.BigEndian.Uint16(data[2:]),
	}, raw, nil
}

type writerState struct {
	length int
	names  int
}

type wireWriter struct {
	data []byte
	dict map[string]uint16
	keys []string
}

func newWriter(capacity int) *wireWriter {
	return &wireWriter{
		data: make([]byte, headerSize, max(capacity, headerSize)),
		dict: make(map[string]uint16),
	}
}

func (w *wireWriter) checkpoint() writerState {
	return writerState{length: len(w.data), names: len(w.keys)}
}

func (w *wireWriter) restore(at writerState) {
	w.data = w.data[:at.length]
	for _, key := range w.keys[at.names:] {
		delete(w.dict, key)
	}
	w.keys = w.keys[:at.names]
}

func (w *wireWriter) u16(n uint16) { w.data = binary.BigEndian.AppendUint16(w.data, n) }

func (w *wireWriter) u32(n uint32) { w.data = binary.BigEndian.AppendUint32(w.data, n) }

func (w *wireWriter) name(name string, compress bool) {
	for name != zone.Root {
		if compress {
			if offset, ok := w.dict[name]; ok {
				w.u16(offset | 0xc000)
				return
			}
			if len(w.data) < 1<<14 {
				w.dict[name] = uint16(len(w.data))
				w.keys = append(w.keys, name)
			}
		}
		end := strings.IndexByte(name, '.')
		start := len(w.data)
		w.data = append(w.data, 0)
		w.data = zone.AppendLabelBytes(w.data, name[:end])
		w.data[start] = byte(len(w.data) - start - 1)
		if end == len(name)-1 {
			break
		}
		name = name[end+1:]
	}
	w.data = append(w.data, 0)
}

func (w *wireWriter) question(q lookup.Question, raw string) {
	if raw == "" {
		raw = q.Name
	}
	w.name(raw, true)
	w.u16(uint16(q.Type))
	w.u16(q.Class)
}

func (w *wireWriter) finish(h header) []byte {
	h.write(w.data)
	return w.data
}
