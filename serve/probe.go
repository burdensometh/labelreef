package serve

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"time"

	"labelreef/lookup"
	"labelreef/zone"
)

type ProbeOptions struct {
	Address          netip.AddrPort
	Timeout          time.Duration
	TCP              bool
	RetryTCP         bool
	EDNSSize         uint16
	RecursionDesired bool
}

type ProbeResult struct {
	Transport     string          `json:"transport"`
	RetriedTCP    bool            `json:"retried_tcp"`
	Name          string          `json:"name"`
	Type          string          `json:"type"`
	Code          string          `json:"code"`
	Authoritative bool            `json:"authoritative"`
	Truncated     bool            `json:"truncated"`
	Answer        []zone.RecordV1 `json:"answer"`
	Authority     []zone.RecordV1 `json:"authority"`
	Additional    []zone.RecordV1 `json:"additional"`
	AdvertisedUDP uint16          `json:"advertised_udp,omitempty"`
	Bytes         int             `json:"bytes"`
}

// Probe sends an ordinary DNS query to a loopback address for diagnosis and demos.
func Probe(ctx context.Context, name string, typ zone.Type, options ProbeOptions) (ProbeResult, error) {
	origin, err := zone.Name(name)
	if err != nil {
		return ProbeResult{}, err
	}
	addr := options.Address.Addr().Unmap()
	if !addr.IsLoopback() || addr.Zone() != "" || options.Address.Port() == 0 || options.Timeout <= 0 {
		return ProbeResult{}, fmt.Errorf("invalid DNS probe endpoint or timeout")
	}
	if typ == 0 || typ == zone.AXFR || typ == zone.IXFR || typ == zone.OPT {
		return ProbeResult{}, fmt.Errorf("probe requires an ordinary DNS question")
	}
	options.Address = netip.AddrPortFrom(addr, options.Address.Port())
	q := lookup.Question{Name: origin, Type: typ, Class: zone.ClassIN}
	id, err := randomID()
	if err != nil {
		return ProbeResult{}, err
	}
	query := probePacket(id, q, options)
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	mode := "udp"
	if options.TCP {
		mode = "tcp"
	}
	result, err := probeExchange(ctx, mode, options.Address, query, id, q)
	if err != nil || !result.Truncated || mode != "udp" || !options.RetryTCP {
		return result, err
	}
	result, err = probeExchange(ctx, "tcp", options.Address, query, id, q)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("TCP after truncated UDP: %w", err)
	}
	result.RetriedTCP = true
	return result, nil
}

func randomID() (uint16, error) {
	var bytes [2]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(bytes[:]), nil
}

func probePacket(id uint16, q lookup.Question, options ProbeOptions) []byte {
	w := newWriter(512)
	w.question(q, "")
	h := header{id: id, questions: 1}
	if options.RecursionDesired {
		h.flags |= flagRD
	}
	if options.EDNSSize != 0 {
		shape := query{opt: &edns{size: options.EDNSSize}}
		shape.addOPT(w, &h, int(options.EDNSSize), lookup.Success)
	}
	return w.finish(h)
}

func probeExchange(ctx context.Context, mode string, address netip.AddrPort, packet []byte, id uint16, q lookup.Question) (ProbeResult, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, mode, address.String())
	if err != nil {
		return ProbeResult{}, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if until, valid := ctx.Deadline(); valid {
		if err := conn.SetDeadline(until); err != nil {
			return ProbeResult{}, err
		}
	}
	var reply []byte
	if mode == "tcp" {
		err = writeFrame(conn, packet)
		if err == nil {
			reply, err = readFrame(conn)
		}
	} else {
		// A connected UDP socket keeps the request and response tied to one peer.
		var n int
		n, err = conn.Write(packet)
		if err == nil && n != len(packet) {
			err = fmt.Errorf("short UDP request")
		}
		if err == nil {
			reply = make([]byte, 65535)
			n, err = conn.Read(reply)
			reply = reply[:n]
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return ProbeResult{}, ctx.Err()
		}
		return ProbeResult{}, err
	}
	result, err := decodeProbe(reply, id, q)
	result.Transport = mode
	return result, err
}

func decodeProbe(packet []byte, id uint16, expected lookup.Question) (ProbeResult, error) {
	h, err := readHeader(packet)
	if err != nil {
		return ProbeResult{}, err
	}
	if h.id != id || h.flags&flagResponse == 0 || h.flags&flagOpcode != 0 || h.questions != 1 {
		return ProbeResult{}, fmt.Errorf("invalid DNS probe response header")
	}
	r := readPacket(packet)
	q, _, err := r.question()
	if err != nil || q != expected {
		return ProbeResult{}, fmt.Errorf("probe question mismatch")
	}
	result := ProbeResult{
		Name: q.Name, Type: q.Type.String(), Authoritative: h.flags&flagAA != 0,
		Truncated: h.flags&flagTC != 0, Bytes: len(packet),
	}
	code := lookup.Code(h.flags & flagRcode)
	result.Answer, err = decodeSection(&r, int(h.answers))
	if err != nil {
		return ProbeResult{}, fmt.Errorf("answer: %w", err)
	}
	result.Authority, err = decodeSection(&r, int(h.authority))
	if err != nil {
		return ProbeResult{}, fmt.Errorf("authority: %w", err)
	}
	result.Additional = make([]zone.RecordV1, 0)
	for range h.additional {
		rr, err := r.record()
		if err != nil {
			return ProbeResult{}, fmt.Errorf("additional: %w", err)
		}
		if rr.typ == zone.OPT {
			if result.AdvertisedUDP != 0 {
				return ProbeResult{}, fmt.Errorf("duplicate response OPT")
			}
			opts, err := readOPT(rr)
			if err != nil {
				return ProbeResult{}, err
			}
			result.AdvertisedUDP = opts.size
			code |= lookup.Code(opts.extended) << 4
		} else {
			record, err := rr.model()
			if err != nil {
				return ProbeResult{}, err
			}
			result.Additional = append(result.Additional, zone.RecordToV1(record))
		}
	}
	if r.offset != r.end {
		return ProbeResult{}, fmt.Errorf("trailing probe response bytes")
	}
	result.Code = code.String()
	return result, nil
}

func decodeSection(r *wireReader, count int) ([]zone.RecordV1, error) {
	if count > (r.end-r.offset)/11 {
		return nil, fmt.Errorf("impossible DNS section count")
	}
	out := make([]zone.RecordV1, 0, count)
	for i := 0; i < count; i++ {
		raw, err := r.record()
		if err != nil {
			return nil, err
		}
		record, err := raw.model()
		if err != nil {
			return nil, err
		}
		out = append(out, zone.RecordToV1(record))
	}
	return out, nil
}
