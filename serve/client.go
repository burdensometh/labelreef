package serve

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"labelreef/lookup"
	"labelreef/transfer"
	"labelreef/zone"
)

type Client struct {
	IOTimeout time.Duration
}

const maxTransferBytes = 128 << 20

func (c Client) Fetch(ctx context.Context, endpoint netip.AddrPort, origin string, base *zone.ZoneVersion) (transfer.Candidate, error) {
	return c.fetch(ctx, endpoint, origin, base, nil)
}

func (c Client) fetch(ctx context.Context, endpoint netip.AddrPort, origin string, base *zone.ZoneVersion, observe func([]byte) error) (transfer.Candidate, error) {
	addr := endpoint.Addr().Unmap()
	if !addr.IsLoopback() || addr.Zone() != "" || endpoint.Port() == 0 || c.IOTimeout <= 0 {
		return transfer.Candidate{}, fmt.Errorf("invalid loopback transfer endpoint or timeout")
	}
	name, err := zone.Name(origin)
	if err != nil || name != origin || (base != nil && base.Origin() != name) {
		return transfer.Candidate{}, fmt.Errorf("invalid transfer origin or base")
	}
	request := transfer.Request{Origin: origin, Type: zone.AXFR}
	if base != nil {
		request.Type = zone.IXFR
		request.HasSerial = true
		request.Serial = base.Serial()
	}
	receiver, err := transfer.NewReceiver(request, base)
	if err != nil {
		return transfer.Candidate{}, err
	}
	dialer := net.Dialer{Timeout: c.IOTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, endpoint.Port()).String())
	if err != nil {
		return transfer.Candidate{}, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	id, err := randomID()
	if err != nil {
		return transfer.Candidate{}, err
	}
	packet, question := makeTransferQuery(id, request, base)
	if observe != nil {
		if err := observe(packet); err != nil {
			return transfer.Candidate{}, err
		}
	}
	if err := conn.SetWriteDeadline(c.deadline(ctx)); err != nil {
		return transfer.Candidate{}, err
	}
	if err := writeFrame(conn, packet); err != nil {
		return transfer.Candidate{}, err
	}
	stream := replyStream{receiver: receiver, id: id, question: question}
	for !receiver.Done() {
		if err := conn.SetReadDeadline(c.deadline(ctx)); err != nil {
			return transfer.Candidate{}, err
		}
		reply, err := readFrame(conn)
		if err != nil {
			if ctx.Err() != nil {
				return transfer.Candidate{}, ctx.Err()
			}
			return transfer.Candidate{}, fmt.Errorf("transfer frame %d before terminal SOA: %w", stream.frames+1, err)
		}
		if err := stream.feed(reply); err != nil {
			return transfer.Candidate{}, err
		}
		if observe != nil {
			if err := observe(reply); err != nil {
				return transfer.Candidate{}, err
			}
		}
	}
	return receiver.Finish()
}

type replyStream struct {
	receiver *transfer.Receiver
	id       uint16
	question lookup.Question
	frames   int
	bytes    int
}

func (s *replyStream) feed(packet []byte) error {
	s.bytes += len(packet)
	if s.bytes > maxTransferBytes {
		return fmt.Errorf("transfer exceeds %d wire bytes", maxTransferBytes)
	}
	records, err := decodeTransfer(packet, s.id, s.question, s.frames == 0)
	if err == nil {
		err = s.receiver.Feed(records)
	}
	if err != nil {
		return fmt.Errorf("transfer frame %d: %w", s.frames+1, err)
	}
	s.frames++
	return nil
}

func (c Client) deadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(c.IOTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}

func decodeTransfer(packet []byte, id uint16, question lookup.Question, first bool) ([]zone.Record, error) {
	h, err := readHeader(packet)
	if err != nil {
		return nil, err
	}
	if h.id != id || h.flags&flagResponse == 0 || h.flags&(flagOpcode|flagTC|flagReserved) != 0 {
		return nil, fmt.Errorf("invalid transfer response header")
	}
	code := lookup.Code(h.flags & flagRcode)
	if code != lookup.Success {
		return nil, fmt.Errorf("transfer rejected with %s", code)
	}
	if h.flags&flagAA == 0 || h.authority != 0 || h.questions > 1 ||
		(first && h.questions != 1) || h.additional > 1 || h.answers == 0 {
		return nil, fmt.Errorf("invalid transfer response sections")
	}
	r := readPacket(packet)
	if h.questions == 1 {
		q, _, err := r.question()
		if err != nil || q != question {
			return nil, fmt.Errorf("transfer response question mismatch")
		}
	}
	if int(h.answers) > (r.end-r.offset)/11 {
		return nil, fmt.Errorf("impossible transfer answer count")
	}
	records := make([]zone.Record, 0, h.answers)
	for range h.answers {
		raw, err := r.record()
		if err != nil {
			return nil, err
		}
		record, err := raw.model()
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	if h.additional == 1 {
		rr, err := r.record()
		if err != nil {
			return nil, err
		}
		o, err := readOPT(rr)
		if err != nil || o.extended != 0 || o.version != 0 {
			return nil, fmt.Errorf("invalid transfer OPT")
		}
	}
	if r.offset != r.end {
		return nil, fmt.Errorf("trailing transfer response bytes")
	}
	return records, nil
}
