package serve

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"labelreef/lookup"
	"labelreef/transfer"
	"labelreef/zone"
)

const traceMagic = "LABELREEF-XFR\x00\x01"

// Capture writes the v1 magic, one DNS TCP query frame and the full sequence
// of DNS TCP reply frames. A writer may contain a partial trace on failure.
func (c Client) Capture(ctx context.Context, source netip.AddrPort, origin string, base *zone.ZoneVersion, w io.Writer) (transfer.Candidate, error) {
	if w == nil {
		return transfer.Candidate{}, fmt.Errorf("transfer capture requires a writer")
	}
	if err := writeAll(w, []byte(traceMagic)); err != nil {
		return transfer.Candidate{}, fmt.Errorf("write transfer trace header: %w", err)
	}
	return c.fetch(ctx, source, origin, base, func(packet []byte) error {
		if err := writeFrame(w, packet); err != nil {
			return fmt.Errorf("write transfer trace frame: %w", err)
		}
		return nil
	})
}

// ReplayTrace consumes the entire recording and applies the live transfer
// parser to each frame. An IXFR record requires the original receiver zone.
func ReplayTrace(r io.Reader, base *zone.ZoneVersion) (transfer.Candidate, error) {
	if r == nil {
		return transfer.Candidate{}, fmt.Errorf("transfer replay requires a reader")
	}
	magic := make([]byte, len(traceMagic))
	if _, err := io.ReadFull(r, magic); err != nil {
		return transfer.Candidate{}, fmt.Errorf("read transfer trace header: %w", err)
	}
	if !bytes.Equal(magic, []byte(traceMagic)) {
		return transfer.Candidate{}, fmt.Errorf("unknown transfer trace format")
	}
	packet, err := readFrame(r)
	if err != nil {
		return transfer.Candidate{}, fmt.Errorf("read recorded transfer request: %w", err)
	}
	q, code, accepted := parseQuery(packet)
	if !accepted || code != lookup.Success || !q.isTransfer() {
		return transfer.Candidate{}, fmt.Errorf("trace does not start with a valid transfer request")
	}
	if base != nil && q.request.Origin != base.Origin() {
		return transfer.Candidate{}, fmt.Errorf("trace origin %s differs from base %s", q.request.Origin, base.Origin())
	}
	receiver, err := transfer.NewReceiver(q.request, base)
	if err != nil {
		return transfer.Candidate{}, err
	}
	stream := replyStream{receiver: receiver, id: q.id, question: q.question}
	for !receiver.Done() {
		reply, err := readFrame(r)
		if err != nil {
			return transfer.Candidate{}, fmt.Errorf("recorded reply frame %d before terminal SOA: %w", stream.frames+1, err)
		}
		if err := stream.feed(reply); err != nil {
			return transfer.Candidate{}, err
		}
	}
	var trailer [1]byte
	if n, err := io.ReadFull(r, trailer[:]); n != 0 || !errors.Is(err, io.EOF) {
		return transfer.Candidate{}, fmt.Errorf("attempted to read beyond trace terminal SOA: got %d bytes, error %v", n, err)
	}
	return receiver.Finish()
}
