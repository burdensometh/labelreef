package serve

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"labelreef/serial"
	"labelreef/transfer"
	"labelreef/zone"
)

func TestCaptureReplayAndIncompleteTrace(t *testing.T) {
	initial := exampleZone(t)
	s := testServer(t, fixtureResolver{initial}, nil)
	client := Client{IOTimeout: time.Second}
	var buffer bytes.Buffer
	got, err := client.Capture(context.Background(), s.Address(), initial.Origin(), nil, &buffer)
	if err != nil || got.Kind != transfer.Full || !serial.Same(got.Zone, initial) {
		t.Fatalf("captured live AXFR: %+v %v", got, err)
	}
	replay, err := ReplayTrace(bytes.NewReader(buffer.Bytes()), nil)
	if err != nil || !serial.Same(replay.Zone, got.Zone) {
		t.Fatalf("trace replay: %+v %v", replay, err)
	}
	for _, fixture := range [][]byte{
		buffer.Bytes()[:buffer.Len()-1],
		append(append([]byte(nil), buffer.Bytes()...), 0x00),
		[]byte("unsupported trace"),
	} {
		candidate, err := ReplayTrace(bytes.NewReader(fixture), nil)
		if err == nil || candidate.Zone != nil {
			t.Fatalf("accepted damaged trace: %+v %v", candidate, err)
		}
	}
	var minimal bytes.Buffer
	got, err = client.Capture(context.Background(), s.Address(), initial.Origin(), initial, &minimal)
	if err != nil || got.Kind != transfer.Unchanged {
		t.Fatalf("captured unchanged IXFR: %+v %v", got, err)
	}
	check, err := ReplayTrace(&minimal, initial)
	if err != nil || check.Kind != transfer.Unchanged || !serial.Same(check.Zone, initial) {
		t.Fatalf("replayed unchanged IXFR: %+v %v", check, err)
	}
	if got, err := client.Capture(context.Background(), s.Address(), initial.Origin(), nil, shortOutput{}); err == nil || got.Zone != nil {
		t.Fatalf("trace accepted a failed writer: %+v %v", got, err)
	}
}

type shortOutput struct{}

func (shortOutput) Write([]byte) (int, error) { return 0, io.ErrShortWrite }

func TestEscapedOwnerThroughWire(t *testing.T) {
	z := exampleZone(t)
	exact := `field\046unit.lab.test.`
	record, err := zone.ParseRecord(z.Origin(), exact, 120, zone.A, "192.0.2.64")
	if err != nil {
		t.Fatal(err)
	}
	z, err = zone.New(z.Origin(), append(z.Records(), record))
	if err != nil {
		t.Fatal(err)
	}
	s := testServer(t, fixtureResolver{z}, nil)
	answer, err := Probe(context.Background(), `Field\.Unit.lab.test.`, zone.A, ProbeOptions{
		Address: s.Address(), Timeout: 2 * time.Second,
	})
	if err != nil || len(answer.Answer) != 1 || answer.Answer[0].Name != exact ||
		answer.Answer[0].Data != "192.0.2.64" {
		t.Fatalf("escaped DNS label lost in transport: %+v %v", answer, err)
	}
}
