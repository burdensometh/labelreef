package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"labelreef/reload"
	"labelreef/serve"
	"labelreef/transfer"
	"labelreef/zone"
)

func xfrCommand(ctx context.Context, args []string, out, stderr io.Writer) error {
	flags := flag.NewFlagSet("xfr", flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("address", "", "numeric loopback DNS IP:port")
	basePath := flags.String("base", "", "v1 receiver zone (requests IXFR)")
	trace := flags.String("trace", "", "write a new v1 transfer recording")
	timeout := flags.Duration("timeout", 15*time.Second, "total transfer timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 || *timeout <= 0 || *timeout > 5*time.Minute {
		return fmt.Errorf("%w: xfr requires ORIGIN and a positive bounded timeout", errUsage)
	}
	address, err := reload.Loopback(*target)
	if err != nil {
		return err
	}
	origin, err := zone.Name(flags.Arg(0))
	if err != nil {
		return err
	}
	base, err := loadBase(*basePath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	client := serve.Client{IOTimeout: min(3*time.Second, *timeout)}
	var result transfer.Candidate
	if *trace == "" {
		result, err = client.Fetch(ctx, address, origin, base)
	} else {
		result, err = writeCapture(*trace, func(out io.Writer) (transfer.Candidate, error) {
			return client.Capture(ctx, address, origin, base, out)
		})
	}
	if err != nil {
		return err
	}
	return zone.EncodeV1(out, result.Zone)
}

func replayCommand(args []string, out, stderr io.Writer) error {
	flags := flag.NewFlagSet("replay", flag.ContinueOnError)
	flags.SetOutput(stderr)
	basePath := flags.String("base", "", "v1 receiver zone for an IXFR trace")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("%w: replay requires exactly one trace file", errUsage)
	}
	base, err := loadBase(*basePath)
	if err != nil {
		return err
	}
	file, err := os.Open(flags.Arg(0))
	if err != nil {
		return err
	}
	defer file.Close()
	result, err := serve.ReplayTrace(file, base)
	if err != nil {
		return err
	}
	return zone.EncodeV1(out, result.Zone)
}

func loadBase(path string) (*zone.ZoneVersion, error) {
	if path == "" {
		return nil, nil
	}
	base, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer base.Close()
	return zone.DecodeV1(base)
}

// writeCapture leaves the destination untouched on failed or incomplete transfers.
func writeCapture(path string, record func(io.Writer) (transfer.Candidate, error)) (transfer.Candidate, error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".labelreef-trace-*")
	if err != nil {
		return transfer.Candidate{}, err
	}
	defer os.Remove(file.Name())
	result, err := record(file)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return transfer.Candidate{}, err
	}
	if closeErr != nil {
		return transfer.Candidate{}, closeErr
	}
	if err := os.Link(file.Name(), path); err != nil {
		return transfer.Candidate{}, fmt.Errorf("publish new trace: %w", err)
	}
	return result, nil
}
