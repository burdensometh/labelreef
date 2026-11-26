package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"labelreef/reload"
	"labelreef/serve"
	"labelreef/zone"
)

func queryCommand(ctx context.Context, args []string, out, stderr io.Writer) error {
	flags := flag.NewFlagSet("query", flag.ContinueOnError)
	flags.SetOutput(stderr)
	address := flags.String("address", "", "numeric loopback DNS IP:port")
	tcp := flags.Bool("tcp", false, "query over TCP")
	retry := flags.Bool("retry-tcp", true, "repeat a truncated UDP answer over TCP")
	edns := flags.Uint("edns", 0, "advertised UDP bytes (zero disables EDNS)")
	timeout := flags.Duration("timeout", 3*time.Second, "total DNS query timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 2 || *edns > 65535 || *timeout <= 0 || *timeout > time.Minute {
		return fmt.Errorf("%w: query requires NAME TYPE and valid EDNS and timeout values", errUsage)
	}
	remote, err := reload.Loopback(*address)
	if err != nil {
		return err
	}
	t, err := zone.ParseType(flags.Arg(1))
	if err != nil {
		return err
	}
	result, err := serve.Probe(ctx, flags.Arg(0), t, serve.ProbeOptions{
		Address: remote, TCP: *tcp, RetryTCP: *retry, EDNSSize: uint16(*edns), Timeout: *timeout,
	})
	if err != nil {
		return err
	}
	return zone.EncodeJSON(out, result)
}

type zoneSummary struct {
	Format  int    `json:"format"`
	Origin  string `json:"origin"`
	Serial  uint32 `json:"serial"`
	Records int    `json:"records"`
	Nodes   int    `json:"nodes"`
}

func zoneCommand(command string, args []string, out, stderr io.Writer) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	format := flags.String("format", "v1", "zone output format: v1 or v2")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("%w: %s requires exactly one zone file", errUsage, command)
	}
	file, err := os.Open(flags.Arg(0))
	if err != nil {
		return err
	}
	defer file.Close()
	version, sourceFormat, err := zone.DecodeZone(file)
	if err != nil {
		return err
	}
	if command == "rewrite" {
		encode, err := zoneEncoder(*format)
		if err != nil {
			return err
		}
		return encode(out, version)
	}
	return zone.EncodeJSON(out, zoneSummary{
		Format: sourceFormat, Origin: version.Origin(), Serial: version.Serial(),
		Records: version.RecordCount(), Nodes: version.NodeCount(),
	})
}
