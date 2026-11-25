package main

import (
	"fmt"
	"io"
	"os"

	"labelreef/serial"
	"labelreef/zone"
)

type comparison struct {
	Origin      string          `json:"origin"`
	LeftSerial  uint32          `json:"left_serial"`
	RightSerial uint32          `json:"right_serial"`
	LeftHash    string          `json:"left_fingerprint"`
	RightHash   string          `json:"right_fingerprint"`
	Equal       bool            `json:"equal"`
	Removes     []zone.RecordV1 `json:"removes"`
	Adds        []zone.RecordV1 `json:"adds"`
}

func compareZones(args []string, out io.Writer) error {
	if len(args) != 2 || args[0] == "" || args[1] == "" {
		return fmt.Errorf("%w: compare requires left and right zone files", errUsage)
	}
	left, err := loadBase(args[0])
	if err != nil {
		return fmt.Errorf("read left zone: %w", err)
	}
	right, err := loadBase(args[1])
	if err != nil {
		return fmt.Errorf("read right zone: %w", err)
	}
	diff, err := zone.Diff(left, right)
	if err != nil {
		return err
	}
	result := comparison{
		Origin: left.Origin(), LeftSerial: left.Serial(), RightSerial: right.Serial(),
		LeftHash: left.Fingerprint(), RightHash: right.Fingerprint(),
		Equal:   len(diff.Removes) == 0 && len(diff.Adds) == 0,
		Removes: recordRows(diff.Removes), Adds: recordRows(diff.Adds),
	}
	return zone.EncodeJSON(out, result)
}

func recordRows(records []zone.Record) []zone.RecordV1 {
	out := make([]zone.RecordV1, 0, len(records))
	for _, record := range records {
		out = append(out, zone.RecordToV1(record))
	}
	return out
}

func showState(args []string, out io.Writer) error {
	if len(args) != 1 {
		return fmt.Errorf("%w: state requires a v1 state file", errUsage)
	}
	file, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer file.Close()
	snapshot, err := serial.DecodeState(file)
	if err != nil {
		return err
	}
	return zone.EncodeJSON(out, snapshot.Inventory())
}
