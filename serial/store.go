package serial

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"labelreef/zone"
)

const MaxStateBytes = 128 << 20

type stateV1 struct {
	Version    int         `json:"version"`
	Generation uint64      `json:"generation"`
	Zone       zone.FileV1 `json:"zone"`
	History    []deltaV1   `json:"history"`
}

type deltaV1 struct {
	Before  zone.RecordV1   `json:"before"`
	After   zone.RecordV1   `json:"after"`
	Deletes []zone.RecordV1 `json:"deletes"`
	Adds    []zone.RecordV1 `json:"adds"`
}

type PublishPoint struct {
	Origin     string
	Generation uint64
	Serial     uint32
}

type Store struct {
	Path          string
	BeforePublish func(PublishPoint) error
}

// Result indicates whether the atomic replacement took place. A directory sync
// error after rename leaves a visible commit whose crash durability is uncertain.
type Result struct {
	Published bool
	Err       error
}

func (s Store) Load(origin string) (*Snapshot, error) {
	f, err := os.Open(s.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	snapshot, err := DecodeState(f)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", s.Path, err)
	}
	if snapshot.Current().Origin() != origin {
		return nil, fmt.Errorf("%s contains state for %s, expected %s", s.Path, snapshot.Current().Origin(), origin)
	}
	return snapshot, nil
}

// Staged is a fully written candidate state file that has not yet replaced its
// destination. Prepare runs the publication hook; Commit makes the candidate
// visible with one rename; Abort removes an unused candidate.
type Staged struct {
	path   string
	temp   string
	digest string
	point  PublishPoint
	hook   func(PublishPoint) error
}

func (s Staged) Origin() string { return s.point.Origin }

func (s Store) Stage(snapshot *Snapshot) (*Staged, error) {
	if snapshot == nil || snapshot.Current() == nil {
		return nil, fmt.Errorf("cannot persist an empty snapshot")
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, ".labelreef-*")
	if err != nil {
		return nil, err
	}
	temp := f.Name()
	discard := func(err error) (*Staged, error) {
		f.Close()
		os.Remove(temp)
		return nil, err
	}
	writer := &stateWriter{file: f, remaining: MaxStateBytes}
	if err := EncodeState(writer, snapshot); err != nil {
		return discard(err)
	}
	if err := f.Sync(); err != nil {
		return discard(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(temp)
		return nil, err
	}
	digest, err := fileDigest(temp)
	if err != nil {
		os.Remove(temp)
		return nil, err
	}
	z := snapshot.Current()
	return &Staged{
		path: s.Path, temp: temp, digest: digest, hook: s.BeforePublish,
		point: PublishPoint{Origin: z.Origin(), Generation: snapshot.Generation(), Serial: z.Serial()},
	}, nil
}

func (s *Staged) Prepare() error {
	if s == nil || s.hook == nil {
		return nil
	}
	if err := s.hook(s.point); err != nil {
		return fmt.Errorf("before publishing %s: %w", s.point.Origin, err)
	}
	return nil
}

func (s *Staged) Commit() Result {
	if s == nil || s.temp == "" {
		return Result{Err: fmt.Errorf("candidate state is unavailable")}
	}
	if err := os.Rename(s.temp, s.path); err != nil {
		return Result{Err: err}
	}
	s.temp = ""
	return Result{Published: true, Err: syncDirectory(filepath.Dir(s.path))}
}

func (s *Staged) Abort() {
	if s == nil || s.temp == "" {
		return
	}
	os.Remove(s.temp)
	s.temp = ""
}

func (s Store) Save(snapshot *Snapshot) Result {
	staged, err := s.Stage(snapshot)
	if err != nil {
		return Result{Err: err}
	}
	defer staged.Abort()
	if err := staged.Prepare(); err != nil {
		return Result{Err: err}
	}
	return staged.Commit()
}

type stateWriter struct {
	file      *os.File
	remaining int
}

func (w *stateWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, fmt.Errorf("state exceeds %d bytes", MaxStateBytes)
	}
	n, err := w.file.Write(p)
	w.remaining -= n
	return n, err
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func encodeRows(records []zone.Record) []zone.RecordV1 {
	rows := make([]zone.RecordV1, 0, len(records))
	for _, record := range records {
		rows = append(rows, zone.RecordToV1(record))
	}
	return rows
}

func EncodeState(w io.Writer, snapshot *Snapshot) error {
	value := stateV1{
		Version: 1, Generation: snapshot.Generation(),
		Zone: snapshot.Current().V1(), History: make([]deltaV1, 0, len(snapshot.deltas)),
	}
	for _, delta := range snapshot.deltas {
		value.History = append(value.History, deltaV1{
			Before: zone.RecordToV1(delta.Before), After: zone.RecordToV1(delta.After),
			Deletes: encodeRows(delta.Deletes), Adds: encodeRows(delta.Adds),
		})
	}
	return zone.EncodeJSON(w, value)
}

func DecodeState(r io.Reader) (*Snapshot, error) {
	var value stateV1
	if err := zone.DecodeJSON(r, MaxStateBytes, &value); err != nil {
		return nil, err
	}
	if value.Version != 1 || value.Generation == 0 {
		return nil, fmt.Errorf("invalid state version or generation")
	}
	z, err := value.Zone.Zone()
	if err != nil {
		return nil, err
	}
	replay := NewReplay(z)
	history := make([]JournalDelta, len(value.History))
	for i := len(history) - 1; i >= 0; i-- {
		d, err := value.History[i].delta(z.Origin())
		if err == nil {
			err = replay.apply(d, true)
		}
		if err != nil {
			return nil, fmt.Errorf("state history %d: %w", i+1, err)
		}
		history[i] = d
	}
	if len(history) > 0 {
		if _, err := replay.Zone(); err != nil {
			return nil, fmt.Errorf("oldest retained zone: %w", err)
		}
	}
	if retainedStart(history, z.Serial(), len(history)) != 0 {
		return nil, fmt.Errorf("state history has ambiguous serials")
	}
	return makeSnapshot(z, value.Generation, history), nil
}

func (row deltaV1) delta(origin string) (JournalDelta, error) {
	before, err := row.Before.Record(origin)
	if err != nil {
		return JournalDelta{}, err
	}
	after, err := row.After.Record(origin)
	if err != nil {
		return JournalDelta{}, err
	}
	deletes, err := parseEditRows(origin, row.Deletes)
	if err != nil {
		return JournalDelta{}, err
	}
	adds, err := parseEditRows(origin, row.Adds)
	if err != nil {
		return JournalDelta{}, err
	}
	return JournalDelta{Before: before, After: after, Deletes: deletes, Adds: adds}, nil
}
