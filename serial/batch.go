package serial

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"labelreef/zone"
)

// MaxBatchMembers bounds one atomic publication. It matches the configured
// zone limit, since every member must be a distinct configured origin.
const MaxBatchMembers = 256

// BatchEditV1 applies sibling edits in one publication. Every member carries
// its own base and next serial; no member shares a serial with another.
type BatchEditV1 struct {
	Version int
	Edits   []EditV1
}

// DecodeBatchEdit preserves the explicit base and next serials of each member.
func DecodeBatchEdit(r io.Reader) (BatchEditV1, error) {
	var fields struct {
		Version int               `json:"version"`
		Edits   []json.RawMessage `json:"edits"`
	}
	if err := zone.DecodeJSON(r, zone.MaxV1Bytes, &fields); err != nil {
		return BatchEditV1{}, err
	}
	if fields.Version != 1 {
		return BatchEditV1{}, fmt.Errorf("unsupported batch edit version %d", fields.Version)
	}
	if len(fields.Edits) == 0 {
		return BatchEditV1{}, fmt.Errorf("batch requires at least one edit")
	}
	if len(fields.Edits) > MaxBatchMembers {
		return BatchEditV1{}, fmt.Errorf("batch exceeds %d edits", MaxBatchMembers)
	}
	batch := BatchEditV1{Version: fields.Version, Edits: make([]EditV1, 0, len(fields.Edits))}
	for i, raw := range fields.Edits {
		edit, err := DecodeEdit(bytes.NewReader(raw))
		if err != nil {
			return BatchEditV1{}, fmt.Errorf("batch edit %d: %w", i+1, err)
		}
		batch.Edits = append(batch.Edits, edit)
	}
	return batch, nil
}

// Expand validates every base against its active zone and computes each
// candidate independently. It returns no candidate if any member disagrees, so
// a batch never contains an applied subset.
func (b BatchEditV1) Expand(current map[string]*Snapshot) (map[string]*zone.ZoneVersion, error) {
	if b.Version != 1 {
		return nil, fmt.Errorf("unsupported batch edit version %d", b.Version)
	}
	if len(b.Edits) == 0 || len(b.Edits) > MaxBatchMembers {
		return nil, fmt.Errorf("batch requires between 1 and %d edits", MaxBatchMembers)
	}
	result := make(map[string]*zone.ZoneVersion, len(b.Edits))
	for i, edit := range b.Edits {
		name, err := zone.Name(edit.Origin)
		if err != nil {
			return nil, fmt.Errorf("batch edit %d: %w", i+1, err)
		}
		if _, duplicate := result[name]; duplicate {
			return nil, fmt.Errorf("batch edit %d repeats %s", i+1, name)
		}
		base := current[name]
		if base == nil || base.Current() == nil {
			return nil, fmt.Errorf("batch edit %d: %w: %s", i+1, ErrUnknownOrigin, name)
		}
		next, err := edit.Apply(base.Current())
		if err != nil {
			return nil, fmt.Errorf("batch edit %d (%s): %w", i+1, name, err)
		}
		result[name] = next
	}
	return result, nil
}

// ErrUnknownOrigin separates an origin missing from the active table from a
// malformed edit. Reload maps the former to its own not-configured error.
var ErrUnknownOrigin = errors.New("zone is not active")

// BatchItem binds one origin to a fully written candidate state file.
type BatchItem struct {
	Origin string
	Staged *Staged
}

const batchJournalName = ".labelreef-batch.json"

type batchJournalV1 struct {
	Version int             `json:"version"`
	Members []batchMemberV1 `json:"members"`
}

type batchMemberV1 struct {
	Origin      string `json:"origin"`
	Path        string `json:"path"`
	Next        string `json:"next"`
	Previous    string `json:"previous,omitempty"`
	HadPrevious bool   `json:"had_previous"`
	NewDigest   string `json:"new_digest"`
	OldDigest   string `json:"old_digest,omitempty"`
}

// CommitBatch publishes all staged candidates with a durable intent record.
// Any interruption leaves a journal that RecoverBatch resolves to either every
// prior file or every candidate file, never a mixture.
func CommitBatch(dir string, items []BatchItem) Result {
	if len(items) == 0 {
		return Result{Err: fmt.Errorf("batch requires at least one member")}
	}
	if len(items) > MaxBatchMembers {
		return Result{Err: fmt.Errorf("batch exceeds %d members", MaxBatchMembers)}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return Result{Err: err}
	}
	journal := batchJournalV1{Version: 1}
	origins := make(map[string]bool, len(items))
	paths := make(map[string]bool, len(items))
	abortAll := func(journal batchJournalV1) {
		for _, item := range items {
			item.Staged.Abort()
		}
		for _, member := range journal.Members {
			if member.Previous != "" {
				os.Remove(member.Previous)
			}
		}
	}
	for _, item := range items {
		if item.Staged == nil || item.Staged.temp == "" || item.Staged.path == "" {
			abortAll(journal)
			return Result{Err: fmt.Errorf("batch member %s has no staged candidate", item.Origin)}
		}
		if origins[item.Origin] || paths[item.Staged.path] {
			abortAll(journal)
			return Result{Err: fmt.Errorf("batch repeats origin %s", item.Origin)}
		}
		origins[item.Origin] = true
		paths[item.Staged.path] = true
		if filepath.Dir(item.Staged.path) != dir {
			abortAll(journal)
			return Result{Err: fmt.Errorf("batch member %s is outside the state directory", item.Origin)}
		}
		member := batchMemberV1{
			Origin: item.Origin, Path: item.Staged.path, Next: item.Staged.temp,
			NewDigest: item.Staged.digest,
		}
		backup, hadPrevious, digest, err := backupState(dir, item.Staged.path)
		if err != nil {
			abortAll(journal)
			return Result{Err: fmt.Errorf("backup %s: %w", item.Origin, err)}
		}
		if hadPrevious {
			member.Previous, member.OldDigest = backup, digest
		}
		member.HadPrevious = hadPrevious
		journal.Members = append(journal.Members, member)
	}

	if err := writeBatchJournal(dir, journal); err != nil {
		abortAll(journal)
		return Result{Err: err}
	}

	var renameErr error
	for _, member := range journal.Members {
		if err := os.Rename(member.Next, member.Path); err != nil {
			renameErr = fmt.Errorf("install %s: %w", member.Origin, err)
			break
		}
	}
	if renameErr != nil {
		// Resolve the journal to one side before reporting the failure. If the
		// journal already showed every candidate installed, the batch stands.
		committed, err := recoverBatch(dir, journal)
		if err != nil {
			return Result{Err: fmt.Errorf("%w; rollback left journal for restart recovery: %v", renameErr, err)}
		}
		if committed {
			return Result{Published: true}
		}
		abortAll(journal)
		return Result{Err: renameErr}
	}

	syncErr := finishBatch(dir, journal)
	return Result{Published: true, Err: syncErr}
}

// RecoverBatch resolves an interrupted batch left in dir. A missing journal is
// a no-op. It is safe to call before any state file is loaded.
func RecoverBatch(dir string) error {
	journal, err := readBatchJournal(dir)
	if err != nil || journal == nil {
		return err
	}
	_, err = recoverBatch(dir, *journal)
	return err
}

// recoverBatch resolves the journal to either the complete batch or the prior
// files and reports which side it chose.
func recoverBatch(dir string, journal batchJournalV1) (bool, error) {
	allNew := true
	states := make([]bool, len(journal.Members))
	for i, member := range journal.Members {
		if err := checkMemberPath(dir, member.Path); err != nil {
			return false, err
		}
		digest, exists, err := stateDigest(member.Path)
		if err != nil {
			return false, err
		}
		states[i] = exists && digest == member.NewDigest
		allNew = allNew && states[i]
	}
	if allNew {
		return true, finishBatch(dir, journal)
	}
	for _, member := range journal.Members {
		if member.Next != "" {
			if err := checkMemberPath(dir, member.Next); err != nil {
				return false, err
			}
			os.Remove(member.Next)
		}
	}
	for i, member := range journal.Members {
		if states[i] {
			// The new bytes reached this member; put the prior bytes back.
			if !member.HadPrevious {
				if err := os.Remove(member.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return false, err
				}
				continue
			}
			if err := checkMemberPath(dir, member.Previous); err != nil {
				return false, err
			}
			if err := os.Rename(member.Previous, member.Path); err != nil {
				return false, err
			}
			continue
		}
		if member.Previous != "" {
			if err := checkMemberPath(dir, member.Previous); err == nil {
				os.Remove(member.Previous)
			}
		}
	}
	if err := removeBatchJournal(dir); err != nil {
		return false, err
	}
	return false, nil
}

func finishBatch(dir string, journal batchJournalV1) error {
	for _, member := range journal.Members {
		for _, path := range []string{member.Previous, member.Next} {
			if path == "" {
				continue
			}
			if err := checkMemberPath(dir, path); err == nil {
				os.Remove(path)
			}
		}
	}
	if err := removeBatchJournal(dir); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func backupState(dir, path string) (string, bool, string, error) {
	src, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, "", nil
	}
	if err != nil {
		return "", false, "", err
	}
	defer src.Close()
	f, err := os.CreateTemp(dir, ".labelreef-prev-*")
	if err != nil {
		return "", false, "", err
	}
	temp := f.Name()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), src); err != nil {
		f.Close()
		os.Remove(temp)
		return "", false, "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(temp)
		return "", false, "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(temp)
		return "", false, "", err
	}
	return temp, true, hex.EncodeToString(h.Sum(nil)), nil
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func stateDigest(path string) (string, bool, error) {
	digest, err := fileDigest(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false, nil
	}
	return digest, err == nil, err
}

func writeBatchJournal(dir string, journal batchJournalV1) error {
	f, err := os.CreateTemp(dir, ".labelreef-journal-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	if err := zone.EncodeJSON(f, journal); err != nil {
		f.Close()
		os.Remove(temp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(temp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(temp)
		return err
	}
	if err := os.Rename(temp, filepath.Join(dir, batchJournalName)); err != nil {
		os.Remove(temp)
		return err
	}
	return syncDirectory(dir)
}

func readBatchJournal(dir string) (*batchJournalV1, error) {
	f, err := os.Open(filepath.Join(dir, batchJournalName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var journal batchJournalV1
	if err := zone.DecodeJSON(f, MaxStateBytes, &journal); err != nil {
		return nil, fmt.Errorf("read batch journal: %w", err)
	}
	if journal.Version != 1 || len(journal.Members) == 0 || len(journal.Members) > MaxBatchMembers {
		return nil, fmt.Errorf("invalid batch journal")
	}
	for _, member := range journal.Members {
		if member.Origin == "" || member.Path == "" || member.Next == "" || member.NewDigest == "" {
			return nil, fmt.Errorf("invalid batch journal member")
		}
	}
	return &journal, nil
}

func removeBatchJournal(dir string) error {
	path := filepath.Join(dir, batchJournalName)
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func checkMemberPath(dir, path string) error {
	if filepath.Dir(path) != dir {
		return fmt.Errorf("batch journal path %s is outside the state directory", path)
	}
	return nil
}
