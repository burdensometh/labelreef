package serial

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"labelreef/zone"
)

func batchFrom(t testing.TB, path string) BatchEditV1 {
	t.Helper()
	f, err := os.Open(filepath.Join("../examples/edits", path))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	batch, err := DecodeBatchEdit(f)
	if err != nil {
		t.Fatal(err)
	}
	return batch
}

func zoneFixture(t testing.TB, path string) *zone.ZoneVersion {
	t.Helper()
	f, err := os.Open("../examples/zones/" + path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := zone.DecodeV1(f)
	if err != nil {
		t.Fatal(err)
	}
	return z
}

func sortedKeys(m map[string]*zone.ZoneVersion) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func statePathFor(dir, origin string) string {
	return filepath.Join(dir, strings.ReplaceAll(strings.TrimSuffix(origin, "."), ".", "_")+".json")
}

func writeFile(t testing.TB, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeBatchEditRequiresPerMemberSerials(t *testing.T) {
	if _, err := DecodeBatchEdit(strings.NewReader(`{"version":1,"edits":[]}`)); err == nil {
		t.Fatal("accepted an empty batch")
	}
	if _, err := DecodeBatchEdit(strings.NewReader(`{"version":1,"edits":[{"version":1}]}`)); err == nil {
		t.Fatal("accepted a member without serials")
	}
	if _, err := DecodeBatchEdit(strings.NewReader(`{"version":1,"edits":[{"version":1,"base":null,"next":1}]}`)); err == nil {
		t.Fatal("accepted a null base")
	}
	batch, err := DecodeBatchEdit(strings.NewReader(`{"version":1,"edits":[
		{"version":1,"origin":"lab.test.","base":4294967295,"next":0},
		{"version":1,"origin":"child.lab.test.","base":17,"next":18}]}`))
	if err != nil || len(batch.Edits) != 2 || batch.Edits[0].Base != ^uint32(0) || batch.Edits[1].Base != 17 {
		t.Fatalf("member serials were lost: %+v %v", batch, err)
	}
	if _, err := DecodeBatchEdit(strings.NewReader(`{"version":1,"edits":[],"extra":true}`)); err == nil {
		t.Fatal("accepted an unknown field")
	}
}

func TestBatchBaseMismatchRejectsBothMembers(t *testing.T) {
	parent := zoneFixture(t, "lab-v1.json")
	child := zoneFixture(t, "child-v1.json")
	current := map[string]*Snapshot{parent.Origin(): Seed(parent), child.Origin(): Seed(child)}

	good := batchFrom(t, "batch-parent-child.json")
	candidates, err := good.Expand(current)
	if err != nil || len(candidates) != 2 {
		t.Fatalf("valid batch: %v", err)
	}
	// The child's base names serial 16 while its active serial is 17.
	stale := batchFrom(t, "batch-stale-child.json")
	if _, err := stale.Expand(current); err == nil {
		t.Fatal("accepted a batch whose child base disagrees")
	}
	// Re-expanding the valid batch over the same bases must still succeed:
	// expansion has no side effects.
	if _, err := good.Expand(current); err != nil {
		t.Fatalf("batch expansion mutated state: %v", err)
	}
}

func TestCommitBatchInstallsBothMembers(t *testing.T) {
	dir := t.TempDir()
	parent := zoneFixture(t, "lab-v1.json")
	child := zoneFixture(t, "child-v1.json")
	batch := batchFrom(t, "batch-parent-child.json")
	current := map[string]*Snapshot{parent.Origin(): Seed(parent), child.Origin(): Seed(child)}
	next, err := batch.Expand(current)
	if err != nil {
		t.Fatal(err)
	}

	batchItems := make([]BatchItem, 0, 2)
	for _, origin := range sortedKeys(next) {
		store := Store{Path: statePathFor(dir, origin)}
		staged, err := store.Stage(mustAdvanceFrom(t, current[origin], next[origin]))
		if err != nil {
			t.Fatal(err)
		}
		batchItems = append(batchItems, BatchItem{Origin: origin, Staged: staged})
	}
	// Both state files must be fully written before CommitBatch runs.
	for _, item := range batchItems {
		if _, err := os.Stat(item.Staged.temp); err != nil {
			t.Fatalf("candidate for %s is not written: %v", item.Origin, err)
		}
	}

	if result := CommitBatch(dir, batchItems); !result.Published || result.Err != nil {
		t.Fatalf("commit batch: %+v", result)
	}
	if err := RecoverBatch(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".labelreef") {
			t.Fatalf("batch left temporary file %s", entry.Name())
		}
	}
	for _, origin := range sortedKeys(next) {
		store := Store{Path: statePathFor(dir, origin)}
		loaded, err := store.Load(origin)
		if err != nil {
			t.Fatal(err)
		}
		if !Same(loaded.Current(), next[origin]) {
			t.Fatalf("%s did not advance to the candidate", origin)
		}
	}
}

func mustAdvanceFrom(t testing.TB, base *Snapshot, target *zone.ZoneVersion) *Snapshot {
	t.Helper()
	snap, err := Advance(base, target, nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

// interruptedBatch models a crash after the journal is durable but before both
// renames complete. It persists each prior state file first, so a rollback has
// prior bytes to restore, then optionally installs the first member.
func interruptedBatch(t testing.TB, dir string) (next, prior map[string]*zone.ZoneVersion, items []BatchItem) {
	t.Helper()
	parent := zoneFixture(t, "lab-v1.json")
	child := zoneFixture(t, "child-v1.json")
	next, err := batchFrom(t, "batch-parent-child.json").Expand(
		map[string]*Snapshot{parent.Origin(): Seed(parent), child.Origin(): Seed(child)})
	if err != nil {
		t.Fatal(err)
	}
	prior = map[string]*zone.ZoneVersion{parent.Origin(): parent, child.Origin(): child}
	for _, origin := range sortedKeys(next) {
		store := Store{Path: statePathFor(dir, origin)}
		if result := store.Save(Seed(prior[origin])); !result.Published || result.Err != nil {
			t.Fatalf("persist prior %s: %+v", origin, result)
		}
		staged, err := store.Stage(mustAdvanceFrom(t, Seed(prior[origin]), next[origin]))
		if err != nil {
			t.Fatal(err)
		}
		if err := staged.Prepare(); err != nil {
			t.Fatal(err)
		}
		items = append(items, BatchItem{Origin: origin, Staged: staged})
	}
	if err := writeTestJournal(t, dir, testJournal(t, dir, items)); err != nil {
		t.Fatal(err)
	}
	return next, prior, items
}

func install(t testing.TB, item BatchItem) {
	t.Helper()
	if _, err := os.Stat(item.Staged.temp); errors.Is(err, os.ErrNotExist) {
		return
	}
	if err := os.Rename(item.Staged.temp, item.Staged.path); err != nil {
		t.Fatal(err)
	}
}

func parentOrChild(t testing.TB, origin string, parent, child *zone.ZoneVersion) *zone.ZoneVersion {
	if origin == parent.Origin() {
		return parent
	}
	if origin == child.Origin() {
		return child
	}
	t.Fatalf("unexpected origin %s", origin)
	return nil
}

func testJournal(t testing.TB, dir string, items []BatchItem) batchJournalV1 {
	t.Helper()
	journal := batchJournalV1{Version: 1}
	for _, item := range items {
		member := batchMemberV1{
			Origin: item.Origin, Path: item.Staged.path, Next: item.Staged.temp,
			NewDigest: item.Staged.digest,
		}
		backup, hadPrevious, digest, err := backupState(dir, item.Staged.path)
		if err != nil {
			t.Fatal(err)
		}
		if hadPrevious {
			member.Previous, member.OldDigest = backup, digest
		}
		member.HadPrevious = hadPrevious
		journal.Members = append(journal.Members, member)
	}
	return journal
}

func writeTestJournal(t testing.TB, dir string, journal batchJournalV1) error {
	t.Helper()
	data, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	return os.WriteFile(filepath.Join(dir, batchJournalName), data, 0600)
}

func TestRecoverBatchRollsForwardCompletedBatch(t *testing.T) {
	dir := t.TempDir()
	_, _, items := interruptedBatch(t, dir)
	install(t, items[0])
	install(t, items[1])
	if err := RecoverBatch(dir); err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		store := Store{Path: item.Staged.path}
		loaded, err := store.Load(item.Origin)
		if err != nil || loaded == nil {
			t.Fatalf("load %s: %v", item.Origin, err)
		}
		// The completed batch must not be rolled back; the first member is
		// at its candidate generation and the reader still validates it.
		if loaded.Generation() != 2 {
			t.Fatalf("%s lost the installed candidate generation: %d", item.Origin, loaded.Generation())
		}
	}
	if _, err := os.Stat(filepath.Join(dir, batchJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal survived roll forward: %v", err)
	}
}

func TestRecoverBatchRollsBackPartialBatch(t *testing.T) {
	dir := t.TempDir()
	_, prior, items := interruptedBatch(t, dir)
	install(t, items[0])
	if err := RecoverBatch(dir); err != nil {
		t.Fatal(err)
	}
	for _, origin := range sortedKeys(prior) {
		store := Store{Path: statePathFor(dir, origin)}
		loaded, err := store.Load(origin)
		if err != nil || loaded == nil {
			t.Fatalf("load %s: %v", origin, err)
		}
		if !Same(loaded.Current(), prior[origin]) {
			t.Fatalf("%s did not return to its prior zone", origin)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, batchJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal survived roll back: %v", err)
	}
}

func TestRecoverBatchDoesNotResurrectAbsentPriorFile(t *testing.T) {
	dir := t.TempDir()
	parent := zoneFixture(t, "lab-v1.json")
	child := zoneFixture(t, "child-v1.json")
	next, err := batchFrom(t, "batch-parent-child.json").Expand(
		map[string]*Snapshot{parent.Origin(): Seed(parent), child.Origin(): Seed(child)})
	if err != nil {
		t.Fatal(err)
	}
	origins := sortedKeys(next)
	items := make([]BatchItem, 0, len(origins))
	for _, origin := range origins {
		store := Store{Path: statePathFor(dir, origin)}
		staged, err := store.Stage(mustAdvanceFrom(t, Seed(parentOrChild(t, origin, parent, child)), next[origin]))
		if err != nil {
			t.Fatal(err)
		}
		if err := staged.Prepare(); err != nil {
			t.Fatal(err)
		}
		items = append(items, BatchItem{Origin: origin, Staged: staged})
	}
	if err := writeTestJournal(t, dir, testJournal(t, dir, items)); err != nil {
		t.Fatal(err)
	}
	// Only the first member is installed; there is no prior file to restore.
	install(t, items[0])
	if err := RecoverBatch(dir); err != nil {
		t.Fatal(err)
	}
	for _, item := range items {
		if _, err := os.Stat(item.Staged.path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s has bytes after rolling back a batch with no prior state", item.Origin)
		}
	}
}

func TestRecoverBatchIgnoresMissingJournal(t *testing.T) {
	dir := t.TempDir()
	if err := RecoverBatch(dir); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverBatchRejectsJournalOutsideStateDirectory(t *testing.T) {
	dir := t.TempDir()
	elsewhere := t.TempDir()
	journal := batchJournalV1{Version: 1, Members: []batchMemberV1{{
		Origin: "lab.test.", Path: filepath.Join(elsewhere, "state.json"),
		Next: filepath.Join(elsewhere, "candidate"), NewDigest: "00",
	}}}
	data, _ := json.Marshal(journal)
	writeFile(t, filepath.Join(dir, batchJournalName), string(data))
	if err := RecoverBatch(dir); err == nil {
		t.Fatal("recovery trusted a journal path outside the state directory")
	}
}
