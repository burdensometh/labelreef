package reload

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"

	"labelreef/lookup"
	"labelreef/serial"
	"labelreef/transfer"
	"labelreef/zone"
)

type Boundary struct {
	BeforePublish func(serial.PublishPoint) error
	BeforeReplace func(epoch uint64) error
}

type Manager struct {
	path    string
	runtime Runtime
	hooks   Boundary
	mu      sync.Mutex
	active  atomic.Pointer[table]
}

var (
	ErrUnknown        = errors.New("zone is not configured")
	ErrRole           = errors.New("operation is unavailable for zone role")
	ErrSuperseded     = errors.New("zone changed while operation was in progress")
	ErrBatchAmbiguous = errors.New("batch requires one parent and one child zone")
)

type Receipt struct {
	Origin     string        `json:"origin"`
	Generation uint64        `json:"generation"`
	Serial     uint32        `json:"serial"`
	Changed    bool          `json:"changed"`
	Kind       transfer.Kind `json:"kind,omitempty"`
	Warning    string        `json:"warning,omitempty"`
}

// BatchReceipt reports one committed batch. Parent and Child each record the
// generation and serial of their own unchanged SOA sequence.
type BatchReceipt struct {
	Epoch   uint64  `json:"epoch"`
	Parent  Receipt `json:"parent"`
	Child   Receipt `json:"child"`
	Changed bool    `json:"changed"`
	Warning string  `json:"warning,omitempty"`
}

type Fetcher interface {
	Fetch(context.Context, netip.AddrPort, string, *zone.ZoneVersion) (transfer.Candidate, error)
}

func Open(path string, hooks Boundary) (*Manager, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	manager := &Manager{path: path, hooks: hooks}
	runtime, specs, err := manager.read()
	if err != nil {
		return nil, err
	}
	// Resolve an interrupted batch before any state file is read, so startup
	// observes either every prior state file or every completed candidate.
	if err := serial.RecoverBatch(runtime.StateDir); err != nil {
		return nil, fmt.Errorf("recover state directory: %w", err)
	}
	manager.runtime = runtime
	first, err := manager.prepare(nil, specs)
	if err != nil {
		return nil, err
	}
	manager.active.Store(first)
	return manager, nil
}

func (m *Manager) read() (Runtime, []specification, error) {
	cfg, err := ReadConfig(m.path)
	if err != nil {
		return Runtime{}, nil, err
	}
	return check(cfg, filepath.Dir(m.path))
}

func (m *Manager) Runtime() Runtime { return m.runtime }

func (m *Manager) prepare(old *table, specs []specification) (*table, error) {
	next := &table{epoch: 1, entries: make(map[string]*entry, len(specs))}
	if old != nil {
		next.epoch = old.epoch + 1
	}
	for _, spec := range specs {
		if old != nil && old.entries[spec.origin] != nil {
			current := old.entries[spec.origin]
			if current.specification == spec {
				next.entries[spec.origin] = current
				continue
			}
			if current.snapshot.Current() != nil {
				changed := *current
				changed.specification = spec
				changed.snapshot = current.snapshot.Limit(spec.retain)
				next.entries[spec.origin] = &changed
				continue
			}
		}
		e, err := spec.open(m.runtime, m.hooks.BeforePublish)
		if err != nil {
			return nil, fmt.Errorf("activate %s: %w", spec.origin, err)
		}
		next.entries[spec.origin] = e
	}
	return next, nil
}

func (m *Manager) Reload() (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	runtime, specs, err := m.read()
	if err != nil {
		return Status{}, err
	}
	if runtime != m.runtime {
		return Status{}, fmt.Errorf("listener, state directory or budget change requires restart")
	}
	next, err := m.prepare(m.active.Load(), specs)
	if err != nil {
		return Status{}, err
	}
	if hook := m.hooks.BeforeReplace; hook != nil {
		if err := hook(next.epoch); err != nil {
			return Status{}, fmt.Errorf("config replacement: %w", err)
		}
	}
	m.active.Store(next)
	return next.status(), nil
}

func (m *Manager) Status() Status { return m.active.Load().status() }

func (m *Manager) Resolve(q lookup.Question) lookup.Answer {
	return lookup.Resolve(m.active.Load().route(q), q)
}

func (m *Manager) Export(origin string) (*zone.ZoneVersion, error) {
	name, err := zone.Name(origin)
	if err != nil {
		return nil, err
	}
	e := m.active.Load().entries[name]
	if e == nil || e.snapshot.Current() == nil {
		return nil, fmt.Errorf("%w or inactive: %s", ErrUnknown, name)
	}
	return e.snapshot.Current(), nil
}

func (m *Manager) Transfer(request transfer.Request) (*transfer.Plan, error) {
	active := m.active.Load()
	e := active.entries[request.Origin]
	if e == nil || e.snapshot.Current() == nil {
		return nil, ErrUnknown
	}
	return transfer.Build(e.snapshot, request)
}

func (m *Manager) Edit(edit serial.EditV1) (Receipt, error) {
	name, err := zone.Name(edit.Origin)
	if err != nil {
		return Receipt{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	active := m.active.Load()
	e, err := active.find(name, Primary)
	if err != nil {
		return Receipt{}, err
	}
	z, err := edit.Apply(e.snapshot.Current())
	if err != nil {
		return Receipt{}, err
	}
	return m.commit(active, e, z, nil)
}

func (m *Manager) Publish(z *zone.ZoneVersion) (Receipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	active := m.active.Load()
	e, err := active.find(z.Origin(), Primary)
	if err != nil {
		return Receipt{}, err
	}
	return m.commit(active, e, z, nil)
}

// PublishBatch applies one parent edit and one child edit as a single
// publication. Each edit validates its own base against its own active SOA
// sequence; if either base disagrees, neither zone is touched. Both candidate
// state files reach disk before either is installed, and the pair swaps under
// one journal, so a restart sees both old files or both new files. In-flight
// transfers keep the snapshot they started from and continue to read the prior
// zone generation.
func (m *Manager) PublishBatch(batch serial.BatchEditV1) (BatchReceipt, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(batch.Edits) != 2 {
		return BatchReceipt{}, fmt.Errorf("%w: expected exactly two edits", ErrBatchAmbiguous)
	}
	active := m.active.Load()

	edits := make(map[string]serial.EditV1, len(batch.Edits))
	for i, edit := range batch.Edits {
		name, err := zone.Name(edit.Origin)
		if err != nil {
			return BatchReceipt{}, fmt.Errorf("batch edit %d: %w", i+1, err)
		}
		e := active.entries[name]
		if e == nil || e.snapshot.Current() == nil {
			return BatchReceipt{}, fmt.Errorf("%w: %s", ErrUnknown, name)
		}
		if e.role != Primary {
			return BatchReceipt{}, fmt.Errorf("%w: %s is %s", ErrRole, name, e.role)
		}
		if _, duplicate := edits[name]; duplicate {
			return BatchReceipt{}, fmt.Errorf("%w: edit repeated for %s", ErrBatchAmbiguous, name)
		}
		edits[name] = edit
	}
	parent, child, err := parentChild(batch.Edits)
	if err != nil {
		return BatchReceipt{}, err
	}

	// Expand both members before writing anything. A base mismatch on either
	// member rejects the whole batch.
	snapshots := make(map[string]*serial.Snapshot, 2)
	for _, name := range []string{parent, child} {
		snapshots[name] = active.entries[name].snapshot
	}
	next, err := batch.Expand(snapshots)
	if err != nil {
		if errors.Is(err, serial.ErrUnknownOrigin) {
			return BatchReceipt{}, fmt.Errorf("%w: %v", ErrUnknown, err)
		}
		return BatchReceipt{}, err
	}

	candidates := make(map[string]*serial.Snapshot, 2)
	for _, name := range []string{parent, child} {
		entry := active.entries[name]
		snap, err := serial.Advance(entry.snapshot, next[name], nil, entry.retain)
		if err != nil {
			return BatchReceipt{}, fmt.Errorf("%s: %w", name, err)
		}
		if snap != entry.snapshot {
			candidates[name] = snap
		}
	}
	if len(candidates) == 0 {
		return BatchReceipt{Parent: m.receiptFor(active, parent, false),
			Child: m.receiptFor(active, child, false)}, nil
	}
	if len(candidates) != 2 {
		return BatchReceipt{}, fmt.Errorf("%w: one member does not advance", ErrBatchAmbiguous)
	}

	// Stage both candidate files completely, then pass the publish boundary
	// for each before either becomes visible.
	items := make([]serial.BatchItem, 0, 2)
	abort := func() {
		for _, item := range items {
			item.Staged.Abort()
		}
	}
	for _, name := range []string{parent, child} {
		staged, err := active.entries[name].store.Stage(candidates[name])
		if err != nil {
			abort()
			return BatchReceipt{}, fmt.Errorf("%s: stage candidate: %w", name, err)
		}
		items = append(items, serial.BatchItem{Origin: name, Staged: staged})
	}
	for _, item := range items {
		if err := item.Staged.Prepare(); err != nil {
			abort()
			return BatchReceipt{}, err
		}
	}

	result := serial.CommitBatch(m.runtime.StateDir, items)
	if !result.Published {
		abort()
		return BatchReceipt{}, result.Err
	}

	nt := &table{epoch: active.epoch + 1, entries: make(map[string]*entry, len(active.entries))}
	for name, current := range active.entries {
		nt.entries[name] = current
	}
	for _, name := range []string{parent, child} {
		changed := *active.entries[name]
		changed.snapshot = candidates[name]
		nt.entries[name] = &changed
	}
	m.active.Store(nt)

	receipt := BatchReceipt{
		Epoch: nt.epoch, Changed: true,
		Parent: m.receiptFor(nt, parent, true),
		Child:  m.receiptFor(nt, child, true),
	}
	if result.Err != nil {
		receipt.Warning = fmt.Sprintf("published with directory sync error: %v", result.Err)
	}
	return receipt, nil
}

// parentChild identifies the enclosing origin. The two configured zones must
// form one pair: exactly one origin lies within the other.
func parentChild(edits []serial.EditV1) (parent, child string, err error) {
	names := make([]string, 0, len(edits))
	for _, edit := range edits {
		name, err := zone.Name(edit.Origin)
		if err != nil {
			return "", "", err
		}
		names = append(names, name)
	}
	switch {
	case names[0] == names[1]:
		return "", "", fmt.Errorf("%w: duplicate origin %s", ErrBatchAmbiguous, names[0])
	case zone.Within(names[1], names[0]):
		return names[0], names[1], nil
	case zone.Within(names[0], names[1]):
		return names[1], names[0], nil
	default:
		return "", "", fmt.Errorf("%w: %s and %s are not a parent and child", ErrBatchAmbiguous, names[0], names[1])
	}
}

func (m *Manager) receiptFor(t *table, origin string, changed bool) Receipt {
	entry := t.entries[origin]
	z := entry.snapshot.Current()
	return Receipt{
		Origin: origin, Serial: z.Serial(), Generation: entry.snapshot.Generation(), Changed: changed,
	}
}

func (m *Manager) Sync(ctx context.Context, origin string, client Fetcher) (Receipt, error) {
	name, err := zone.Name(origin)
	if err != nil {
		return Receipt{}, err
	}
	start, err := m.active.Load().find(name, Secondary)
	if err != nil {
		return Receipt{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, m.runtime.SyncTimeout)
	defer cancel()
	candidate, err := client.Fetch(ctx, start.source, name, start.snapshot.Current())
	if err != nil {
		return Receipt{}, err
	}
	if candidate.Zone == nil || candidate.Zone.Origin() != name {
		return Receipt{}, fmt.Errorf("transfer returned no valid zone for %s", name)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	active := m.active.Load()
	if active.entries[name] != start {
		return Receipt{}, ErrSuperseded
	}
	receipt, err := m.commit(active, start, candidate.Zone, candidate.Deltas)
	receipt.Kind = candidate.Kind
	return receipt, err
}

func (t *table) find(origin string, role Role) (*entry, error) {
	e := t.entries[origin]
	if e == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknown, origin)
	}
	if e.role != role {
		return nil, fmt.Errorf("%w: %s is %s", ErrRole, origin, e.role)
	}
	return e, nil
}

func (m *Manager) commit(t *table, old *entry, z *zone.ZoneVersion, deltas []serial.JournalDelta) (Receipt, error) {
	snapshot, err := serial.Advance(old.snapshot, z, deltas, old.retain)
	if err != nil {
		return Receipt{}, err
	}
	receipt := Receipt{Origin: z.Origin(), Serial: z.Serial(), Generation: snapshot.Generation()}
	if snapshot == old.snapshot {
		return receipt, nil
	}
	result := old.store.Save(snapshot)
	if !result.Published {
		return Receipt{}, result.Err
	}
	next := *old
	next.snapshot = snapshot
	m.active.Store(t.replace(&next))
	receipt.Changed = true
	if result.Err != nil {
		receipt.Warning = fmt.Sprintf("published with directory sync error: %v", result.Err)
	}
	return receipt, nil
}
