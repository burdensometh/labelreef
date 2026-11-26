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
	ErrUnknown    = errors.New("zone is not configured")
	ErrRole       = errors.New("operation is unavailable for zone role")
	ErrSuperseded = errors.New("zone changed while operation was in progress")
)

type Receipt struct {
	Origin     string        `json:"origin"`
	Generation uint64        `json:"generation"`
	Serial     uint32        `json:"serial"`
	Changed    bool          `json:"changed"`
	Kind       transfer.Kind `json:"kind,omitempty"`
	Warning    string        `json:"warning,omitempty"`
}

type Fetcher interface {
	Fetch(context.Context, netip.AddrPort, string, *zone.ZoneVersion) (transfer.Candidate, error)
}

func Open(path string, hooks Boundary) (*Manager, error) {
	return openAt(path, hooks, true)
}

// Inspect opens a manager without persisting any retention trim, so diagnostic
// commands can report the durable state without modifying it.
func Inspect(path string, hooks Boundary) (*Manager, error) {
	return openAt(path, hooks, false)
}

func openAt(path string, hooks Boundary, persist bool) (*Manager, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	manager := &Manager{path: path, hooks: hooks}
	runtime, specs, err := manager.read()
	if err != nil {
		return nil, err
	}
	manager.runtime = runtime
	first, trimmed, err := manager.prepare(nil, specs)
	if err != nil {
		return nil, err
	}
	if persist {
		if err := persistTrims(trimmed); err != nil {
			return nil, err
		}
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

// prepare builds the candidate routing table and returns the entries whose
// retained history shrank. A shrinking retention window is an eviction, not a
// view change: the caller must make it durable before the new table activates,
// or a later reload or restart could offer deltas the window already dropped.
func (m *Manager) prepare(old *table, specs []specification) (*table, []*entry, error) {
	next := &table{epoch: 1, entries: make(map[string]*entry, len(specs))}
	if old != nil {
		next.epoch = old.epoch + 1
	}
	var trimmed []*entry
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
				if changed.snapshot.Retained() != current.snapshot.Retained() {
					trimmed = append(trimmed, &changed)
				}
				next.entries[spec.origin] = &changed
				continue
			}
		}
		e, evicted, err := spec.open(m.runtime, m.hooks.BeforePublish)
		if err != nil {
			return nil, nil, fmt.Errorf("activate %s: %w", spec.origin, err)
		}
		if evicted {
			trimmed = append(trimmed, e)
		}
		next.entries[spec.origin] = e
	}
	return next, trimmed, nil
}

// persistTrims makes retention shrink durable. Each save is an ordinary state
// publication at the active generation and serial; only history is shortened.
// A failed save aborts activation so the daemon never serves an eviction that
// the durable state still contradicts.
func persistTrims(trimmed []*entry) error {
	for _, e := range trimmed {
		result := e.store.Save(e.snapshot)
		if !result.Published {
			return fmt.Errorf("persist retention for %s: %w", e.origin, result.Err)
		}
	}
	return nil
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
	next, trimmed, err := m.prepare(m.active.Load(), specs)
	if err != nil {
		return Status{}, err
	}
	if hook := m.hooks.BeforeReplace; hook != nil {
		if err := hook(next.epoch); err != nil {
			return Status{}, fmt.Errorf("config replacement: %w", err)
		}
	}
	if err := persistTrims(trimmed); err != nil {
		return Status{}, err
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
