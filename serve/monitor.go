package serve

import (
	"sort"
	"sync"

	"labelreef/transfer"
)

type TransferState string

const (
	Sending     TransferState = "sending"
	Delivered   TransferState = "delivered"
	Interrupted TransferState = "interrupted"
)

type TransferStatus struct {
	ID      uint64        `json:"id"`
	Origin  string        `json:"origin"`
	Kind    transfer.Kind `json:"kind"`
	Serial  uint32        `json:"serial"`
	State   TransferState `json:"state"`
	Records int           `json:"planned_records"`
	Written int           `json:"written_records"`
	Frames  int           `json:"written_frames"`
	Failure string        `json:"failure,omitempty"`
}

type TransferView struct {
	Active []TransferStatus `json:"active"`
	Recent []TransferStatus `json:"recent"`
}

const savedTransfers = 32

type transferMonitor struct {
	mu       sync.Mutex
	nextID   uint64
	active   map[uint64]TransferStatus
	recent   [savedTransfers]TransferStatus
	count    int
	nextSlot int
}

func (m *transferMonitor) start(origin string, plan *transfer.Plan) uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active == nil {
		m.active = make(map[uint64]TransferStatus)
	}
	m.nextID++
	id := m.nextID
	m.active[id] = TransferStatus{
		ID: id, Origin: origin, Kind: plan.Kind(), Serial: plan.Serial(), State: Sending,
		Records: plan.Count(),
	}
	return id
}

func (m *transferMonitor) advance(id uint64, position transfer.Position) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, found := m.active[id]
	if !found {
		return
	}
	entry.Written = position.NextRecord
	entry.Frames = position.Frames
	m.active[id] = entry
}

func (m *transferMonitor) finish(id uint64, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, found := m.active[id]
	if !found {
		return
	}
	delete(m.active, id)
	entry.State = Delivered
	if err != nil {
		entry.State = Interrupted
		entry.Failure = err.Error()
	}
	m.recent[m.nextSlot] = entry
	m.nextSlot = (m.nextSlot + 1) % len(m.recent)
	m.count = min(m.count+1, len(m.recent))
}

func (m *transferMonitor) status() TransferView {
	m.mu.Lock()
	defer m.mu.Unlock()
	view := TransferView{
		Active: make([]TransferStatus, 0, len(m.active)),
		Recent: make([]TransferStatus, 0, m.count),
	}
	for _, entry := range m.active {
		view.Active = append(view.Active, entry)
	}
	sort.Slice(view.Active, func(i, j int) bool { return view.Active[i].ID < view.Active[j].ID })
	for i := 1; i <= m.count; i++ {
		slot := (len(m.recent) + m.nextSlot - i) % len(m.recent)
		view.Recent = append(view.Recent, m.recent[slot])
	}
	return view
}

// TransferStatus observes acknowledged TCP frames and a bounded terminal
// history. A delivered transfer means all frames were written by this server.
func (s *Server) TransferStatus() TransferView { return s.progress.status() }
