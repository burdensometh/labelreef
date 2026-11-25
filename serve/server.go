package serve

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"labelreef/lookup"
	"labelreef/transfer"
	"labelreef/zone"
)

type Resolver interface {
	Resolve(lookup.Question) lookup.Answer
	Transfer(transfer.Request) (*transfer.Plan, error)
}

type FramePoint struct {
	Origin   string
	Kind     transfer.Kind
	Serial   uint32
	Position transfer.Position
}

type Options struct {
	Address             netip.AddrPort
	MaxUDP              int
	FrameRecords        int
	IOTimeout           time.Duration
	BeforeTransferFrame func(FramePoint) error
}

type Stats struct {
	UDP                  uint64 `json:"udp"`
	TCP                  uint64 `json:"tcp"`
	Truncated            uint64 `json:"truncated"`
	TransfersStarted     uint64 `json:"transfers_started"`
	TransfersCompleted   uint64 `json:"transfers_completed"`
	TransfersInterrupted uint64 `json:"transfers_interrupted"`
	TransferFrames       uint64 `json:"transfer_frames"`
}

type counters struct {
	udp         atomic.Uint64
	tcp         atomic.Uint64
	truncated   atomic.Uint64
	started     atomic.Uint64
	completed   atomic.Uint64
	interrupted atomic.Uint64
	frames      atomic.Uint64
}

type Server struct {
	service Resolver
	opts    Options
	tcp     *net.TCPListener
	udp     *net.UDPConn
	address netip.AddrPort

	mu       sync.Mutex
	closing  bool
	peers    map[net.Conn]struct{}
	workers  sync.WaitGroup
	stop     sync.Once
	errs     chan error
	stats    counters
	progress transferMonitor
}

const maxPeers = 128

func Listen(service Resolver, opts Options) (*Server, error) {
	address := opts.Address.Addr().Unmap()
	if service == nil || !address.IsLoopback() || address.Zone() != "" || opts.MaxUDP < 512 ||
		opts.MaxUDP > 4096 || opts.FrameRecords < 1 || opts.FrameRecords > 1024 || opts.IOTimeout <= 0 {
		return nil, fmt.Errorf("invalid DNS listener options")
	}
	tcp, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(address, opts.Address.Port())))
	if err != nil {
		return nil, err
	}
	bound := tcp.Addr().(*net.TCPAddr).AddrPort()
	udp, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(bound))
	if err != nil {
		tcp.Close()
		return nil, err
	}
	s := &Server{
		service: service, opts: opts, tcp: tcp, udp: udp, address: bound,
		peers: make(map[net.Conn]struct{}), errs: make(chan error, 2),
	}
	s.workers.Add(2)
	go s.serveTCP()
	go s.serveUDP()
	return s, nil
}

func (s *Server) Address() netip.AddrPort { return s.address }

func (s *Server) Errors() <-chan error { return s.errs }

func (s *Server) Stats() Stats {
	return Stats{
		UDP: s.stats.udp.Load(), TCP: s.stats.tcp.Load(), Truncated: s.stats.truncated.Load(),
		TransfersStarted: s.stats.started.Load(), TransfersCompleted: s.stats.completed.Load(),
		TransfersInterrupted: s.stats.interrupted.Load(), TransferFrames: s.stats.frames.Load(),
	}
}

func (s *Server) Close() {
	s.stop.Do(func() {
		s.mu.Lock()
		s.closing = true
		s.tcp.Close()
		s.udp.Close()
		for peer := range s.peers {
			peer.Close()
		}
		s.mu.Unlock()
		s.workers.Wait()
		close(s.errs)
	})
}

func (s *Server) serveUDP() {
	defer s.workers.Done()
	packet := make([]byte, maxWire)
	for {
		n, peer, err := s.udp.ReadFromUDPAddrPort(packet)
		if err != nil {
			s.listenerError("UDP", err)
			return
		}
		if !peer.Addr().Unmap().IsLoopback() {
			continue
		}
		s.stats.udp.Add(1)
		q, code, accepted := parseQuery(packet[:n])
		if !accepted {
			continue
		}
		var response []byte
		switch {
		case code != lookup.Success:
			response = s.errorPacket(q, code, false)
		case q.question.Type == zone.IXFR:
			response = s.udpIXFR(q)
		case q.isTransfer():
			response = s.errorPacket(q, lookup.Refused, false)
		default:
			response = s.answer(q, false)
		}
		s.udp.WriteToUDPAddrPort(response, peer)
	}
}

func (s *Server) serveTCP() {
	defer s.workers.Done()
	for {
		conn, err := s.tcp.AcceptTCP()
		if err != nil {
			s.listenerError("TCP", err)
			return
		}
		s.mu.Lock()
		if s.closing || len(s.peers) >= maxPeers || !conn.RemoteAddr().(*net.TCPAddr).AddrPort().Addr().Unmap().IsLoopback() {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.peers[conn] = struct{}{}
		s.workers.Add(1)
		s.mu.Unlock()
		go s.servePeer(conn)
	}
}

func (s *Server) listenerError(network string, err error) {
	if !errors.Is(err, net.ErrClosed) {
		s.errs <- fmt.Errorf("%s DNS listener: %w", network, err)
	}
}

func (s *Server) servePeer(conn net.Conn) {
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.peers, conn)
		s.mu.Unlock()
		s.workers.Done()
	}()
	for {
		if err := conn.SetReadDeadline(time.Now().Add(s.opts.IOTimeout)); err != nil {
			return
		}
		packet, err := readFrame(conn)
		if err != nil {
			return
		}
		s.stats.tcp.Add(1)
		q, code, accepted := parseQuery(packet)
		if !accepted {
			return
		}
		if code == lookup.Success && q.isTransfer() {
			if err := s.sendTransfer(conn, q); err != nil {
				return
			}
			continue
		}
		var response []byte
		if code == lookup.Success {
			response = s.answer(q, true)
		} else {
			response = s.errorPacket(q, code, true)
		}
		if err := s.write(conn, response); err != nil {
			return
		}
	}
}

func (s *Server) write(conn net.Conn, packet []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(s.opts.IOTimeout)); err != nil {
		return err
	}
	return writeFrame(conn, packet)
}

func (s *Server) errorPacket(q query, code lookup.Code, tcp bool) []byte {
	return encodeAnswer(q, lookup.Answer{Code: code}, tcp, s.opts.MaxUDP)
}

func (s *Server) answer(q query, tcp bool) []byte {
	response := encodeAnswer(q, s.service.Resolve(q.question), tcp, s.opts.MaxUDP)
	h, _ := readHeader(response)
	if h.flags&flagTC != 0 {
		s.stats.truncated.Add(1)
	}
	return response
}

func (s *Server) udpIXFR(q query) []byte {
	plan, err := s.service.Transfer(q.request)
	if err != nil {
		return s.errorPacket(q, lookup.Refused, false)
	}
	// Every wire RR needs more than 11 octets, including a compressed owner.
	// Skip materializing a large plan when it cannot fit by that lower bound.
	if plan.Count() <= q.budget(false, s.opts.MaxUDP)/11 {
		response, encoded := encodeTransfer(q, plan.Cursor().Offer(plan.Count()), true, s.opts.MaxUDP)
		if encoded == plan.Count() && len(response) <= q.budget(false, s.opts.MaxUDP) {
			return response
		}
	}
	opening := plan.Cursor().Offer(1)
	response := encodeAnswer(q, lookup.Answer{
		Authoritative: true, Answer: []zone.RRset{zone.NewRRset(opening)},
	}, false, s.opts.MaxUDP)
	h, _ := readHeader(response)
	h.flags |= flagTC
	h.write(response)
	s.stats.truncated.Add(1)
	return response
}

func (s *Server) sendTransfer(conn net.Conn, q query) (err error) {
	plan, err := s.service.Transfer(q.request)
	if err != nil {
		return s.write(conn, s.errorPacket(q, lookup.Refused, true))
	}
	s.stats.started.Add(1)
	cursor := plan.Cursor()
	id := s.progress.start(q.question.Name, plan)
	defer func() {
		if err == nil {
			s.stats.completed.Add(1)
		} else {
			s.stats.interrupted.Add(1)
		}
		s.progress.finish(id, err)
	}()

	for !cursor.Done() {
		position := cursor.Position()
		if hook := s.opts.BeforeTransferFrame; hook != nil {
			point := FramePoint{Origin: q.question.Name, Kind: plan.Kind(), Serial: plan.Serial(), Position: position}
			if err := hook(point); err != nil {
				return err
			}
		}
		packet, n := encodeTransfer(q, cursor.Offer(s.opts.FrameRecords), position.Frames == 0, s.opts.MaxUDP)
		if n == 0 {
			return fmt.Errorf("transfer record exceeds DNS TCP frame limit")
		}
		if err := s.write(conn, packet); err != nil {
			return err
		}
		if err := cursor.Commit(n); err != nil {
			return err
		}
		s.stats.frames.Add(1)
		s.progress.advance(id, cursor.Position())
	}
	return nil
}
