package reload

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"labelreef/serial"
	"labelreef/zone"
)

type Role string

const (
	Primary   Role = "primary"
	Secondary Role = "secondary"
)

type Config struct {
	Version       int          `json:"version"`
	DNS           string       `json:"dns"`
	Control       string       `json:"control"`
	StateDir      string       `json:"state_dir"`
	MaxUDP        int          `json:"max_udp"`
	FrameRecords  int          `json:"frame_records"`
	IOTimeoutMS   int          `json:"io_timeout_ms"`
	SyncTimeoutMS int          `json:"sync_timeout_ms"`
	Zones         []ZoneConfig `json:"zones"`
}

type ZoneConfig struct {
	Origin string `json:"origin"`
	Role   Role   `json:"role"`
	Seed   string `json:"seed,omitempty"`
	Source string `json:"source,omitempty"`
	Retain int    `json:"retain"`
}

type Runtime struct {
	DNS          netip.AddrPort
	Control      netip.AddrPort
	StateDir     string
	MaxUDP       int
	FrameRecords int
	IOTimeout    time.Duration
	SyncTimeout  time.Duration
}

type specification struct {
	origin string
	role   Role
	seed   string
	source netip.AddrPort
	retain int
}

func ReadConfig(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer f.Close()
	return decodeConfig(f)
}

func decodeConfig(r io.Reader) (Config, error) {
	var cfg Config
	err := zone.DecodeJSON(r, 1<<20, &cfg)
	return cfg, err
}

func Check(path string) (Runtime, error) {
	cfg, err := ReadConfig(path)
	if err != nil {
		return Runtime{}, err
	}
	runtime, _, err := check(cfg, filepath.Dir(path))
	return runtime, err
}

func check(cfg Config, dir string) (Runtime, []specification, error) {
	if cfg.Version != 1 || cfg.StateDir == "" {
		return Runtime{}, nil, fmt.Errorf("config requires version 1 and state_dir")
	}
	dns, err := Loopback(cfg.DNS)
	if err != nil {
		return Runtime{}, nil, fmt.Errorf("dns: %w", err)
	}
	control, err := Loopback(cfg.Control)
	if err != nil {
		return Runtime{}, nil, fmt.Errorf("control: %w", err)
	}
	if dns == control {
		return Runtime{}, nil, fmt.Errorf("control must use a separate TCP endpoint")
	}
	stateDir, err := filepath.Abs(resolve(dir, cfg.StateDir))
	if err != nil {
		return Runtime{}, nil, err
	}

	if cfg.MaxUDP == 0 {
		cfg.MaxUDP = 1232
	}
	if cfg.FrameRecords == 0 {
		cfg.FrameRecords = 64
	}
	if cfg.IOTimeoutMS == 0 {
		cfg.IOTimeoutMS = 3000
	}
	if cfg.SyncTimeoutMS == 0 {
		cfg.SyncTimeoutMS = 15000
	}
	if cfg.MaxUDP < 512 || cfg.MaxUDP > 4096 || cfg.FrameRecords < 1 || cfg.FrameRecords > 1024 ||
		cfg.IOTimeoutMS < 100 || cfg.IOTimeoutMS > 60000 || cfg.SyncTimeoutMS < cfg.IOTimeoutMS ||
		cfg.SyncTimeoutMS > 300000 {
		return Runtime{}, nil, fmt.Errorf("invalid DNS budget, frame size or timeout")
	}
	runtime := Runtime{
		DNS: dns, Control: control, StateDir: stateDir,
		MaxUDP: cfg.MaxUDP, FrameRecords: cfg.FrameRecords,
		IOTimeout:   time.Duration(cfg.IOTimeoutMS) * time.Millisecond,
		SyncTimeout: time.Duration(cfg.SyncTimeoutMS) * time.Millisecond,
	}

	if len(cfg.Zones) > 256 {
		return Runtime{}, nil, fmt.Errorf("configuration exceeds 256 zones")
	}
	specs := make([]specification, 0, len(cfg.Zones))
	seen := make(map[string]bool)
	for i, item := range cfg.Zones {
		s, err := zoneSpec(item, dir, runtime)
		if err != nil {
			return Runtime{}, nil, fmt.Errorf("zone %d: %w", i+1, err)
		}
		if seen[s.origin] {
			return Runtime{}, nil, fmt.Errorf("duplicate zone %s", s.origin)
		}
		seen[s.origin] = true
		specs = append(specs, s)
	}
	return runtime, specs, nil
}

func zoneSpec(item ZoneConfig, dir string, runtime Runtime) (specification, error) {
	name, err := zone.Name(item.Origin)
	if err != nil || strings.Contains(name, "*") {
		return specification{}, fmt.Errorf("invalid zone origin %q", item.Origin)
	}
	if item.Retain < 0 || item.Retain > 512 {
		return specification{}, fmt.Errorf("%s: retention must be between 0 and 512", name)
	}
	s := specification{origin: name, role: item.Role, retain: item.Retain}
	if item.Seed != "" {
		s.seed, err = filepath.Abs(resolve(dir, item.Seed))
		if err != nil {
			return specification{}, err
		}
	}
	switch s.role {
	case Primary:
		if s.seed == "" || item.Source != "" {
			return specification{}, fmt.Errorf("%s: primary requires a seed and no source", name)
		}
	case Secondary:
		s.source, err = Loopback(item.Source)
		if err != nil {
			return specification{}, fmt.Errorf("%s source: %w", name, err)
		}
		if s.source == runtime.DNS || s.source == runtime.Control {
			return specification{}, fmt.Errorf("%s: source points to this daemon", name)
		}
	default:
		return specification{}, fmt.Errorf("%s: invalid role %q", name, s.role)
	}
	return s, nil
}

func resolve(dir, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(dir, path)
}

func Loopback(value string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(value)
	if err != nil || !ap.Addr().Unmap().IsLoopback() || ap.Addr().Zone() != "" || ap.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("expected a numeric loopback address with a nonzero port: %q", value)
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
}

func (s specification) open(runtime Runtime, hook func(serial.PublishPoint) error) (*entry, error) {
	store := serial.Store{Path: statePath(runtime.StateDir, s.origin), BeforePublish: hook}
	snapshot, err := store.Load(s.origin)
	if err != nil {
		return nil, err
	}
	if snapshot == nil && s.seed != "" {
		f, err := os.Open(s.seed)
		if err != nil {
			return nil, err
		}
		z, err := zone.DecodeV1(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("read seed %s: %w", s.seed, err)
		}
		if z.Origin() != s.origin {
			return nil, fmt.Errorf("seed %s has origin %s, expected %s", s.seed, z.Origin(), s.origin)
		}
		snapshot = serial.Seed(z)
	}
	return &entry{specification: s, snapshot: snapshot.Limit(s.retain), store: store}, nil
}
