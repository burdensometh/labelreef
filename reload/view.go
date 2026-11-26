package reload

import (
	"errors"
	"fmt"

	"labelreef/lookup"
	"labelreef/transfer"
	"labelreef/zone"
)

// View pins one active routing table for the read side. Queries, exports,
// transfers and checks made through a single view observe one complete
// table: a view opened before a replacement keeps serving the old table and
// never follows the new one.
type View struct {
	table *table
}

// View captures the current active table as a read-side handle. Each call
// loads the table once, so a replacement between calls is observed only by
// views opened afterwards.
func (m *Manager) View() *View {
	return &View{table: m.active.Load()}
}

// Resolve answers a question from this view's table. Zone selection uses the
// longest active suffix, with parent authority for DS at a delegation.
func (v *View) Resolve(q lookup.Question) lookup.Answer {
	return lookup.Resolve(v.table.route(q), q)
}

// Export returns the active zone for an exact configured origin.
func (v *View) Export(origin string) (*zone.ZoneVersion, error) {
	name, err := zone.Name(origin)
	if err != nil {
		return nil, err
	}
	e := v.table.exact(name)
	if e == nil {
		return nil, fmt.Errorf("%w or inactive: %s", ErrUnknown, name)
	}
	return e.snapshot.Current(), nil
}

// Transfer plans an AXFR or IXFR from the exact active zone in this view's
// table. The plan holds the view's snapshot and ignores later replacements.
func (v *View) Transfer(request transfer.Request) (*transfer.Plan, error) {
	e := v.table.exact(request.Origin)
	if e == nil {
		return nil, ErrUnknown
	}
	return transfer.Build(e.snapshot, request)
}

// Check verifies read-only that the read-side selections agree across this
// view's table: every active zone is exported, transferred and routed to from
// the same snapshot, and every inactive zone is refused by export and
// transfer and skipped by routing.
func (v *View) Check() error {
	for _, origin := range v.table.origins() {
		if err := v.checkOrigin(origin); err != nil {
			return err
		}
	}
	return nil
}

func (v *View) checkOrigin(origin string) error {
	z := v.table.entries[origin].snapshot.Current()
	if z == nil {
		if _, err := v.Export(origin); !errors.Is(err, ErrUnknown) {
			return fmt.Errorf("check %s: inactive zone exported: %v", origin, err)
		}
		request := transfer.Request{Origin: origin, Type: zone.AXFR}
		if _, err := v.Transfer(request); !errors.Is(err, ErrUnknown) {
			return fmt.Errorf("check %s: inactive zone transferred: %v", origin, err)
		}
		if routed := v.table.route(apex(origin, zone.SOA)); routed != nil && routed.Origin() == origin {
			return fmt.Errorf("check %s: inactive zone routes queries", origin)
		}
		return nil
	}
	if z.Origin() != origin {
		return fmt.Errorf("check %s: active zone has origin %s", origin, z.Origin())
	}
	exported, err := v.Export(origin)
	if err != nil {
		return fmt.Errorf("check %s: export: %w", origin, err)
	}
	if exported != z {
		return fmt.Errorf("check %s: export selected a different zone", origin)
	}
	plan, err := v.Transfer(transfer.Request{Origin: origin, Type: zone.AXFR})
	if err != nil {
		return fmt.Errorf("check %s: transfer: %w", origin, err)
	}
	if plan.Kind() != transfer.Full || plan.Serial() != z.Serial() {
		return fmt.Errorf("check %s: transfer offers %s at serial %d, active zone has serial %d",
			origin, plan.Kind(), plan.Serial(), z.Serial())
	}
	if routed := v.table.route(apex(origin, zone.SOA)); routed != z {
		return fmt.Errorf("check %s: apex query routes to %s", origin, originOf(routed))
	}
	if routed, expected := v.table.route(apex(origin, zone.DS)), v.delegation(origin, z); routed != expected {
		return fmt.Errorf("check %s: DS query routes to %s, expected %s",
			origin, originOf(routed), originOf(expected))
	}
	return nil
}

// delegation computes the zone expected to answer a DS query at origin: the
// nearest active ancestor that delegates origin, or the zone itself.
func (v *View) delegation(origin string, z *zone.ZoneVersion) *zone.ZoneVersion {
	for name := zone.Parent(origin); ; name = zone.Parent(name) {
		if e := v.table.exact(name); e != nil {
			parent := e.snapshot.Current()
			if match := parent.Find(origin); match.Kind == zone.Cut && match.Cut == origin {
				return parent
			}
			return z
		}
		if name == zone.Root {
			return z
		}
	}
}

func apex(origin string, typ zone.Type) lookup.Question {
	return lookup.Question{Name: origin, Type: typ, Class: zone.ClassIN}
}

func originOf(z *zone.ZoneVersion) string {
	if z == nil {
		return "<none>"
	}
	return z.Origin()
}

// Resolve opens a fresh view for one query.
func (m *Manager) Resolve(q lookup.Question) lookup.Answer {
	return m.View().Resolve(q)
}

// Export opens a fresh view for one export.
func (m *Manager) Export(origin string) (*zone.ZoneVersion, error) {
	return m.View().Export(origin)
}

// Transfer opens a fresh view for one transfer plan.
func (m *Manager) Transfer(request transfer.Request) (*transfer.Plan, error) {
	return m.View().Transfer(request)
}

// Check runs the read-only selection check against one capture of the
// current active table.
func (m *Manager) Check() error {
	return m.View().Check()
}
