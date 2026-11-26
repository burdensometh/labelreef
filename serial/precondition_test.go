package serial

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"labelreef/zone"
)

func decodeEditText(t *testing.T, text string) EditV1 {
	t.Helper()
	edit, err := DecodeEdit(strings.NewReader(text))
	if err != nil {
		t.Fatalf("decode edit: %v\n%s", err, text)
	}
	return edit
}

func guardedFixture(t *testing.T) EditV1 {
	t.Helper()
	return editFromFixturePath(t, "guarded-www")
}

func editFromFixturePath(t *testing.T, name string) EditV1 {
	t.Helper()
	f, err := os.Open(filepath.Join("../examples/edits", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	edit, err := DecodeEdit(f)
	if err != nil {
		t.Fatal(err)
	}
	return edit
}

// unrelatedHeadEdit advances the serial without touching the www RRset.
const unrelatedHeadEdit = `{"version":1,"origin":"lab.test.","base":4294967294,"next":4294967295,` +
	`"remove":[],"add":[{"name":"head","type":"A","ttl":60,"data":"192.0.2.20"}]}`

// guardedWWWEdit expects the seed www RRset; fixture lists members in reverse
// order, so this also proves member ordering is irrelevant.
const guardedWWWEdit = `{"version":1,"origin":"lab.test.","base":4294967294,"next":5,` +
	`"preconditions":[{"name":"www","type":"A","ttl":120,"records":[` +
	`{"name":"www","type":"A","ttl":120,"data":"192.0.2.11"},` +
	`{"name":"www","type":"A","ttl":120,"data":"192.0.2.10"}]}],` +
	`"remove":[],"add":[{"name":"guarded","type":"TXT","ttl":120,"data":"\"rrset precondition held\""}]}`

func TestPreconditionEditAppliesOnExactBase(t *testing.T) {
	base := initial(t)
	got, err := guardedFixture(t).Apply(base)
	if err != nil {
		t.Fatal(err)
	}
	if got.Serial() != 5 {
		t.Fatalf("serial = %d, want 5", got.Serial())
	}
	www := got.Set("www.lab.test.", zone.A)
	if len(www.Records) != 2 || www.Records[0].TTL != 120 {
		t.Fatalf("www RRset altered: %+v", www.Records)
	}
	if txt := got.Set("guarded.lab.test.", zone.TXT); len(txt.Records) != 1 {
		t.Fatalf("guarded TXT missing: %+v", txt.Records)
	}
}

func TestPreconditionSurvivesUnrelatedChange(t *testing.T) {
	base := initial(t)
	moved, err := decodeEditText(t, unrelatedHeadEdit).Apply(base)
	if err != nil {
		t.Fatal(err)
	}
	if moved.Serial() != 4294967295 {
		t.Fatalf("unrelated edit serial = %d", moved.Serial())
	}
	// The guarded edit still names the old base serial 4294967294.
	got, err := decodeEditText(t, guardedWWWEdit).Apply(moved)
	if err != nil {
		t.Fatalf("guarded edit rejected after unrelated change: %v", err)
	}
	if got.Serial() != 5 {
		t.Fatalf("serial = %d, want 5", got.Serial())
	}
	if head := got.Set("head.lab.test.", zone.A); len(head.Records) != 1 {
		t.Fatal("unrelated head record was lost")
	}
	if txt := got.Set("guarded.lab.test.", zone.TXT); len(txt.Records) != 1 {
		t.Fatal("guarded edit record missing")
	}
	if www := got.Set("www.lab.test.", zone.A); len(www.Records) != 2 {
		t.Fatalf("www RRset changed: %+v", www.Records)
	}
}

func TestLegacyEditStillRequiresExactBase(t *testing.T) {
	base := initial(t)
	moved, err := decodeEditText(t, unrelatedHeadEdit).Apply(base)
	if err != nil {
		t.Fatal(err)
	}
	// to-1.json has base 0; without preconditions the exact base must match.
	legacy := editFromFixturePath(t, "to-1")
	if _, err := legacy.Apply(moved); err == nil ||
		!strings.Contains(err.Error(), "differs from active") {
		t.Fatalf("legacy edit bypassed exact base check: %v", err)
	}
}

func TestPreconditionRejectsStaleMembers(t *testing.T) {
	base := initial(t)
	// to-4294967295 replaces www 192.0.2.10 with 192.0.2.12.
	moved := next(t, base, "to-4294967295")
	if _, err := decodeEditText(t, guardedWWWEdit).Apply(moved); err == nil ||
		!strings.Contains(err.Error(), "precondition failed") {
		t.Fatalf("changed member did not fail the precondition: %v", err)
	}
	if moved.Serial() != 4294967295 || len(moved.Set("www.lab.test.", zone.A).Records) != 2 {
		t.Fatal("failed precondition mutated the active zone view")
	}
}

func TestPreconditionRejectsTTLChange(t *testing.T) {
	base := initial(t)
	ttlEdit := `{"version":1,"origin":"lab.test.","base":4294967294,"next":4294967295,` +
		`"remove":[` +
		`{"name":"www","type":"A","ttl":120,"data":"192.0.2.10"},` +
		`{"name":"www","type":"A","ttl":120,"data":"192.0.2.11"}],` +
		`"add":[` +
		`{"name":"www","type":"A","ttl":180,"data":"192.0.2.10"},` +
		`{"name":"www","type":"A","ttl":180,"data":"192.0.2.11"}]}`
	moved, err := decodeEditText(t, ttlEdit).Apply(base)
	if err != nil {
		t.Fatal(err)
	}
	_, err = decodeEditText(t, guardedWWWEdit).Apply(moved)
	if err == nil || !strings.Contains(err.Error(), "TTL") {
		t.Fatalf("TTL change did not fail the precondition: %v", err)
	}
}

func TestPreconditionRejectsExtraAndMissingMembers(t *testing.T) {
	base := initial(t)
	extra := `{"version":1,"origin":"lab.test.","base":4294967294,"next":4294967295,` +
		`"remove":[],"add":[{"name":"www","type":"A","ttl":120,"data":"192.0.2.13"}]}`
	moved, err := decodeEditText(t, extra).Apply(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeEditText(t, guardedWWWEdit).Apply(moved); err == nil ||
		!strings.Contains(err.Error(), "expected 2") {
		t.Fatalf("extra member did not fail the precondition: %v", err)
	}

	gone := `{"version":1,"origin":"lab.test.","base":4294967294,"next":4294967295,` +
		`"remove":[` +
		`{"name":"www","type":"A","ttl":120,"data":"192.0.2.10"},` +
		`{"name":"www","type":"A","ttl":120,"data":"192.0.2.11"}],"add":[]}`
	empty, err := decodeEditText(t, gone).Apply(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeEditText(t, guardedWWWEdit).Apply(empty); err == nil ||
		!strings.Contains(err.Error(), "has 0 records") {
		t.Fatalf("missing RRset did not fail the precondition: %v", err)
	}
}

func TestAbsencePrecondition(t *testing.T) {
	base := initial(t)
	absent := `{"version":1,"origin":"lab.test.","base":4294967294,"next":5,` +
		`"preconditions":[{"name":"head","type":"A","ttl":60,"records":[]}],` +
		`"remove":[],"add":[{"name":"head","type":"A","ttl":60,"data":"192.0.2.20"}]}`
	got, err := decodeEditText(t, absent).Apply(base)
	if err != nil {
		t.Fatalf("absence precondition should hold on seed: %v", err)
	}
	present, err := decodeEditText(t, unrelatedHeadEdit).Apply(base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeEditText(t, absent).Apply(present); err == nil ||
		!strings.Contains(err.Error(), "must be absent") {
		t.Fatalf("present RRset did not fail absence precondition: %v", err)
	}
	if head := got.Set("head.lab.test.", zone.A); len(head.Records) != 1 {
		t.Fatal("absence edit did not add its record")
	}
}

func TestPreconditionSerialOrdering(t *testing.T) {
	base := initial(t)
	for _, tc := range []struct {
		name       string
		base, next uint32
	}{
		{"base ahead", 10, 5},
		{"undefined distance", 2147483646, 5},
		{"next equals active", 4294967294, 4294967294},
		{"next older than active", 4294967294, 4294967293},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := guardedWWWEdit
			text = strings.Replace(text, `"base":4294967294`, `"base":`+strconv.FormatUint(uint64(tc.base), 10), 1)
			text = strings.Replace(text, `"next":5`, `"next":`+strconv.FormatUint(uint64(tc.next), 10), 1)
			if _, err := decodeEditText(t, text).Apply(base); err == nil {
				t.Fatalf("%s edit was accepted", tc.name)
			}
		})
	}
}

func TestEmptyPreconditionsSelectGuardedMode(t *testing.T) {
	base := initial(t)
	moved, err := decodeEditText(t, unrelatedHeadEdit).Apply(base)
	if err != nil {
		t.Fatal(err)
	}
	empty := `{"version":1,"origin":"lab.test.","base":4294967294,"next":5,` +
		`"preconditions":[],"remove":[],"add":[]}`
	if _, err := decodeEditText(t, empty).Apply(moved); err != nil {
		t.Fatalf("empty precondition list should enable guarded mode: %v", err)
	}
	legacy := `{"version":1,"origin":"lab.test.","base":4294967294,"next":5,"remove":[],"add":[]}`
	if _, err := decodeEditText(t, legacy).Apply(moved); err == nil {
		t.Fatal("missing preconditions field unexpectedly enabled guarded mode")
	}
	nullPreconditions := `{"version":1,"origin":"lab.test.","base":4294967294,"next":5,` +
		`"preconditions":null,"remove":[],"add":[]}`
	if _, err := decodeEditText(t, nullPreconditions).Apply(moved); err == nil {
		t.Fatal("null preconditions should retain legacy exact-base behavior")
	}
}

func TestPreconditionDecodingErrors(t *testing.T) {
	if _, err := DecodeEdit(strings.NewReader(`{"version":1,"origin":"lab.test.","base":1,"next":2,` +
		`"preconditions":[{"name":"www","type":"A","ttl":120,"records":[],"bogus":1}]}`)); err == nil {
		t.Fatal("edit with unknown precondition field was accepted")
	}
}

func TestPreconditionParseErrors(t *testing.T) {
	base := initial(t)
	validMembers := `"records":[{"name":"www","type":"A","ttl":120,"data":"192.0.2.10"}]`
	for _, tc := range []struct {
		name, body string
	}{
		{"soa precondition", `{"version":1,"origin":"lab.test.","base":1,"next":2,` +
			`"preconditions":[{"name":"@","type":"SOA","ttl":600,` + validMembers + `}]}`},
		{"member wrong owner", `{"version":1,"origin":"lab.test.","base":1,"next":2,` +
			`"preconditions":[{"name":"www","type":"A","ttl":120,` +
			`"records":[{"name":"mail","type":"A","ttl":120,"data":"192.0.2.10"}]}]}`},
		{"member wrong type", `{"version":1,"origin":"lab.test.","base":1,"next":2,` +
			`"preconditions":[{"name":"www","type":"A","ttl":120,` +
			`"records":[{"name":"www","type":"AAAA","ttl":120,"data":"2001:db8::1"}]}]}`},
		{"member ttl mismatch", `{"version":1,"origin":"lab.test.","base":1,"next":2,` +
			`"preconditions":[{"name":"www","type":"A","ttl":120,` +
			`"records":[{"name":"www","type":"A","ttl":180,"data":"192.0.2.10"}]}]}`},
		{"duplicate member", `{"version":1,"origin":"lab.test.","base":1,"next":2,` +
			`"preconditions":[{"name":"www","type":"A","ttl":120,` +
			`"records":[` +
			`{"name":"www","type":"A","ttl":120,"data":"192.0.2.10"},` +
			`{"name":"www","type":"A","ttl":120,"data":"192.0.2.10"}]}]}`},
		{"duplicate precondition", `{"version":1,"origin":"lab.test.","base":1,"next":2,` +
			`"preconditions":[` +
			`{"name":"www","type":"A","ttl":120,` + validMembers + `},` +
			`{"name":"www","type":"A","ttl":120,` + validMembers + `}]}`},
		{"member outside zone", `{"version":1,"origin":"lab.test.","base":1,"next":2,` +
			`"preconditions":[{"name":"www","type":"A","ttl":120,` +
			`"records":[{"name":"www.other.test.","type":"A","ttl":120,"data":"192.0.2.10"}]}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			edit, err := DecodeEdit(strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("structure decode should succeed: %v", err)
			}
			if _, err := edit.Apply(base); err == nil {
				t.Fatalf("%s edit was applied", tc.name)
			}
		})
	}
}

func TestFailedPreconditionLeavesReplayableZone(t *testing.T) {
	base := initial(t)
	moved := next(t, base, "to-4294967295")
	if _, err := decodeEditText(t, guardedWWWEdit).Apply(moved); err == nil {
		t.Fatal("expected precondition failure")
	}
	// The same zone still accepts an edit whose precondition holds.
	holds := `{"version":1,"origin":"lab.test.","base":4294967295,"next":5,` +
		`"preconditions":[{"name":"www","type":"A","ttl":120,"records":[` +
		`{"name":"www","type":"A","ttl":120,"data":"192.0.2.11"},` +
		`{"name":"www","type":"A","ttl":120,"data":"192.0.2.12"}]}],` +
		`"remove":[],"add":[{"name":"guarded","type":"TXT","ttl":120,"data":"\"ok\""}]}`
	got, err := decodeEditText(t, holds).Apply(moved)
	if err != nil {
		t.Fatalf("valid precondition edit failed after earlier rejection: %v", err)
	}
	if got.Serial() != 5 || len(got.Set("guarded.lab.test.", zone.TXT).Records) != 1 {
		t.Fatal("guarded edit did not apply cleanly after retry")
	}
}
