package zone

import (
	"strings"
	"testing"
)

func TestIsDelegation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		origin  string
		ns      []string
		owner   string
		exposed bool
	}{
		{"apex is never a delegation", "lab.test.", []string{"lab.test."}, "lab.test.", false},
		{"direct child cut", "lab.test.", []string{"sub.lab.test."}, "sub.lab.test.", true},
		{"owner without NS", "lab.test.", nil, "sub.lab.test.", false},
		{"hidden below a cut", "lab.test.", []string{"sub.lab.test.", "deep.sub.lab.test."}, "deep.sub.lab.test.", false},
		{"exposed when ancestors carry no NS", "lab.test.", []string{"deep.sub.lab.test."}, "deep.sub.lab.test.", true},
		{"empty ancestors do not hide", "lab.test.", []string{"c.b.a.lab.test."}, "c.b.a.lab.test.", true},
		{"root origin cut", ".", []string{"example."}, "example.", true},
		{"root origin hidden", ".", []string{"example.", "sub.example."}, "sub.example.", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			carrying := make(map[string]bool, len(tc.ns))
			for _, owner := range tc.ns {
				carrying[owner] = true
			}
			hasNS := func(owner string) bool { return carrying[owner] }
			if got := IsDelegation(tc.owner, tc.origin, hasNS); got != tc.exposed {
				t.Errorf("IsDelegation(%q, %q) = %t, want %t", tc.owner, tc.origin, got, tc.exposed)
			}
		})
	}
}

func TestOwnerShape(t *testing.T) {
	record := func(owner string, ttl uint32, typ Type, data string) Record {
		r, err := ParseRecord("lab.test.", owner, ttl, typ, data)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	shape := make(OwnerShape)
	if err := shape.Add(record("www", 120, A, "192.0.2.10")); err != nil {
		t.Fatal(err)
	}
	if err := shape.Add(record("www", 999, A, "192.0.2.11")); err == nil ||
		!strings.Contains(err.Error(), "mixed RRset TTLs") {
		t.Fatalf("mixed TTL accepted: %v", err)
	}
	if err := shape.Add(record("www", 120, TXT, `"note"`)); err != nil {
		t.Fatal(err)
	}
	if shape.HasNS() {
		t.Fatal("shape claims NS without NS records")
	}
	shape.Remove(record("www", 120, TXT, `"note"`))
	if _, ok := shape[TXT]; ok {
		t.Fatal("empty RRset left in shape")
	}

	ordinary := OwnerShape{A: {Count: 1, TTL: 120}, TXT: {Count: 2, TTL: 60}}
	if err := ordinary.Validate("www.lab.test.", false); err != nil {
		t.Fatalf("ordinary owner rejected: %v", err)
	}
	if err := ordinary.Validate("sub.lab.test.", true); err == nil {
		t.Fatal("TXT accepted at an exposed delegation")
	}
	alias := OwnerShape{CNAME: {Count: 1, TTL: 120}}
	if err := alias.Validate("alias.lab.test.", false); err != nil {
		t.Fatalf("lone CNAME rejected: %v", err)
	}
	alias[A] = RRsetShape{Count: 1, TTL: 120}
	if err := alias.Validate("alias.lab.test.", false); err == nil {
		t.Fatal("CNAME coexistence accepted")
	}
}
