package zone

import (
	"strings"
	"testing"
)

func dnameZone(t *testing.T, extra ...Record) *ZoneVersion {
	t.Helper()
	base := loadExample(t)
	records := append(base.Records(), extra...)
	z, err := New(base.Origin(), records)
	if err != nil {
		t.Fatalf("zone construction failed: %v", err)
	}
	return z
}

func TestDNameParseAndRoundTrip(t *testing.T) {
	record, err := ParseRecord("lab.test.", "map", 120, DNAME, "target.lab.test.")
	if err != nil {
		t.Fatal(err)
	}
	want := Record{
		Name: "map.lab.test.", Type: DNAME, TTL: 120,
		Data: RData{Target: "target.lab.test."},
	}
	if record != want {
		t.Fatalf("parsed %+v, want %+v", record, want)
	}
	if got := record.Presentation(); got != "target.lab.test." {
		t.Fatalf("presentation %q", got)
	}
	relative, err := ParseRecord("lab.test.", "map", 120, DNAME, "elsewhere")
	if err != nil {
		t.Fatal(err)
	}
	if relative.Data.Target != "elsewhere.lab.test." {
		t.Fatalf("relative DNAME target not qualified: %s", relative.Data.Target)
	}
	if record.Validate() != nil {
		t.Fatalf("canonical DNAME rejected: %v", record.Validate())
	}
}

func TestDNameInvalidOwners(t *testing.T) {
	base := loadExample(t)
	mk := func(owner string, typ Type, data string) Record {
		t.Helper()
		record, err := ParseRecord(base.Origin(), owner, 100, typ, data)
		if err != nil {
			t.Fatal(err)
		}
		return record
	}
	for _, tc := range []struct {
		owner, data, contains string
		extra                 []Record
	}{
		{"@", "apex-target.example.", "apex", nil},
		{"mapz", "elsewhere.example.", "coexist", []Record{
			mk("mapz", CNAME, "other.lab.test."),
		}},
		{"mapx", "a.example.", "single", []Record{
			mk("mapx", DNAME, "b.example."),
		}},
		{"mapy", "elsewhere.example.", "coexist", []Record{
			mk("mapy", CNAME, "other.lab.test."),
		}},
		{"child", "elsewhere.example.", "invalid at a delegation", nil},
	} {
		t.Run(tc.contains+"/"+tc.owner, func(t *testing.T) {
			record, err := ParseRecord(base.Origin(), tc.owner, 100, DNAME, tc.data)
			if err != nil {
				t.Fatal(err)
			}
			records := append(base.Records(), record)
			records = append(records, tc.extra...)
			_, err = New(base.Origin(), records)
			if err == nil || !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("expected %q, got %v", tc.contains, err)
			}
		})
	}
}

func TestDNameRedirectSynthesis(t *testing.T) {
	dname := Record{
		Name: "map.lab.test.", Type: DNAME, TTL: 130,
		Data: RData{Target: "target.example."},
	}
	z := dnameZone(t, dname)

	// The DNAME owner itself is not a redirect.
	if _, _, ok := z.DNameRedirect("map.lab.test."); ok {
		t.Fatal("DNAME owner synthesized a CNAME")
	}
	set, target, ok := z.DNameRedirect("host.map.lab.test.")
	if !ok {
		t.Fatal("strict descendant did not trigger DNAME redirect")
	}
	if target != "host.target.example." || set.Records[0] != dname {
		t.Fatalf("synthesized target %s from %+v", target, set)
	}
	if deep, deepTarget, ok := z.DNameRedirect("a.b.map.lab.test."); !ok ||
		deepTarget != "a.b.target.example." || deep.Records[0].TTL != 130 {
		t.Fatalf("deep redirect: %s %+v %t", deepTarget, deep, ok)
	}
	// Outside the zone never redirects.
	if _, _, ok := z.DNameRedirect("example.org."); ok {
		t.Fatal("out-of-zone name produced a redirect")
	}
}

func TestDNameRedirectToRoot(t *testing.T) {
	dname := Record{
		Name: "map.lab.test.", Type: DNAME, TTL: 130,
		Data: RData{Target: Root},
	}
	z := dnameZone(t, dname)
	_, target, ok := z.DNameRedirect("host.map.lab.test.")
	if !ok || target != "host." {
		t.Fatalf("root DNAME target gave %q ok=%t", target, ok)
	}
}

func TestWildcardDNameRedirect(t *testing.T) {
	dname := Record{
		Name: "*.wild.lab.test.", Type: DNAME, TTL: 110,
		Data: RData{Target: "target.example."},
	}
	z := dnameZone(t, dname)
	_, target, ok := z.DNameRedirect("a.wild.lab.test.")
	if !ok || target != "a.target.example." {
		t.Fatalf("wildcard DNAME gave %q ok=%t", target, ok)
	}
	// Wildcards span exactly one label: a deeper name with no intermediate
	// node has no redirect.
	if _, _, ok := z.DNameRedirect("b.a.wild.lab.test."); ok {
		t.Fatal("wildcard DNAME matched more than one label")
	}
	// The wildcard owner itself is not a redirect.
	if _, _, ok := z.DNameRedirect("*.wild.lab.test."); ok {
		t.Fatal("wildcard DNAME owner synthesized a CNAME")
	}
}

func TestDNameRedirectOversizedTarget(t *testing.T) {
	long := strings.Repeat("a", 60)
	dname := Record{
		Name: "map.lab.test.", Type: DNAME, TTL: 100,
		Data: RData{Target: long + ".example."},
	}
	z := dnameZone(t, dname)
	// A short question fits; a deep one cannot be encoded within 255 octets.
	if _, target, ok := z.DNameRedirect("x.map.lab.test."); !ok ||
		target != "x."+long+".example." {
		t.Fatalf("short redirect failed: %q", target)
	}
	qname := strings.Repeat("label.", 40) + "map.lab.test."
	set, target, ok := z.DNameRedirect(qname)
	if ok || target != "" || len(set.Records) == 0 {
		t.Fatalf("oversized synthesis reported ok=%t target=%q set=%+v", ok, target, set)
	}
}

func TestDNameDoesNotCrossDelegation(t *testing.T) {
	// Records below an existing cut are accepted but stay in foreign
	// territory: the cut shadow means DNameRedirect never descends to them.
	dname := Record{
		Name: "under.child.lab.test.", Type: DNAME, TTL: 100,
		Data: RData{Target: "elsewhere.example."},
	}
	base := loadExample(t)
	z, err := New(base.Origin(), append(base.Records(), dname))
	if err != nil {
		t.Fatalf("below-cut record rejected: %v", err)
	}
	if _, _, ok := z.DNameRedirect("x.under.child.lab.test."); ok {
		t.Fatal("DNAME below a delegation cut was applied across the cut")
	}
}

func TestWireLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		want int
	}{
		{Root, 1},
		{"a.", 3},
		{"lab.test.", 10},
		// 1+4 "dot.", 1+3 "lab", 1+4 "test", root: three labels plus root.
		{`dot\046lab.test.`, 14},
	} {
		if got := WireLength(tc.name); got != tc.want {
			t.Errorf("WireLength(%q) = %d, want %d", tc.name, got, tc.want)
		}
	}
}
