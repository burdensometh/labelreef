package zone

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"
)

func loadExample(t testing.TB) *ZoneVersion {
	t.Helper()
	f, err := os.Open("../examples/zones/lab-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	version, err := DecodeV1(f)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

func TestV1RoundTripAndTree(t *testing.T) {
	version := loadExample(t)
	if version.Origin() != "lab.test." || version.Serial() != 4294967294 {
		t.Fatalf("wrong seed identity: %s %d", version.Origin(), version.Serial())
	}
	for _, item := range []struct {
		name string
		want Match
	}{
		{"lab.test.", Match{Kind: Apex, Closest: "lab.test."}},
		{"branch.lab.test.", Match{Kind: Empty, Closest: "branch.lab.test."}},
		{"deep.branch.lab.test.", Match{Kind: Empty, Closest: "deep.branch.lab.test."}},
		{"lost.branch.lab.test.", Match{Kind: Missing, Closest: "branch.lab.test."}},
		{"a.never.lab.test.", Match{Kind: Missing, Closest: "lab.test.", Wildcard: "*.lab.test."}},
		{"www.child.lab.test.", Match{Kind: Cut, Closest: "child.lab.test.", Cut: "child.lab.test."}},
		{"nolab.test.", Match{}},
	} {
		if got := version.Find(item.name); got != item.want {
			t.Errorf("Find(%s) = %#v, want %#v", item.name, got, item.want)
		}
	}
	updated := version.Set("www.lab.test.", A)
	updated.Records[0] = Record{}
	if version.Set("www.lab.test.", A).Records[0].Type != A {
		t.Fatal("returned RRset aliases zone storage")
	}
	var output bytes.Buffer
	if err := EncodeV1(&output, version); err != nil {
		t.Fatal(err)
	}
	canonical, err := DecodeV1(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(canonical.Records(), version.Records()) {
		t.Fatal("v1 round-trip changed records")
	}
	for _, row := range canonical.V1().Records {
		if !strings.HasSuffix(row.Name, ".") {
			t.Errorf("output owner not absolute: %s", row.Name)
		}
	}
}

func TestInvalidZoneRecords(t *testing.T) {
	base := loadExample(t)
	for _, test := range []struct {
		name, typ, data, contains string
		ttl                       uint32
	}{
		{"outside.test.", "A", "192.0.2.2", "outside zone", 120},
		{"www", "CNAME", "ns", "cannot coexist", 120},
		{"www", "A", "192.0.2.2", "mixed RRset", 999},
		{"www", "A", "192.0.2.10", "duplicate record", 120},
		{"child", "TXT", "\"forbidden at cut\"", "invalid at a delegation", 100},
	} {
		t.Run(test.contains, func(t *testing.T) {
			typ, _ := ParseType(test.typ)
			record, err := ParseRecord(base.Origin(), test.name, test.ttl, typ, test.data)
			if err != nil {
				t.Fatal(err)
			}
			_, err = New(base.Origin(), append(base.Records(), record))
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("expected %q, got %v", test.contains, err)
			}
		})
	}
}

func TestNamesAndPackedText(t *testing.T) {
	for _, value := range []string{"", "hi..test.", strings.Repeat("a", 64) + ".", `foo\999.test.`} {
		if _, err := Name(value); err == nil {
			t.Errorf("accepted invalid name %q", value)
		}
	}
	for _, tc := range []struct{ input, output string }{
		{`DoT\.NAME.\000Lab.Test`, `dot\046name.\000lab.test.`},
		{`label*with*asterisks.`, `label\042with\042asterisks.`},
	} {
		if got, err := Name(tc.input); err != nil || got != tc.output {
			t.Errorf("Name(%q)=%q, %v, want %q", tc.input, got, err, tc.output)
		}
	}
	for _, data := range []string{`"" "a b" "x\x00y"`, `"one" two "three\\four"`} {
		first, err := ParseRecord("lab.test.", "@", 60, TXT, data)
		if err != nil {
			t.Fatal(err)
		}
		second, err := ParseRecord("lab.test.", "@", 60, TXT, first.Presentation())
		if err != nil || first != second {
			t.Errorf("TXT roundtrip failed for %s: %v", data, err)
		}
	}
}

func BenchmarkDeepName(b *testing.B) {
	base := loadExample(b)
	prefix := strings.Repeat("part.", 36)
	record, err := ParseRecord(base.Origin(), "leaf."+prefix+base.Origin(), 60, A, "192.0.2.63")
	if err != nil {
		b.Fatal(err)
	}
	version, err := New(base.Origin(), append(base.Records(), record))
	if err != nil {
		b.Fatal(err)
	}
	names := []string{record.Name, "missing." + prefix + base.Origin(), "another." + base.Origin()}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		match := version.Find(names[i%len(names)])
		if match.Closest == "" {
			b.Fatal("lookup escaped zone")
		}
	}
}
