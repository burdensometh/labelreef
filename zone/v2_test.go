package zone

import (
	"bytes"
	"os"
	"reflect"
	"strings"
	"testing"
)

func loadV2Example(t testing.TB) *ZoneVersion {
	t.Helper()
	f, err := os.Open("../examples/zones/lab-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, format, err := DecodeZone(f)
	if err != nil {
		t.Fatal(err)
	}
	if format != 2 {
		t.Fatalf("DecodeZone reported format %d, want 2", format)
	}
	return z
}

func TestV2MatchesV1Semantics(t *testing.T) {
	v1 := loadExample(t)
	v2 := loadV2Example(t)
	if !reflect.DeepEqual(v1.Records(), v2.Records()) {
		t.Fatal("v1 and v2 examples produced different records")
	}
	if v1.Fingerprint() != v2.Fingerprint() || !v1.Equal(v2) {
		t.Fatal("v1 and v2 examples are not equal zones")
	}
	if v1.NodeCount() != v2.NodeCount() || v1.RecordCount() != v2.RecordCount() {
		t.Fatal("v1 and v2 zone shape differs")
	}
}

func TestV2RoundTripIsRepeatable(t *testing.T) {
	version := loadV2Example(t)

	var first bytes.Buffer
	if err := EncodeV2(&first, version); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeV2(bytes.NewReader(first.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded.Records(), version.Records()) {
		t.Fatal("v2 round-trip changed records")
	}
	var second bytes.Buffer
	if err := EncodeV2(&second, decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("v2 encoding is not repeatable")
	}

	// Emitting either format from the same zone, then re-reading it, converges
	// back onto the identical canonical zone.
	var v1Out bytes.Buffer
	if err := EncodeV1(&v1Out, version); err != nil {
		t.Fatal(err)
	}
	fromV1, format, err := DecodeZone(bytes.NewReader(v1Out.Bytes()))
	if err != nil || format != 1 || !fromV1.Equal(version) {
		t.Fatalf("v1 export did not converge: format=%d err=%v", format, err)
	}
	fromV2, format, err := DecodeZone(bytes.NewReader(first.Bytes()))
	if err != nil || format != 2 || !fromV2.Equal(version) {
		t.Fatalf("v2 export did not converge: format=%d err=%v", format, err)
	}
}

func TestV2RelativeOwnersAndSegmentedTXT(t *testing.T) {
	input := `{
	  "version": 2,
	  "origin": "Lab.Test.",
	  "rrsets": [
	    {"name": "@", "type": "SOA", "ttl": 600, "records": ["ns admin 1 60 20 3600 45"]},
	    {"name": "@", "type": "NS", "ttl": 600, "records": ["ns"]},
	    {"name": "ns", "type": "A", "ttl": 300, "records": ["192.0.2.53"]},
	    {"name": "txt", "type": "TXT", "ttl": 120,
	     "records": ["\"first segment\" \"second segment\"", "\"single\""]}
	  ]
	}`
	z, format, err := DecodeZone(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if format != 2 {
		t.Fatalf("format = %d, want 2", format)
	}
	txt := z.Set("txt.lab.test.", TXT)
	if len(txt.Records) != 2 {
		t.Fatalf("TXT RRset size = %d, want 2", len(txt.Records))
	}
	parts, err := UnpackText(txt.Records[0].Data.Text)
	if err != nil || len(parts) != 2 || parts[0] != "first segment" || parts[1] != "second segment" {
		t.Fatalf("segmented TXT lost its structure: %#v %v", parts, err)
	}
	if txt.Records[0].TTL != 120 || txt.Records[1].TTL != 120 {
		t.Fatal("RRset TTL was not applied to every record")
	}
	if got := z.SOA().Name; got != "lab.test." {
		t.Fatalf("relative apex owner not qualified: %s", got)
	}
}

func TestV2RejectsConflictingAndMalformedRRSets(t *testing.T) {
	validGroups := `
	    {"name": "@", "type": "SOA", "ttl": 600, "records": ["ns admin 1 60 20 3600 45"]},
	    {"name": "@", "type": "NS", "ttl": 600, "records": ["ns"]},
	    {"name": "ns", "type": "A", "ttl": 300, "records": ["192.0.2.53"]}`
	for _, tc := range []struct {
		name     string
		body     string
		contains string
	}{
		{
			"duplicate rrset",
			`{"version":2,"origin":"lab.test.","rrsets":[` + validGroups + `,
			  {"name":"ns","type":"A","ttl":301,"records":["192.0.2.54"]}]}`,
			"conflicts with rrset",
		},
		{
			"same owner type after name canonicalization",
			`{"version":2,"origin":"lab.test.","rrsets":[` + validGroups + `,
			  {"name":"ns.lab.test.","type":"a","ttl":300,"records":["192.0.2.54"]}]}`,
			"conflicts with rrset",
		},
		{"missing ttl", `{"version":2,"origin":"lab.test.","rrsets":[
			  {"name":"@","type":"SOA","records":["ns admin 1 60 20 3600 45"]}]}`, "explicit ttl"},
		{"empty rrset", `{"version":2,"origin":"lab.test.","rrsets":[
			  {"name":"@","type":"NS","ttl":600,"records":[]}]}`, "at least one record"},
		{"unknown field", `{"version":2,"origin":"lab.test.","rrsets":[
			  {"name":"@","type":"NS","ttl":600,"records":["ns"],"extra":true}]}`, "unknown field"},
		{"wrong version", `{"version":3,"origin":"lab.test.","rrsets":[]}`, "unsupported zone file version 3"},
		{"missing version", `{"origin":"lab.test.","rrsets":[]}`, "unsupported zone file version 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeV2(strings.NewReader(tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.contains) {
				t.Fatalf("expected %q, got %v", tc.contains, err)
			}
		})
	}
}

func TestV2RejectsDuplicateRecordWithinRRset(t *testing.T) {
	input := `{
	  "version": 2,
	  "origin": "lab.test.",
	  "rrsets": [
	    {"name": "@", "type": "SOA", "ttl": 600, "records": ["ns admin 1 60 20 3600 45"]},
	    {"name": "@", "type": "NS", "ttl": 600, "records": ["ns"]},
	    {"name": "ns", "type": "A", "ttl": 300, "records": ["192.0.2.53", "192.0.2.53"]}
	  ]
	}`
	if _, err := DecodeV2(strings.NewReader(input)); err == nil ||
		!strings.Contains(err.Error(), "duplicate record") {
		t.Fatalf("expected duplicate record rejection, got %v", err)
	}
}

func TestV2PreservesRecordOrder(t *testing.T) {
	version := loadV2Example(t)
	bulletin := version.Set("bulletin.lab.test.", TXT)
	want := []string{"atlas", "boreal", "cinder", "delta", "ember", "fjord"}
	if len(bulletin.Records) != len(want) {
		t.Fatalf("bulletin size = %d, want %d", len(bulletin.Records), len(want))
	}
	for i, prefix := range want {
		parts, err := UnpackText(bulletin.Records[i].Data.Text)
		if err != nil || len(parts) != 1 || !strings.HasPrefix(parts[0], prefix) {
			t.Fatalf("record %d lost ordering or segments: %#v %v", i, parts, err)
		}
	}
}

func TestDecodeZoneRejectsTrailingAndOversized(t *testing.T) {
	base := func() []byte {
		var buf bytes.Buffer
		if err := EncodeV2(&buf, loadV2Example(t)); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}()
	if _, _, err := DecodeZone(bytes.NewReader(append(append([]byte{}, base...), '\n', '{'))); err == nil ||
		(!strings.Contains(err.Error(), "trailing JSON value") &&
			!strings.Contains(err.Error(), "after top-level value")) {
		t.Fatalf("expected trailing value rejection, got %v", err)
	}
	if _, _, err := DecodeZone(strings.NewReader(`{"version":2}`)); err == nil {
		t.Fatal("accepted structurally incomplete envelope")
	}
}
