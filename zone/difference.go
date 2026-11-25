package zone

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
)

type Difference struct {
	Removes []Record
	Adds    []Record
}

// Diff compares complete record identities, so a TTL change appears as a
// removal and an addition. Both outputs retain canonical zone ordering.
func Diff(left, right *ZoneVersion) (Difference, error) {
	if left == nil || right == nil || left.origin != right.origin {
		return Difference{}, fmt.Errorf("record comparison requires the same origin")
	}
	var result Difference
	a, b := left.records, right.records
	for len(a) != 0 && len(b) != 0 {
		switch {
		case a[0] == b[0]:
			a, b = a[1:], b[1:]
		case Less(a[0], b[0]):
			result.Removes = append(result.Removes, a[0])
			a = a[1:]
		default:
			result.Adds = append(result.Adds, b[0])
			b = b[1:]
		}
	}
	result.Removes = append(result.Removes, a...)
	result.Adds = append(result.Adds, b...)
	return result, nil
}

func (z *ZoneVersion) Equal(other *ZoneVersion) bool {
	if z == nil || other == nil || z.origin != other.origin || len(z.records) != len(other.records) ||
		z.soa != other.soa {
		return false
	}
	for i, record := range z.records {
		if other.records[i] != record {
			return false
		}
	}
	return true
}

func (z *ZoneVersion) Fingerprint() string {
	h := sha256.New()
	hashText(h, "labelreef-zone-v1")
	hashText(h, z.origin)
	for _, rr := range z.records {
		hashText(h, rr.Name)
		var meta [6]byte
		binary.BigEndian.PutUint16(meta[:2], uint16(rr.Type))
		binary.BigEndian.PutUint32(meta[2:], rr.TTL)
		h.Write(meta[:])
		hashText(h, rr.Presentation())
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hashText(h hash.Hash, data string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(data)))
	h.Write(length[:])
	h.Write([]byte(data))
}
