package serial

type Ordering uint8

const (
	Equal Ordering = iota
	Newer
	Older
	Undefined
)

// Compare implements DNS serial arithmetic for 32-bit SOA values.
func Compare(candidate, current uint32) Ordering {
	difference := candidate - current
	switch {
	case difference == 0:
		return Equal
	case difference == 1<<31:
		return Undefined
	case difference < 1<<31:
		return Newer
	default:
		return Older
	}
}
