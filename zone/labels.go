package zone

import (
	"fmt"
	"strings"
)

func plainByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') || b == '_' || b == '-'
}

// LabelText encodes a raw DNS label without introducing separator dots.
func LabelText(raw []byte, fold bool) string {
	if len(raw) == 1 && raw[0] == '*' {
		return "*"
	}
	var out strings.Builder
	for _, b := range raw {
		if plainByte(b) {
			if fold && b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			out.WriteByte(b)
		} else {
			out.WriteByte('\\')
			out.WriteByte('0' + b/100)
			out.WriteByte('0' + b%100/10)
			out.WriteByte('0' + b%10)
		}
	}
	return out.String()
}

// AppendLabelBytes expands decimal escapes in a canonical presentation label.
func AppendLabelBytes(dst []byte, label string) []byte {
	for {
		i := strings.IndexByte(label, '\\')
		if i < 0 {
			return append(dst, label...)
		}
		dst = append(dst, label[:i]...)
		value := int(label[i+1]-'0')*100 + int(label[i+2]-'0')*10 + int(label[i+3]-'0')
		dst = append(dst, byte(value))
		label = label[i+4:]
	}
}

func escapedName(input, origin string) (string, error) {
	if input == "" {
		return "", fmt.Errorf("empty DNS name")
	}
	var result strings.Builder
	var raw [63]byte
	size, wire := 0, 1
	absolute := false
	for start := 0; start < len(input); {
		b := input[start]
		start++
		if b == '.' {
			if size == 0 {
				return "", fmt.Errorf("empty label in %q", input)
			}
			result.WriteString(LabelText(raw[:size], true))
			result.WriteByte('.')
			wire += size + 1
			size = 0
			absolute = start == len(input)
			continue
		}
		if b == '\\' {
			value, next, err := escapedByte(input, start)
			if err != nil {
				return "", err
			}
			b, start = value, next
		}
		if size == len(raw) {
			return "", fmt.Errorf("label exceeds 63 octets in %q", input)
		}
		raw[size] = b
		size++
	}
	if size != 0 {
		result.WriteString(LabelText(raw[:size], true))
		result.WriteByte('.')
		wire += size + 1
	}
	if !absolute && origin != Root {
		for _, label := range Labels(origin) {
			wire += 1 + len(AppendLabelBytes(nil, label))
		}
		result.WriteString(origin)
	}
	if wire > 255 {
		return "", fmt.Errorf("DNS name exceeds 255 wire octets")
	}
	return result.String(), nil
}

func escapedByte(value string, from int) (byte, int, error) {
	if from >= len(value) {
		return 0, 0, fmt.Errorf("unfinished name escape in %q", value)
	}
	b := value[from]
	if b < '0' || b > '9' {
		return b, from + 1, nil
	}
	if from+3 > len(value) {
		return 0, 0, fmt.Errorf("expected three decimal digits in %q", value)
	}
	number := 0
	for _, digit := range value[from : from+3] {
		if digit < '0' || digit > '9' {
			return 0, 0, fmt.Errorf("invalid decimal name escape in %q", value)
		}
		number = number*10 + int(digit-'0')
	}
	if number > 255 {
		return 0, 0, fmt.Errorf("name escape beyond one octet in %q", value)
	}
	return byte(number), from + 3, nil
}
