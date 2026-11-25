package zone

import "strings"

const Root = "."

// Name canonicalizes a presentation name and folds its ASCII letters.
func Name(input string) (string, error) {
	return qualify(input, Root)
}

func Qualify(input, origin string) (string, error) {
	if input == "@" {
		return Name(origin)
	}
	return qualify(input, origin)
}

func qualify(input, origin string) (string, error) {
	if canonical, ok := simpleName(input, origin); ok {
		return canonical, nil
	}
	return escapedName(input, origin)
}

func simpleName(input, origin string) (string, bool) {
	if input == Root {
		return Root, true
	}
	if input == "" || strings.ContainsRune(origin, '\\') {
		return "", false
	}
	total := len(input)
	if input[total-1] != '.' {
		total++
		if origin != Root {
			total += len(origin)
		}
	}
	if total > 254 {
		return "", false
	}
	start := 0
	for i := 0; i <= len(input); i++ {
		if i != len(input) && input[i] != '.' {
			if !plainByte(input[i]) && input[i] != '*' {
				return "", false
			}
			continue
		}
		if i == len(input) && start == i {
			break
		}
		if i-start < 1 || i-start > 63 {
			return "", false
		}
		label := input[start:i]
		if strings.Contains(label, "*") && label != "*" {
			return "", false
		}
		start = i + 1
	}
	if strings.HasSuffix(input, ".") {
		return strings.ToLower(input), true
	}
	if origin == Root {
		return strings.ToLower(input) + ".", true
	}
	return strings.ToLower(input) + "." + origin, true
}

func Within(name, origin string) bool {
	if origin == Root || name == origin {
		return true
	}
	return len(name) > len(origin) && name[len(name)-len(origin)-1] == '.' &&
		strings.HasSuffix(name, origin)
}

func Parent(name string) string {
	if name == Root {
		return Root
	}
	i := strings.IndexByte(name, '.')
	if i == len(name)-1 || i < 0 {
		return Root
	}
	return name[i+1:]
}

func Wildcard(name string) string {
	if name == Root {
		return "*."
	}
	return "*." + name
}

// Labels returns the labels in presentation order.
func Labels(name string) []string {
	if name == Root {
		return nil
	}
	return strings.Split(strings.TrimSuffix(name, "."), ".")
}
