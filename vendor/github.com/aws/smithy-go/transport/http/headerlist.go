package http

import (
	"fmt"
	"strings"
)

func splitHeaderListValues(vs []string, splitFn func(string) ([]string, error)) ([]string, error) {
	for i := 0; i < len(vs); i++ {
		if len(vs[i]) == 0 {
			continue
		}

		parts, err := splitFn(vs[i])
		if err != nil {
			return nil, err
		}
		if len(parts) < 2 {
			continue
		}

		tmp := make([]string, len(vs)+len(parts)-1)
		copy(tmp, vs[:i])

		for j, p := range parts {
			tmp[i+j] = strings.TrimSpace(p)
		}

		copy(tmp[i+len(parts):], vs[i+1:])

		vs = tmp
		i += len(parts) - 1
	}

	return vs, nil
}

// SplitHeaderListValues attempts to split the elements of the slice by commas,
// and return a list of all values separated. Returns error if unable to
// separate the values.
func SplitHeaderListValues(vs []string) ([]string, error) {
	return splitHeaderListValues(vs, commaSplit)
}

func commaSplit(v string) ([]string, error) {
	return strings.Split(v, ","), nil
}

// SplitHTTPDateTimestampHeaderListValues attempts to split the HTTP-Date
// timestamp values in the slice by commas, and return a list of all values
// separated. The split is aware of HTTP-Date timestamp format, and will skip
// comma within the timestamp value. Returns an error if unable to split the
// timestamp values.
func SplitHTTPDateTimestampHeaderListValues(vs []string) ([]string, error) {
	return splitHeaderListValues(vs, splitHTTPDateHeaderValue)
}

func splitHTTPDateHeaderValue(v string) ([]string, error) {
	if n := strings.Count(v, ","); n == 1 {
		// Skip values with only a single HTTPDate value
		return nil, nil
	} else if n == 0 || n%2 == 0 {
		return nil, fmt.Errorf("invalid timestamp HTTPDate header comma separations, %q", v)
	}

	var parts []string
	var i, j int

	var doSplit bool
	for ; i < len(v); i++ {
		if v[i] == ',' {
			if doSplit {
				doSplit = false
				parts = append(parts, v[j:i])
				j = i + 1
			} else {
				// Skip the first comma in the timestamp value since that
				// separates the day from the rest of the timestamp.
				//
				// Tue, 17 Dec 2019 23:48:18 GMT
				doSplit = true
			}
		}
	}
	if j < len(v) {
		parts = append(parts, v[j:])
	}

	return parts, nil
}
