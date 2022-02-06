package ff

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
)

// JSONParser is a parser for config files in JSON format. Input should be
// an object. The object's keys are treated as flag names, and the object's
// values as flag values. If the value is an array, the flag will be set
// multiple times.
func JSONParser(r io.Reader, set func(name, value string) error) error {
	var m map[string]interface{}
	d := json.NewDecoder(r)
	d.UseNumber() // must set UseNumber for stringifyValue to work
	if err := d.Decode(&m); err != nil {
		return JSONParseError{Inner: err}
	}
	for key, val := range m {
		values, err := stringifySlice(val)
		if err != nil {
			return JSONParseError{Inner: err}
		}
		for _, value := range values {
			if err := set(key, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func stringifySlice(val interface{}) ([]string, error) {
	if vals, ok := val.([]interface{}); ok {
		ss := make([]string, len(vals))
		for i := range vals {
			s, err := stringifyValue(vals[i])
			if err != nil {
				return nil, err
			}
			ss[i] = s
		}
		return ss, nil
	}
	s, err := stringifyValue(val)
	if err != nil {
		return nil, err
	}
	return []string{s}, nil
}

func stringifyValue(val interface{}) (string, error) {
	switch v := val.(type) {
	case string:
		return v, nil
	case json.Number:
		return v.String(), nil
	case bool:
		return strconv.FormatBool(v), nil
	default:
		return "", StringConversionError{Value: val}
	}
}

// JSONParseError wraps all errors originating from the JSONParser.
type JSONParseError struct {
	Inner error
}

// Error implenents the error interface.
func (e JSONParseError) Error() string {
	return fmt.Sprintf("error parsing JSON config: %v", e.Inner)
}

// Unwrap implements the errors.Wrapper interface, allowing errors.Is and
// errors.As to work with JSONParseErrors.
func (e JSONParseError) Unwrap() error {
	return e.Inner
}

// StringConversionError is returned when a value in a config file
// can't be converted to a string, to be provided to a flag.
type StringConversionError struct {
	Value interface{}
}

// Error implements the error interface.
func (e StringConversionError) Error() string {
	return fmt.Sprintf("couldn't convert %q (type %T) to string", e.Value, e.Value)
}
