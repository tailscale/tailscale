package rfc1035label

import (
	"errors"
	"fmt"
	"strings"
)

// Labels represents RFC1035 labels
//
// This implements RFC 1035 labels, including compression.
// https://tools.ietf.org/html/rfc1035#section-4.1.4
type Labels struct {
	// original contains the original bytes if the object was parsed from a byte
	// sequence, or nil otherwise. The `original` field is necessary to deal
	// with compressed labels. If the labels are further modified, the original
	// content is invalidated and no compression will be used.
	original []byte
	// Labels contains the parsed labels. A change here invalidates the
	// `original` object.
	Labels []string
}

// same compares two string arrays
func same(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// String prints labels.
func (l *Labels) String() string {
	return fmt.Sprintf("%v", l.Labels)
}

// ToBytes returns a byte sequence representing the labels. If the original
// sequence is modified, the labels are parsed again, otherwise the original
// byte sequence is returned.
func (l *Labels) ToBytes() []byte {
	// if the original byte sequence has been modified, invalidate it and
	// serialize again.
	// NOTE: this function is not thread-safe. If multiple threads modify
	// the `Labels` field, the result may be wrong.
	originalLabels, err := labelsFromBytes(l.original)
	// if the original object has not been modified, or we cannot parse it,
	// return the original bytes.
	if err != nil || (l.original != nil && same(originalLabels, l.Labels)) {
		return l.original
	}
	return labelsToBytes(l.Labels)
}

// Length returns the length in bytes of the serialized labels
func (l *Labels) Length() int {
	return len(l.ToBytes())
}

// NewLabels returns an initialized Labels object.
func NewLabels() *Labels {
	return &Labels{
		Labels: make([]string, 0),
	}
}

// FromBytes reads labels from a bytes stream according to RFC 1035.
func (l *Labels) FromBytes(data []byte) error {
	labs, err := labelsFromBytes(data)
	if err != nil {
		return err
	}
	l.original = data
	l.Labels = labs
	return nil
}

// FromBytes returns a Labels object from the given byte sequence, or an error if
// any.
func FromBytes(data []byte) (*Labels, error) {
	var l Labels
	if err := l.FromBytes(data); err != nil {
		return nil, err
	}
	return &l, nil
}

// fromBytes decodes a serialized stream and returns a list of labels
func labelsFromBytes(buf []byte) ([]string, error) {
	var (
		labels          = make([]string, 0)
		pos, oldPos     int
		label           string
		handlingPointer bool
	)

	for {
		if pos >= len(buf) {
			break
		}
		length := int(buf[pos])
		pos++
		var chunk string
		if length == 0 {
			labels = append(labels, label)
			label = ""
			if handlingPointer {
				pos = oldPos
				handlingPointer = false
			}
		} else if length&0xc0 == 0xc0 {
			// compression pointer
			if handlingPointer {
				return nil, errors.New("rfc1035label: cannot handle nested pointers")
			}
			handlingPointer = true
			if pos+1 > len(buf) {
				return nil, errors.New("rfc1035label: pointer buffer too short")
			}
			off := int(buf[pos-1]&^0xc0)<<8 + int(buf[pos])
			oldPos = pos + 1
			pos = off
		} else {
			if pos+length > len(buf) {
				return nil, errors.New("rfc1035label: buffer too short")
			}
			chunk = string(buf[pos : pos+length])
			if label != "" {
				label += "."
			}
			label += chunk
			pos += length
		}
	}
	return labels, nil
}

// labelToBytes encodes a label and returns a serialized stream of bytes
func labelToBytes(label string) []byte {
	var encodedLabel []byte
	if len(label) == 0 {
		return []byte{0}
	}
	for _, part := range strings.Split(label, ".") {
		encodedLabel = append(encodedLabel, byte(len(part)))
		encodedLabel = append(encodedLabel, []byte(part)...)
	}
	return append(encodedLabel, 0)
}

// labelsToBytes encodes a list of labels and returns a serialized stream of
// bytes
func labelsToBytes(labels []string) []byte {
	var encodedLabels []byte
	for _, label := range labels {
		encodedLabels = append(encodedLabels, labelToBytes(label)...)
	}
	return encodedLabels
}
