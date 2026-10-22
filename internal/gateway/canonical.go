package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"unicode/utf8"
)

// CanonicalJSON is for the optional structural proxy. Staging remains byte exact.
func CanonicalJSON(b []byte, c Config) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if int64(len(b)) > c.MaxBytes || !utf8.Valid(b) {
		return nil, errors.New("invalid JSON size or UTF-8")
	}
	var escapes escapeValidator
	if _, err := escapes.Write(b); err != nil {
		return nil, err
	}
	if err := escapes.Finish(); err != nil {
		return nil, err
	}
	if err := validateJSON(bytes.NewReader(b), c); err != nil {
		return nil, err
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		return nil, err
	}
	out, err := json.Marshal(value)
	if int64(len(out)) > c.MaxBytes {
		return nil, errors.New("canonical JSON exceeds limit")
	}
	return out, err
}
