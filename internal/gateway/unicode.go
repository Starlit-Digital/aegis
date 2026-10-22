package gateway

import "errors"

// JSON's decoder replaces lone escaped surrogates. Reject them before decoding
// so two different byte strings cannot silently become the same identity.
type escapeValidator struct {
	inString, escaped bool
	digits            int
	code              uint16
	pendingHigh       bool
	pairStep          int
}

func (v *escapeValidator) Write(p []byte) (int, error) {
	for _, b := range p {
		if v.pairStep > 0 {
			if v.pairStep == 1 {
				if b != '\\' {
					return 0, errors.New("unpaired surrogate")
				}
				v.pairStep = 2
				continue
			}
			if b != 'u' {
				return 0, errors.New("unpaired surrogate")
			}
			v.pairStep = 0
			v.digits = 4
			v.code = 0
			continue
		}
		if v.digits > 0 {
			var n byte
			switch {
			case b >= '0' && b <= '9':
				n = b - '0'
			case b >= 'a' && b <= 'f':
				n = b - 'a' + 10
			case b >= 'A' && b <= 'F':
				n = b - 'A' + 10
			default:
				return 0, errors.New("invalid Unicode escape")
			}
			v.code = v.code<<4 | uint16(n)
			v.digits--
			if v.digits == 0 {
				if v.pendingHigh {
					if v.code < 0xdc00 || v.code > 0xdfff {
						return 0, errors.New("unpaired surrogate")
					}
					v.pendingHigh = false
				} else if v.code >= 0xd800 && v.code <= 0xdbff {
					v.pendingHigh = true
					v.pairStep = 1
				} else if v.code >= 0xdc00 && v.code <= 0xdfff {
					return 0, errors.New("unpaired surrogate")
				}
			}
			continue
		}
		if !v.inString {
			if b == '"' {
				v.inString = true
			}
			continue
		}
		if v.escaped {
			v.escaped = false
			if b == 'u' {
				v.digits = 4
				v.code = 0
			}
			continue
		}
		if b == '\\' {
			v.escaped = true
		} else if b == '"' {
			v.inString = false
		}
	}
	return len(p), nil
}
func (v *escapeValidator) Finish() error {
	if v.pendingHigh || v.pairStep != 0 || v.digits != 0 {
		return errors.New("incomplete Unicode escape")
	}
	return nil
}
