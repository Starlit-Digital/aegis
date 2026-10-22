package gateway

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
)

// Ticket grants identity and one operation, never resource policy.
type Ticket struct {
	Purpose   string `json:"purpose"`
	Audience  string `json:"aud"`
	ID        string `json:"id"`
	Subject   string `json:"sub"`
	Operation string `json:"op"`
	Expires   int64  `json:"exp"`
}

var identifier = regexp.MustCompile(`^[a-f0-9]{32}$`)
var subject = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)

func Sign(key []byte, t Ticket) (string, error) {
	if len(key) != 32 {
		return "", errors.New("ticket key must be 32 bytes")
	}
	b, e := json.Marshal(t)
	if e != nil {
		return "", e
	}
	p := base64.RawURLEncoding.EncodeToString(b)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(p))
	return p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
func verify(key []byte, raw string, c Config, now time.Time) (Ticket, error) {
	var t Ticket
	if len(raw) > 1024 {
		return t, errors.New("invalid ticket")
	}
	p := strings.Split(raw, ".")
	if len(p) != 2 {
		return t, errors.New("invalid ticket")
	}
	sig, e := base64.RawURLEncoding.Strict().DecodeString(p[1])
	if e != nil {
		return t, e
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(p[0]))
	if !hmac.Equal(mac.Sum(nil), sig) {
		return t, errors.New("invalid signature")
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(p[0])
	if e != nil {
		return t, e
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if e = dec.Decode(&t); e != nil {
		return t, e
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return t, errors.New("trailing ticket data")
	}
	if t.Purpose != c.Purpose || t.Audience != "aegis-staging-v1" || !identifier.MatchString(t.ID) || !subject.MatchString(t.Subject) || (t.Operation != "upload" && t.Operation != "read" && t.Operation != "delete") || t.Expires <= now.Unix() || t.Expires > now.Add(time.Duration(c.TicketSeconds)*time.Second).Unix() {
		return t, errors.New("invalid claims")
	}
	return t, nil
}
