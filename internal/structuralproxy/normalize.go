package structuralproxy

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/Starlit-Digital/aegis/internal/gateway"
)

var errInput = errors.New("invalid structural input")

func valueOK(s string) bool {
	if len(s) > 4096 || !utf8.ValidString(s) {
		return false
	}
	for _, c := range s {
		if c == 0 || c == 127 || (c < 32 && c != '\t' && c != '\r' && c != '\n') {
			return false
		}
	}
	return true
}
func addField(v url.Values, k, s string) error {
	// PHP rewrites dots/spaces and interprets bracket syntax. Reject those aliases
	// rather than silently changing identities or allowing scalar/array collisions.
	if !fieldName.MatchString(k) || strings.EqualFold(k, "PHP_SESSION_UPLOAD_PROGRESS") || !valueOK(s) || len(v[k]) != 0 || len(v) >= 128 {
		return errInput
	}
	v.Set(k, s)
	return nil
}
func form(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return []byte{}, nil
	}
	if !utf8.Valid(b) || bytes.ContainsRune(b, ';') {
		return nil, errInput
	}
	v := url.Values{}
	for _, pair := range strings.Split(string(b), "&") {
		k, s, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, errInput
		}
		k, e := url.QueryUnescape(k)
		if e != nil {
			return nil, errInput
		}
		s, e = url.QueryUnescape(s)
		if e != nil {
			return nil, errInput
		}
		if e = addField(v, k, s); e != nil {
			return nil, e
		}
	}
	return []byte(v.Encode()), nil
}
func normalize(r *http.Request, b []byte, c Config) ([]byte, string, string, error) {
	format, ct := "none", ""
	if len(b) > 0 || r.Header.Get("Content-Type") != "" {
		media, params, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if e != nil {
			return nil, "", "", errInput
		}
		switch media {
		case "application/json":
			if len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
				return nil, "", "", errInput
			}
			policy := gateway.DefaultConfig()
			policy.MaxBytes = c.MaxBytes
			policy.MaxDepth = c.MaxDepth
			policy.MaxTokens = c.MaxTokens
			policy.MaxStringBytes = c.MaxStringBytes
			b, e = gateway.CanonicalJSON(b, policy)
			if e != nil {
				return nil, "", "", e
			}
			format = "json"
			ct = "application/json"
		case "application/x-www-form-urlencoded":
			if len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
				return nil, "", "", errInput
			}
			b, e = form(b)
			if e != nil {
				return nil, "", "", e
			}
			format = "form"
			ct = media
		case "multipart/form-data":
			if len(params) != 1 || params["boundary"] == "" || len(params["boundary"]) > 70 {
				return nil, "", "", errInput
			}
			mr := multipart.NewReader(bytes.NewReader(b), params["boundary"])
			v := url.Values{}
			for parts := 0; ; parts++ {
				p, e := mr.NextRawPart()
				if e == io.EOF {
					break
				}
				if e != nil || parts >= 32 {
					return nil, "", "", errInput
				}
				if len(p.Header) != 1 || len(p.Header.Values("Content-Disposition")) != 1 {
					return nil, "", "", errInput
				}
				disposition, dp, e := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
				if e != nil || disposition != "form-data" || len(dp) != 1 || dp["name"] == "" {
					return nil, "", "", errInput
				}
				data, e := io.ReadAll(io.LimitReader(p, 4097))
				if e != nil {
					return nil, "", "", e
				}
				if e = addField(v, dp["name"], string(data)); e != nil {
					return nil, "", "", e
				}
			}
			b = []byte(v.Encode())
			format = "multipart"
			ct = "application/x-www-form-urlencoded"
		default:
			return nil, "", "", errInput
		}
	}
	if int64(len(b)) > c.MaxBytes {
		return nil, "", "", errInput
	}
	return b, ct, format, nil
}
