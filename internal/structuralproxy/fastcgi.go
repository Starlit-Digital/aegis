package structuralproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"time"
)

// This deliberately implements one responder request per private connection.
// No multiplexing, persistent workers, request supplied CGI parameters or retries.
func fcgi(ctx context.Context, r *http.Request, route Route, limit int64) (*http.Response, error) {
	conn, e := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", route.Socket)
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	record := func(kind byte, b []byte) error {
		for len(b) > 65535 {
			if e := writeRecord(conn, kind, b[:65535]); e != nil {
				return e
			}
			b = b[65535:]
		}
		return writeRecord(conn, kind, b)
	}
	if e = record(1, []byte{0, 1, 0, 0, 0, 0, 0, 0}); e != nil {
		return nil, e
	}
	params := map[string]string{"GATEWAY_INTERFACE": "CGI/1.1", "SERVER_PROTOCOL": "HTTP/1.1", "SERVER_SOFTWARE": "aegis", "REQUEST_METHOD": r.Method, "SCRIPT_FILENAME": route.ScriptFilename, "SCRIPT_NAME": route.ScriptName, "DOCUMENT_ROOT": route.DocumentRoot, "SERVER_NAME": route.ServerName, "SERVER_PORT": strconv.Itoa(route.ServerPort), "REQUEST_URI": r.URL.RequestURI(), "QUERY_STRING": r.URL.RawQuery, "CONTENT_LENGTH": strconv.FormatInt(r.ContentLength, 10), "REMOTE_ADDR": peer(r.RemoteAddr)}
	if route.HTTPS {
		params["HTTPS"] = "on"
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		params["CONTENT_TYPE"] = ct
	}
	for k, vs := range r.Header {
		if forwarded[k] {
			params["HTTP_"+strings.ToUpper(strings.ReplaceAll(k, "-", "_"))] = vs[0]
		}
	}
	params["HTTP_HOST"] = route.ServerName
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var encoded []byte
	for _, k := range keys {
		v := params[k]
		encoded = length(encoded, len(k))
		encoded = length(encoded, len(v))
		encoded = append(encoded, k...)
		encoded = append(encoded, v...)
	}
	if e = record(4, encoded); e != nil {
		return nil, e
	}
	if e = record(4, nil); e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return nil, errInput
	}
	if len(b) > 0 {
		if e = record(5, b); e != nil {
			return nil, e
		}
	}
	if e = record(5, nil); e != nil {
		return nil, e
	}
	var out bytes.Buffer
	stderr := 0
	closed := false
	for records := 0; records < 4096; records++ {
		var h [8]byte
		if _, e = io.ReadFull(conn, h[:]); e != nil {
			return nil, e
		}
		if h[0] != 1 || h[2] != 0 || h[3] != 1 || h[7] != 0 {
			return nil, errInput
		}
		n := int(binary.BigEndian.Uint16(h[4:6]))
		payload := make([]byte, n+int(h[6]))
		if _, e = io.ReadFull(conn, payload); e != nil {
			return nil, e
		}
		payload = payload[:n]
		switch h[1] {
		case 6:
			if closed {
				return nil, errInput
			}
			if n == 0 {
				closed = true
				continue
			}
			if int64(out.Len()+n) > limit+4096 {
				return nil, errInput
			}
			out.Write(payload)
		case 7:
			stderr += n
			if stderr > 8192 {
				return nil, errInput
			}
		case 3:
			// PHP FPM may end the request without a separate empty STDOUT record.
			if n != 8 || binary.BigEndian.Uint32(payload[:4]) != 0 || payload[4] != 0 {
				return nil, errInput
			}
			return parseCGI(out.Bytes(), limit, r.Method == "HEAD")
		default:
			return nil, errInput
		}
	}
	return nil, errors.New("FastCGI record limit")
}
func length(b []byte, n int) []byte {
	if n < 128 {
		return append(b, byte(n))
	}
	return binary.BigEndian.AppendUint32(b, uint32(n)|0x80000000)
}
func writeRecord(w io.Writer, kind byte, b []byte) error {
	h := []byte{1, kind, 0, 1, byte(len(b) >> 8), byte(len(b)), 0, 0}
	frame := append(h, b...)
	for len(frame) > 0 {
		n, e := w.Write(frame)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}
func parseCGI(b []byte, limit int64, head bool) (*http.Response, error) {
	i := bytes.Index(b, []byte("\r\n\r\n"))
	if i < 0 || i > 4092 || int64(len(b)-i-4) > limit {
		return nil, errInput
	}
	// Reject obsolete folding and LF only spellings before MIMEHeader parsing.
	for _, line := range strings.Split(string(b[:i]), "\r\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' || strings.ContainsAny(line, "\r\n") {
			return nil, errInput
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || !token(k) || !headerValue(strings.TrimSpace(v)) {
			return nil, errInput
		}
	}
	h, e := textproto.NewReader(bufio.NewReader(bytes.NewReader(b[:i+4]))).ReadMIMEHeader()
	if e != nil {
		return nil, e
	}
	status := 200
	if values := h.Values("Status"); len(values) > 0 {
		if len(values) != 1 {
			return nil, errInput
		}
		parts := strings.SplitN(values[0], " ", 2)
		if len(parts[0]) != 3 {
			return nil, errInput
		}
		status, e = strconv.Atoi(parts[0])
		if e != nil || status < 200 || status > 599 {
			return nil, errInput
		}
		h.Del("Status")
	} else if h.Get("Location") != "" {
		status = 302
	}
	declared := int64(-1)
	if values := h.Values("Content-Length"); len(values) > 0 {
		if len(values) != 1 {
			return nil, errInput
		}
		n, e := strconv.ParseInt(values[0], 10, 64)
		if e != nil || n < 0 || n > limit || ((!head || len(b)-i-4 > 0) && n != int64(len(b)-i-4)) {
			return nil, errInput
		}
		declared = n
	}
	return &http.Response{ContentLength: declared, StatusCode: status, Header: http.Header(h), Body: io.NopCloser(bytes.NewReader(b[i+4:]))}, nil
}
