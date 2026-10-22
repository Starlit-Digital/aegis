package structuralproxy

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Server struct {
	c          Config
	transports []*http.Transport
	slots      chan struct{}
	mu         sync.Mutex
	window     time.Time
	admitted   int
	accepted   atomic.Uint64
	rejected   atomic.Uint64
	failed     atomic.Uint64
}

func New(c Config) (*Server, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	c.Hosts = append([]string(nil), c.Hosts...)
	c.Routes = append([]Route(nil), c.Routes...)
	for i := range c.Routes {
		c.Routes[i].Methods = append([]string(nil), c.Routes[i].Methods...)
		c.Routes[i].Formats = append([]string(nil), c.Routes[i].Formats...)
	}
	sort.Slice(c.Routes, func(i, j int) bool { return len(c.Routes[i].Prefix) > len(c.Routes[j].Prefix) })
	s := &Server{c: c, slots: make(chan struct{}, c.MaxConcurrent)}
	for _, r := range c.Routes {
		socket := r.Socket
		s.transports = append(s.transports, &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", socket)
		}, DisableCompression: true, DisableKeepAlives: true, MaxConnsPerHost: 2, MaxResponseHeaderBytes: 4096, ResponseHeaderTimeout: time.Duration(c.RequestSeconds) * time.Second})
	}
	return s, nil
}
func (s *Server) Close() error {
	for _, t := range s.transports {
		t.CloseIdleConnections()
	}
	return nil
}
func (s *Server) Sweep() {}
func (s *Server) reject(w http.ResponseWriter, status int) {
	s.rejected.Add(1)
	http.Error(w, http.StatusText(status), status)
}
func (s *Server) admit() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Sub(s.window) >= time.Second {
		s.window = now
		s.admitted = 0
	}
	if s.admitted >= 16 {
		return false
	}
	s.admitted++
	return true
}

var forwarded = map[string]bool{"Accept": true, "Accept-Language": true, "Authorization": true, "Cookie": true, "User-Agent": true, "Origin": true, "Referer": true, "X-Csrf-Token": true}

func token(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^`|~", c)) {
			return false
		}
	}
	return true
}
func headerValue(s string) bool {
	for _, c := range s {
		if c == 127 || c < 32 && c != '\t' || c > 126 {
			return false
		}
	}
	return true
}
func headersOK(r *http.Request) bool {
	if len(r.Header) > 32 || len(r.Trailer) > 0 || r.Header.Get("Trailer") != "" || r.Header.Get("Content-Encoding") != "" || r.Header.Get("Expect") != "" || r.Header.Get("Upgrade") != "" {
		return false
	}
	if len(r.TransferEncoding) != 0 {
		return false
	}
	total := 0
	for k, vs := range r.Header {
		total += len(k)
		if !token(k) || strings.Contains(k, "_") || len(vs) != 1 {
			return false
		}
		upper := strings.ToUpper(k)
		if strings.HasPrefix(upper, "X-FORWARDED-") || upper == "FORWARDED" || strings.HasPrefix(upper, "PHP-") || strings.HasPrefix(upper, "PROXY") || upper == "X-ORIGINAL-URL" || upper == "X-REWRITE-URL" {
			return false
		}
		for _, v := range vs {
			total += len(v)
			if !headerValue(v) {
				return false
			}
		}
	}
	return total <= 4096
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	if !s.admit() {
		s.reject(w, 429)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		s.reject(w, 503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.c.RequestSeconds)*time.Second)
	defer cancel()
	deadline := time.Now().Add(time.Duration(s.c.RequestSeconds) * time.Second)
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(deadline)
	_ = rc.SetWriteDeadline(deadline)
	if !contains(s.c.Hosts, r.Host) || r.URL.IsAbs() || r.URL.Host != "" || r.URL.Fragment != "" || r.URL.RawPath != "" || !validPath(r.URL.Path) || r.URL.ForceQuery || len(r.URL.RequestURI()) > 2048 || !headersOK(r) {
		s.reject(w, 400)
		return
	}
	// Administration and staging are never reachable through a catch all route.
	for _, p := range []string{"/healthz", "/metrics", "/Q", "/v1/uploads"} {
		if r.URL.Path == p || strings.HasPrefix(r.URL.Path, p+"/") {
			s.reject(w, 404)
			return
		}
	}
	idx := -1
	for i, route := range s.c.Routes {
		if route.Prefix == "/" || r.URL.Path == route.Prefix || strings.HasPrefix(r.URL.Path, route.Prefix+"/") {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.reject(w, 404)
		return
	}
	route := s.c.Routes[idx]
	if !contains(route.Methods, r.Method) {
		s.reject(w, 405)
		return
	}
	query, e := form([]byte(r.URL.RawQuery))
	if e != nil {
		s.reject(w, 400)
		return
	}
	if r.ContentLength > s.c.MaxBytes {
		s.reject(w, 413)
		return
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, s.c.MaxBytes))
	if e != nil {
		var size *http.MaxBytesError
		if errors.As(e, &size) {
			s.reject(w, 413)
		} else {
			s.reject(w, 400)
		}
		return
	}
	if (r.Method == "GET" || r.Method == "HEAD") && len(b) > 0 {
		s.reject(w, 400)
		return
	}
	b, ct, format, e := normalize(r, b, s.c)
	if e != nil || !contains(route.Formats, format) {
		s.reject(w, 400)
		return
	}
	// Decoding both sources into PHP must not introduce an ambiguous selector.
	if format == "form" || format == "multipart" {
		q, _ := url.ParseQuery(string(query))
		v, _ := url.ParseQuery(string(b))
		for k := range q {
			if _, ok := v[k]; ok {
				s.reject(w, 400)
				return
			}
		}
	}
	upstream := &http.Request{Method: r.Method, URL: &url.URL{Scheme: "http", Host: route.ServerName, Path: r.URL.Path, RawQuery: string(query)}, Host: route.ServerName, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(b)), ContentLength: int64(len(b)), RemoteAddr: r.RemoteAddr}
	if len(b) == 0 {
		upstream.Body = http.NoBody
	}
	upstream = upstream.WithContext(ctx)
	nominated := map[string]bool{}
	for _, h := range strings.Split(r.Header.Get("Connection"), ",") {
		nominated[http.CanonicalHeaderKey(strings.TrimSpace(h))] = true
	}
	for k, v := range r.Header {
		if forwarded[k] && !nominated[k] {
			upstream.Header.Set(k, v[0])
		}
	}
	if ct != "" {
		upstream.Header.Set("Content-Type", ct)
	}
	// No network identity claims are forwarded. Authentication remains the app's job.
	var response *http.Response
	if route.Protocol == "fastcgi" {
		response, e = fcgi(ctx, upstream, route, s.c.MaxResponseBytes)
	} else {
		response, e = s.transports[idx].RoundTrip(upstream)
	}
	if e != nil {
		s.failed.Add(1)
		s.reject(w, 502)
		return
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, s.c.MaxResponseBytes+1))
	if e != nil || int64(len(data)) > s.c.MaxResponseBytes || response.StatusCode < 200 || response.StatusCode > 599 || response.Header.Get("Content-Encoding") != "" || len(response.Trailer) > 0 || (r.Method == "HEAD" && response.ContentLength > s.c.MaxResponseBytes) {
		s.failed.Add(1)
		s.reject(w, 502)
		return
	}
	out, e := responseHeaders(response.Header)
	if e != nil {
		s.failed.Add(1)
		s.reject(w, 502)
		return
	}
	for k, v := range out {
		w.Header()[k] = v
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == "HEAD" && response.ContentLength >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(response.ContentLength, 10))
	} else {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	}
	s.accepted.Add(1)
	w.WriteHeader(response.StatusCode)
	if r.Method != "HEAD" {
		_, _ = w.Write(data)
	}
}
func responseHeaders(h http.Header) (http.Header, error) {
	skip := map[string]bool{}
	for _, k := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Length", "Server", "X-Powered-By", "X-Accel-Redirect", "X-Sendfile"} {
		skip[k] = true
	}
	for _, k := range strings.Split(h.Get("Connection"), ",") {
		skip[http.CanonicalHeaderKey(strings.TrimSpace(k))] = true
	}
	out := make(http.Header)
	total := 0
	for k, vs := range h {
		if !token(k) {
			return nil, errInput
		}
		for _, v := range vs {
			total += len(k) + len(v)
			if !headerValue(v) {
				return nil, errInput
			}
		}
		if !skip[k] {
			out[k] = append([]string(nil), vs...)
		}
	}
	if total > 4096 {
		return nil, errInput
	}
	return out, nil
}

// AdminHandler is installed only on a separate loopback listener with a separate
// local key. Metrics have fixed labels, never URLs, subjects, headers or payloads.
func (s *Server) AdminHandler(key []byte) (http.Handler, error) {
	if len(key) != 32 {
		return nil, errors.New("admin key must be 32 bytes")
	}
	expected := "Bearer " + fmt.Sprintf("%x", key)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" || r.URL.RawQuery != "" || len(r.Header.Values("Authorization")) != 1 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(expected)) != 1 {
			http.Error(w, "unauthorized", 401)
			return
		}
		switch r.URL.Path {
		case "/healthz":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintln(w, "ok")
		case "/metrics":
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			fmt.Fprintf(w, "aegis_proxy_forwarded_total %d\naegis_proxy_rejected_total %d\naegis_proxy_backend_errors_total %d\n", s.accepted.Load(), s.rejected.Load(), s.failed.Load())
		default:
			http.NotFound(w, r)
		}
	}), nil
}
