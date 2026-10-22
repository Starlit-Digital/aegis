package structuralproxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	gofcgi "net/http/fcgi"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, h http.Handler, protocol string) (*Server, *atomic.Int32) {
	t.Helper()
	dir, e := os.MkdirTemp("", "aegis-proxy-test-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "backend.sock")
	ln, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	count := &atomic.Int32{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); h.ServeHTTP(w, r) })
	c := DefaultConfig()
	c.Hosts = []string{"app.test"}
	route := Route{Prefix: "/api", Socket: socket, ServerName: "backend.test", Protocol: protocol, Methods: []string{"GET", "HEAD", "POST"}, Formats: []string{"none", "json", "form", "multipart"}}
	if protocol == "fastcgi" {
		route.ScriptFilename = "/srv/app/public/index.php"
		route.DocumentRoot = "/srv/app/public"
		route.ScriptName = "/index.php"
		route.ServerPort = 443
		route.HTTPS = true
		go gofcgi.Serve(ln, handler)
	} else {
		srv := &http.Server{Handler: handler}
		go srv.Serve(ln)
		t.Cleanup(func() { srv.Close() })
	}
	c.Routes = []Route{route}
	s, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, count
}
func request(s *Server, method, path, ct, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "app.test"
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func TestNormalizedProtocols(t *testing.T) {
	for _, protocol := range []string{"http", "fastcgi"} {
		t.Run(protocol, func(t *testing.T) {
			s, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				if len(r.TransferEncoding) != 0 {
					t.Error("rebuilt request used transfer encoding")
				}
				if r.Host != "backend.test" || r.URL.RawQuery != "a=1&z=%E9%9B%AA" || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("backend request: %s %s %v", r.Host, r.URL, r.Header)
				}
				if protocol == "fastcgi" {
					env := gofcgi.ProcessEnv(r)
					if env["SCRIPT_FILENAME"] != "/srv/app/public/index.php" || r.TLS == nil || env["PHP_VALUE"] != "" {
						t.Errorf("CGI env: %v", env)
					}
				}
				w.Header().Add("Set-Cookie", "a=1")
				w.Header().Add("Set-Cookie", "b=2")
				w.Header().Set("Server", "secret")
				w.Header().Set("X-Accel-Redirect", "/private")
				w.Write(b)
			}), protocol)
			w := request(s, "POST", "/api/x?z=%E9%9B%AA&a=1", "application/json", `{ "z": "雪", "a": 9007199254740993 }`)
			if w.Code != 200 || w.Body.String() != `{"a":9007199254740993,"z":"雪"}` || len(w.Header().Values("Set-Cookie")) != 2 || w.Header().Get("Server") != "" || w.Header().Get("X-Accel-Redirect") != "" {
				t.Fatalf("%d %s %v", w.Code, w.Body, w.Header())
			}
		})
	}
}
func TestRejectedBeforeBackend(t *testing.T) {
	cases := []struct{ path, ct, body, header, value string }{
		{"/apievil", "", "", "", ""}, {"/metrics", "", "", "", ""}, {"/Q/metrics", "", "", "", ""}, {"/v1/uploads", "", "", "", ""},
		{"/api/../secret", "", "", "", ""}, {"/api/%2fsecret", "", "", "", ""}, {"/api/%252e%252e", "", "", "", ""},
		{"/api?a.b=x", "", "", "", ""}, {"/api?a=1&a=2", "", "", "", ""}, {"/api?a[]=1", "", "", "", ""}, {"/api?a=%00", "", "", "", ""}, {"/api?a=%ff", "", "", "", ""},
		{"/api", "application/json", `{"x":1,"x":2}`, "", ""}, {"/api", "application/json", `{"x":"\ud800"}`, "", ""}, {"/api", "application/json", "{\"x\":\"\xff\"}", "", ""},
		{"/api", "application/json", `[] {}`, "", ""}, {"/api", "text/plain", "x", "", ""}, {"/api", "application/x-www-form-urlencoded", "a.b=x", "", ""}, {"/api", "application/x-www-form-urlencoded", "a=x&a=y", "", ""}, {"/api", "application/x-www-form-urlencoded", "PHP_SESSION_UPLOAD_PROGRESS=x", "", ""}, {"/api?a=1", "application/x-www-form-urlencoded", "a=2", "", ""},
		{"/api", "", "", "X-Forwarded-For", "127.0.0.1"}, {"/api", "", "", "PHP_VALUE", "auto_prepend_file=x"}, {"/api", "", "", "Content-Encoding", "gzip"}, {"/api", "", "", "X-Original-URL", "/secret"},
	}
	for i, c := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			s, count := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("rejected request reached backend") }), "http")
			r := httptest.NewRequest("POST", c.path, strings.NewReader(c.body))
			r.Host = "app.test"
			if c.ct != "" {
				r.Header.Set("Content-Type", c.ct)
			}
			if c.header != "" {
				r.Header.Set(c.header, c.value)
			}
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code < 400 || count.Load() != 0 {
				t.Fatalf("%d, calls=%d", w.Code, count.Load())
			}
		})
	}
}
func TestFormsAndMultipart(t *testing.T) {
	for _, files := range []bool{false, true} {
		t.Run(fmt.Sprint(files), func(t *testing.T) {
			s, count := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				if len(r.TransferEncoding) != 0 {
					t.Error("rebuilt request used transfer encoding")
				}
				if string(b) != "name=%E9%9B%AA" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
					t.Error("form not rebuilt", string(b), r.Header)
				}
				w.WriteHeader(204)
			}), "http")
			var b bytes.Buffer
			mw := multipart.NewWriter(&b)
			if files {
				p, _ := mw.CreateFormFile("name", "file.json")
				p.Write([]byte("{}"))
			} else {
				mw.WriteField("name", "雪")
			}
			mw.Close()
			w := request(s, "POST", "/api", mw.FormDataContentType(), b.String())
			if files {
				if w.Code != 400 || count.Load() != 0 {
					t.Fatal(w.Code)
				}
			} else if w.Code != 204 {
				t.Fatal(w.Code, w.Body)
			}
		})
	}
	s, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { b, _ := io.ReadAll(r.Body); w.Write(b) }), "http")
	w := request(s, "POST", "/api", "application/x-www-form-urlencoded", "z=%e9%9b%aa&a=hello%20world")
	if w.Body.String() != "a=hello+world&z=%E9%9B%AA" {
		t.Fatal(w.Body)
	}
}
func TestLimitsAndPrivateMetrics(t *testing.T) {
	s, count := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("x", 128))) }), "http")
	s.c.MaxBytes = 32
	s.c.MaxResponseBytes = 64
	if w := request(s, "POST", "/api", "application/json", strings.Repeat(" ", 33)); w.Code != 413 {
		t.Fatal(w.Code)
	}
	if count.Load() != 0 {
		t.Fatal("oversize forwarded")
	}
	if w := request(s, "GET", "/api", "", ""); w.Code != 502 || strings.Contains(w.Body.String(), "xxxx") {
		t.Fatal(w.Code, w.Body)
	}
	key := bytes.Repeat([]byte{7}, 32)
	h, e := s.AdminHandler(key)
	if e != nil {
		t.Fatal(e)
	}
	for _, authorized := range []bool{false, true} {
		r := httptest.NewRequest("GET", "/metrics", nil)
		if authorized {
			r.Header.Set("Authorization", fmt.Sprintf("Bearer %x", key))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !authorized && w.Code != 401 || authorized && (w.Code != 200 || strings.Contains(w.Body.String(), "api") || !strings.Contains(w.Body.String(), "aegis_proxy_backend_errors_total 1")) {
			t.Fatal(w.Code, w.Body)
		}
	}
}
func TestActualChunkedLimitAndHeaderAmbiguity(t *testing.T) {
	for _, wire := range []string{
		"POST /api HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
		"POST /api HTTP/1.1\r\nHost: app.test\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}",
		"POST /api HTTP/1.1\r\nHost: app.test\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n21\r\n" + strings.Repeat(" ", 33) + "\r\n0\r\n\r\n",
	} {
		t.Run(fmt.Sprint(len(wire)), func(t *testing.T) {
			s, count := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("ambiguous input reached backend") }), "http")
			s.c.MaxBytes = 32
			server := httptest.NewServer(s)
			defer server.Close()
			conn, e := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Second))
			fmt.Fprint(conn, wire)
			var b [256]byte
			n, _ := conn.Read(b[:])
			if n == 0 || !bytes.Contains(b[:n], []byte(" 4")) || count.Load() != 0 {
				t.Fatal(string(b[:n]), count.Load())
			}
		})
	}
}
func TestFastCGIBadResponse(t *testing.T) {
	for _, b := range [][]byte{[]byte("Status: 200 OK\r\nContent-Length: 9\r\n\r\nx"), []byte("Status: 101 Switching\r\n\r\n"), []byte("X: a\r\n folded\r\n\r\n"), []byte("X: a\n\nbody")} {
		if _, e := parseCGI(b, 64, false); e == nil {
			t.Fatalf("accepted %q", b)
		}
	}
	var b bytes.Buffer
	if e := writeRecord(&b, 6, []byte("ok")); e != nil {
		t.Fatal(e)
	}
	if binary.BigEndian.Uint16(b.Bytes()[4:6]) != 2 {
		t.Fatal("invalid record")
	}
}
func TestConfigSnapshotAndCeilings(t *testing.T) {
	s, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), "http")
	c := s.c
	c.Hosts = append([]string(nil), c.Hosts...)
	c.Routes = append([]Route(nil), c.Routes...)
	copyServer, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	defer copyServer.Close()
	c.Hosts[0] = "evil.test"
	c.Routes[0].Methods[0] = "TRACE"
	if copyServer.c.Hosts[0] != "app.test" || copyServer.c.Routes[0].Methods[0] != "GET" {
		t.Fatal("mutable local config")
	}
	c.MaxResponseBytes = 4<<20 + 1
	if c.Validate() == nil {
		t.Fatal("raised ceiling accepted")
	}
}

func TestTimeoutAdmissionAndHeaderFiltering(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	s, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}), "http")
	s.c.RequestSeconds = 1
	done := make(chan *httptest.ResponseRecorder, 2)
	for i := 0; i < 2; i++ {
		go func() { done <- request(s, "GET", "/api", "", "") }()
		<-started
	}
	if w := request(s, "GET", "/api", "", ""); w.Code != 503 {
		t.Fatal("concurrency ceiling", w.Code)
	}
	for i := 0; i < 2; i++ {
		if w := <-done; w.Code != 502 {
			t.Fatal("backend timeout", w.Code)
		}
	}
	close(release)
	s2, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Choose-Socket") != "" {
			t.Error("unsafe header forwarded")
		}
		w.WriteHeader(200)
	}), "http")
	r := httptest.NewRequest("GET", "/api", nil)
	r.Host = "app.test"
	r.Header.Set("Authorization", "secret")
	r.Header.Set("Connection", "Authorization")
	r.Header.Set("X-Choose-Socket", "/tmp/evil.sock")
	w := httptest.NewRecorder()
	s2.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}
func TestPlansAndStrictConfig(t *testing.T) {
	s, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), "http")
	for _, server := range []string{"nginx", "apache", "caddy"} {
		var b bytes.Buffer
		if e := Plan(&b, s.c, "127.0.0.1:8099", server); e != nil || !strings.Contains(b.String(), "127.0.0.1:8099") {
			t.Fatal(server, e, b.String())
		}
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.Routes[0].Methods = nil }, func(c *Config) { c.Routes[0].Formats = nil }, func(c *Config) { c.Routes[0].Socket = "/tmp/../evil" }, func(c *Config) { c.Routes[0].Prefix = "/api/../evil" }, func(c *Config) { c.MaxConcurrent = 3 }} {
		c := s.c
		c.Routes = append([]Route(nil), c.Routes...)
		mutate(&c)
		if c.Validate() == nil {
			t.Fatal("unsafe config accepted")
		}
	}
}
func FuzzCanonicalForm(f *testing.F) {
	for _, seed := range []string{"a=1", "name=%E9%9B%AA", "a[]=1", "x=%ff", "x=%00", "x=1&x=2", "x=%", "x=%252e"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		if len(in) > 4096 {
			return
		}
		out, e := form([]byte(in))
		if e != nil {
			return
		}
		again, e := form(out)
		if e != nil || !bytes.Equal(out, again) {
			t.Fatal("non idempotent form", string(out), string(again), e)
		}
	})
}

func TestHeadRepresentationLength(t *testing.T) {
	for _, protocol := range []string{"http", "fastcgi"} {
		t.Run(protocol, func(t *testing.T) {
			s, _ := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "7")
				w.Write([]byte("payload"))
			}), protocol)
			r := httptest.NewRequest("HEAD", "/api", nil)
			r.Host = "app.test"
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			if w.Code != 200 || w.Header().Get("Content-Length") != "7" || w.Body.Len() != 0 {
				t.Fatal(w.Code, w.Header(), w.Body)
			}
		})
	}
}
func TestFastCGIWireValidation(t *testing.T) {
	for _, kind := range []string{"valid", "wrong-id", "stderr", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			dir, e := os.MkdirTemp("", "aegis-wire-")
			if e != nil {
				t.Fatal(e)
			}
			defer os.RemoveAll(dir)
			socket := filepath.Join(dir, "backend.sock")
			ln, e := net.Listen("unix", socket)
			if e != nil {
				t.Fatal(e)
			}
			defer ln.Close()
			go func() {
				conn, e := ln.Accept()
				if e != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(2 * time.Second))
				for {
					var h [8]byte
					if _, e := io.ReadFull(conn, h[:]); e != nil {
						return
					}
					n := int(binary.BigEndian.Uint16(h[4:6]))
					payload := make([]byte, n+int(h[6]))
					if _, e := io.ReadFull(conn, payload); e != nil {
						return
					}
					if h[1] == 5 && n == 0 {
						break
					}
				}
				switch kind {
				case "wrong-id":
					conn.Write([]byte{1, 6, 0, 2, 0, 0, 0, 0})
					return
				case "stderr":
					writeRecord(conn, 7, bytes.Repeat([]byte{'x'}, 8193))
					return
				case "oversize":
					writeRecord(conn, 6, bytes.Repeat([]byte{'x'}, 5000))
					return
				}
				writeRecord(conn, 6, []byte("Content-Type: text/plain\r\n\r\nok"))
				writeRecord(conn, 3, make([]byte, 8))
			}()
			c := DefaultConfig()
			c.Hosts = []string{"app.test"}
			c.MaxResponseBytes = 64
			c.Routes = []Route{{Prefix: "/api", Protocol: "fastcgi", Socket: socket, ServerName: "app.test", DocumentRoot: "/srv/app", ScriptFilename: "/srv/app/index.php", ScriptName: "/index.php", ServerPort: 443, HTTPS: true, Methods: []string{"GET"}, Formats: []string{"none"}}}
			s, e := New(c)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			w := request(s, "GET", "/api", "", "")
			want := 502
			if kind == "valid" {
				want = 200
			}
			if w.Code != want {
				t.Fatal(w.Code, w.Body)
			}
		})
	}
}

func TestLocalJSONLimits(t *testing.T) {
	for _, configure := range []func(*Config){func(c *Config) { c.MaxDepth = 1 }, func(c *Config) { c.MaxTokens = 2 }, func(c *Config) { c.MaxStringBytes = 1 }} {
		s, count := fixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("parser limit bypassed") }), "http")
		configure(&s.c)
		r := httptest.NewRequest("POST", "/api", strings.NewReader(`{"name":{"nested":"value"}}`))
		r.Host = "app.test"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Max-Depth", "16")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 400 || count.Load() != 0 {
			t.Fatal(w.Code, count.Load())
		}
	}
}
