package gateway

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func setup(t *testing.T) (*Server, []byte) { return setupPolicy(t, DefaultConfig()) }
func setupPolicy(t *testing.T, policy Config) (*Server, []byte) {
	t.Helper()
	key := bytes.Repeat([]byte{1}, 32)
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := New(policy, key, bytes.Repeat([]byte{2}, 32), dir)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s, key
}
func grant(t *testing.T, key []byte, id, sub, op string, exp time.Time) string {
	t.Helper()
	v, e := Sign(key, Ticket{"account-import", "aegis-staging-v1", id, sub, op, exp.Unix()})
	if e != nil {
		t.Fatal(e)
	}
	return v
}

const testID = "0123456789abcdef0123456789abcdef"

func request(t *testing.T, s *Server, key []byte, method, id, sub, body string, edit func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://localhost/v1/uploads", strings.NewReader(body))
	op := map[string]string{"PUT": "upload", "GET": "read", "DELETE": "delete"}[method]
	r.Header.Set("Authorization", "Bearer "+grant(t, key, id, sub, op, s.now().Add(30*time.Second)))
	if method == "PUT" {
		r.Header.Set("Content-Type", "application/json")
	}
	if edit != nil {
		edit(r)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func TestEncryptedRoundTripOwnershipAndConsumption(t *testing.T) {
	s, k := setup(t)
	body := `{"name":"Zoë 東京 🛡️","items":[1,true,null]}`
	w := request(t, s, k, "PUT", testID, "alice", body, nil)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var receipt struct {
		SHA256 string `json:"sha256"`
		Bytes  int    `json:"bytes"`
	}
	json.Unmarshal(w.Body.Bytes(), &receipt)
	h := sha256.Sum256([]byte(body))
	if receipt.SHA256 != hex.EncodeToString(h[:]) || receipt.Bytes != len(body) {
		t.Fatal("receipt mismatch")
	}
	data, e := os.ReadFile(s.objects[testID].path)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(data, []byte("Zoë")) || bytes.Contains(data, []byte(body)) {
		t.Fatal("plaintext at rest")
	}
	if w = request(t, s, k, "GET", testID, "bob", "", nil); w.Code != 404 {
		t.Fatal("cross subject read", w.Code)
	}
	if w = request(t, s, k, "PUT", testID, "alice", body, nil); w.Code != 409 {
		t.Fatal("replay", w.Code)
	}
	if w = request(t, s, k, "GET", testID, "alice", "", nil); w.Code != 200 || w.Body.String() != body {
		t.Fatal("round trip", w.Code, w.Body.String())
	}
	if w = request(t, s, k, "GET", testID, "alice", "", nil); w.Code != 404 {
		t.Fatal("read replay", w.Code)
	}
	files, _ := os.ReadDir(s.dir)
	if len(files) != 0 {
		t.Fatal("staging retained")
	}
}
func TestInputRejections(t *testing.T) {
	cases := []struct {
		name, body string
		edit       func(*http.Request)
		status     int
	}{
		{"invalid_utf8", string([]byte{'"', 0xff, '"'}), nil, 400},
		{"lone_high_surrogate", `{"name":"\ud800"}`, nil, 400},
		{"lone_low_surrogate", `{"name":"\udfff"}`, nil, 400},
		{"duplicate_keys", `{"a":1,"a":2}`, nil, 400},
		{"nested_duplicate", `{"a":{"b":1,"b":2}}`, nil, 400},
		{"trailing_value", `{} {}`, nil, 400},
		{"depth", strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17), nil, 400},
		{"long_string", `{"a":"` + strings.Repeat("a", 4097) + `"}`, nil, 400},
		{"token_limit", "[" + strings.Repeat("0,", 10000) + "0]", nil, 400},
		{"malformed", `{"a":`, nil, 400},
		{"empty", "", nil, 400},
		{"compression", `{}`, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 400},
		{"charset", `{}`, func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=iso-8859-1") }, 415},
		{"parser_bypass_type", `{}`, func(r *http.Request) { r.Header.Set("Content-Type", "application/octet-stream") }, 415},
		{"multipart", `{}`, func(r *http.Request) { r.Header.Set("Content-Type", "multipart/form-data; boundary=x") }, 415},
		{"duplicate_auth", `{}`, func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) }, 400},
		{"proxy_identity", `{}`, func(r *http.Request) { r.Header.Set("X-Forwarded-For", "127.0.0.1") }, 400},
		{"untrusted_origin", `{}`, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, 403},
		{"oversize_declared", `{}`, func(r *http.Request) { r.ContentLength = 1<<20 + 1 }, 413},
		{"oversize_chunked", strings.Repeat(" ", 1<<20) + `{}`, func(r *http.Request) { r.ContentLength = -1; r.TransferEncoding = []string{"chunked"} }, 413},
		{"query_policy", `{}`, func(r *http.Request) { r.URL.RawQuery = "max_bytes=99999999" }, 404},
		{"header_policy", strings.Repeat(" ", 1<<20) + `{}`, func(r *http.Request) { r.Header.Set("X-Aegis-Max-Bytes", "99999999"); r.ContentLength = -1 }, 413},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, k := setup(t)
			w := request(t, s, k, "PUT", testID, "alice", tc.body, tc.edit)
			if w.Code != tc.status {
				t.Fatalf("got %d want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if len(s.objects) != 0 {
				t.Fatal("failed upload retained")
			}
			files, _ := os.ReadDir(s.dir)
			if len(files) != 0 {
				t.Fatal("failed bytes retained")
			}
		})
	}
}
func TestTicketAndPolicy(t *testing.T) {
	s, k := setup(t)
	for _, tc := range []struct {
		name   string
		edit   func(*http.Request)
		status int
	}{
		{"no_auth", func(r *http.Request) { r.Header.Del("Authorization") }, 401},
		{"tamper", func(r *http.Request) { r.Header.Set("Authorization", r.Header.Get("Authorization")+"x") }, 401},
		{"expiry", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+grant(t, k, testID, "alice", "upload", s.now().Add(-time.Second)))
		}, 401},
		{"future", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+grant(t, k, testID, "alice", "upload", s.now().Add(time.Hour)))
		}, 401},
		{"wrong_purpose", func(r *http.Request) {
			token, _ := Sign(k, Ticket{Purpose: "different-workflow", Audience: "aegis-staging-v1", ID: testID, Subject: "alice", Operation: "upload", Expires: s.now().Add(30 * time.Second).Unix()})
			r.Header.Set("Authorization", "Bearer "+token)
		}, 401},
		{"wrong_op", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+grant(t, k, testID, "alice", "read", s.now().Add(30*time.Second)))
		}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := request(t, s, k, "PUT", testID, "alice", `{}`, tc.edit)
			if w.Code != tc.status {
				t.Fatal(w.Code)
			}
		})
	}
	c := DefaultConfig()
	c.MaxBytes++
	if c.Validate() == nil {
		t.Fatal("config can raise ceiling")
	}
	c = DefaultConfig()
	c.MaxConcurrent++
	if c.Validate() == nil {
		t.Fatal("concurrency ceiling")
	}
}
func TestRetentionAndQuotas(t *testing.T) {
	s, k := setup(t)
	now := time.Now()
	s.now = func() time.Time { return now }
	for _, id := range []string{testID, "1123456789abcdef0123456789abcdef"} {
		if w := request(t, s, k, "PUT", id, "alice", `{}`, nil); w.Code != 201 {
			t.Fatal(w.Code)
		}
	}
	if w := request(t, s, k, "PUT", "2123456789abcdef0123456789abcdef", "alice", `{}`, nil); w.Code != 429 {
		t.Fatal("subject quota", w.Code)
	}
	now = now.Add(301 * time.Second)
	s.Sweep()
	if len(s.objects) != 0 || len(s.used) != 0 {
		t.Fatal("expiry retained state")
	}
	files, _ := os.ReadDir(s.dir)
	if len(files) != 0 {
		t.Fatal("expired files retained")
	}
}
func TestCorruptCiphertextIsNeverReleased(t *testing.T) {
	s, k := setup(t)
	request(t, s, k, "PUT", testID, "alice", `{"sensitive":"payroll"}`, nil)
	o := s.objects[testID]
	b, _ := os.ReadFile(o.path)
	b[len(b)-1] ^= 1
	os.WriteFile(o.path, b, 0600)
	w := request(t, s, k, "GET", testID, "alice", "", nil)
	if w.Code != 500 || strings.Contains(w.Body.String(), "payroll") {
		t.Fatal("tampered ciphertext released", w.Code)
	}
}
func TestBinaryAndUTF8Boundary(t *testing.T) {
	c := DefaultConfig()
	c.ContentType = "application/octet-stream"
	s, k := setupPolicy(t, c)
	body := strings.Repeat("a", 32767) + "東京"
	w := request(t, s, k, "PUT", testID, "alice", body, func(r *http.Request) { r.Header.Set("Content-Type", "application/octet-stream") })
	if w.Code != 201 {
		t.Fatal(w.Code)
	}
	w = request(t, s, k, "GET", testID, "alice", "", nil)
	if w.Body.String() != body {
		t.Fatal("chunk boundary corruption")
	}
	// One byte reads force all Unicode code points across reader boundaries.
	raw := `{"name":"東京🛡️"}`
	if e := validateJSON(&utf8Reader{r: bufio.NewReader(&oneByteReader{r: strings.NewReader(raw)})}, DefaultConfig()); e != nil {
		t.Fatal(e)
	}
}

type oneByteReader struct{ r io.Reader }

func (r *oneByteReader) Read(p []byte) (int, error) { return r.r.Read(p[:1]) }
func TestConcurrentTicketSingleWinner(t *testing.T) {
	s, k := setup(t)
	var wg sync.WaitGroup
	results := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- request(t, s, k, "PUT", testID, "alice", `{}`, nil).Code }()
	}
	wg.Wait()
	close(results)
	wins := 0
	for code := range results {
		if code == 201 {
			wins++
		} else if code != 409 && code != 503 {
			t.Fatal(code)
		}
	}
	if wins != 1 {
		t.Fatal("duplicate winners", wins)
	}
}
func TestSelfTest(t *testing.T) {
	if e := SelfTest(io.Discard); e != nil {
		t.Fatal(e)
	}
}

func TestSpoolExclusiveAndCrashCleanup(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	k := bytes.Repeat([]byte{1}, 32)
	sk := bytes.Repeat([]byte{2}, 32)
	s, e := New(DefaultConfig(), k, sk, dir)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := New(DefaultConfig(), k, sk, dir); e == nil {
		second.Close()
		t.Fatal("two spool owners")
	}
	old := s.dir
	os.WriteFile(old+"/orphan.stage", []byte("ciphertext"), 0600)
	s.lock.Close()
	next, e := New(DefaultConfig(), k, sk, dir)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	if _, e = os.Stat(old); !os.IsNotExist(e) {
		t.Fatal("crash leftovers retained")
	}
}
func TestGlobalRateAndStagingLimits(t *testing.T) {
	s, k := setup(t)
	for i := 0; i < 16; i++ {
		request(t, s, k, "GET", testID, "alice", "", nil)
	}
	if w := request(t, s, k, "GET", testID, "alice", "", nil); w.Code != 429 {
		t.Fatal("rate admission", w.Code)
	}
	s, k = setup(t)
	for i := 0; i < 16; i++ {
		id := fmt.Sprintf("%032x", i)
		if w := request(t, s, k, "PUT", id, fmt.Sprint("actor", i), `{}`, nil); w.Code != 201 {
			t.Fatal(w.Code)
		}
	}
	s.rateWindow = time.Now().Add(-2 * time.Second)
	if w := request(t, s, k, "PUT", "ffffffffffffffffffffffffffffffff", "newactor", `{}`, nil); w.Code != 429 {
		t.Fatal("staging cap", w.Code)
	}
}

func TestUploadReplaySurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	key := bytes.Repeat([]byte{1}, 32)
	sk := bytes.Repeat([]byte{2}, 32)
	s, e := New(DefaultConfig(), key, sk, dir)
	if e != nil {
		t.Fatal(e)
	}
	w := request(t, s, key, "PUT", testID, "alice", `{}`, nil)
	if w.Code != 201 {
		t.Fatal(w.Code)
	}
	s.Close()
	next, e := New(DefaultConfig(), key, sk, dir)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	if w = request(t, next, key, "PUT", testID, "alice", `{}`, nil); w.Code != 409 {
		t.Fatal("replayed across restart", w.Code)
	}
}
func TestValidSurrogatesAndFailedGrantBurn(t *testing.T) {
	s, k := setup(t)
	w := request(t, s, k, "PUT", testID, "alice", `{"emoji":"\ud83d\udee1"}`, nil)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	id := "1123456789abcdef0123456789abcdef"
	if w = request(t, s, k, "PUT", id, "alice", `{"emoji":"\ud800"}`, nil); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w = request(t, s, k, "PUT", id, "alice", `{}`, nil); w.Code != 409 {
		t.Fatal("failed grant reused", w.Code)
	}
}
