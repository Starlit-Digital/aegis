package gateway

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"time"
)

// SelfTest uses disposable keys and a real loopback HTTP server, then removes both.
func SelfTest(out io.Writer) error {
	dir, e := os.MkdirTemp("", "aegis-selftest-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(dir)
	key := make([]byte, 32)
	storage := make([]byte, 32)
	if _, e = rand.Read(key); e != nil {
		return e
	}
	if _, e = rand.Read(storage); e != nil {
		return e
	}
	defer clear(key)
	defer clear(storage)
	g, e := New(DefaultConfig(), key, storage, dir)
	if e != nil {
		return e
	}
	defer g.Close()
	srv := httptest.NewServer(g)
	defer srv.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	ticket := func(id, op string) string {
		v, _ := Sign(key, Ticket{"account-import", "aegis-staging-v1", id, "demo", op, time.Now().Add(30 * time.Second).Unix()})
		return v
	}
	call := func(method, id, format string, b []byte) (int, []byte, error) {
		r, e := http.NewRequest(method, srv.URL+"/v1/uploads", bytes.NewReader(b))
		if e != nil {
			return 0, nil, e
		}
		op := map[string]string{"PUT": "upload", "GET": "read"}[method]
		r.Header.Set("Authorization", "Bearer "+ticket(id, op))
		if format != "" {
			r.Header.Set("Content-Type", format)
		}
		res, e := client.Do(r)
		if e != nil {
			return 0, nil, e
		}
		defer res.Body.Close()
		data, e := io.ReadAll(res.Body)
		return res.StatusCode, data, e
	}
	fmt.Fprintln(out, "Aegis selftest | disposable loopback session")
	good := []byte(`{"name":"Zoë 東京 🛡️","records":[1,2,3]}`)
	id := "0123456789abcdef0123456789abcdef"
	status, _, e := call("PUT", id, "application/json", good)
	if e != nil || status != 201 {
		return fmt.Errorf("upload: status=%d error=%v", status, e)
	}
	fmt.Fprintln(out, "PASS  streamed UTF 8 JSON accepted; encrypted staging")
	status, _, e = call("PUT", id, "application/json", good)
	if e != nil || status != 409 {
		return fmt.Errorf("replay: %d %v", status, e)
	}
	fmt.Fprintln(out, "PASS  replay rejected")
	status, b, e := call("GET", id, "", nil)
	if e != nil || status != 200 || !bytes.Equal(b, good) {
		return fmt.Errorf("round trip: %d %v", status, e)
	}
	fmt.Fprintln(out, "PASS  authenticated single use retrieval matches original bytes")
	status, _, e = call("GET", id, "", nil)
	if e != nil || status != 404 {
		return fmt.Errorf("read replay: %d %v", status, e)
	}
	fmt.Fprintln(out, "PASS  consumed object unavailable")
	status, _, e = call("PUT", "1123456789abcdef0123456789abcdef", "application/json", []byte{'"', 0xff, '"'})
	if e != nil || status != 400 {
		return fmt.Errorf("UTF 8: %d %v", status, e)
	}
	fmt.Fprintln(out, "PASS  malformed UTF 8 rejected")
	status, _, e = call("PUT", "2123456789abcdef0123456789abcdef", "application/octet-stream", make([]byte, DefaultConfig().MaxBytes+1))
	if e != nil || status != 413 {
		return fmt.Errorf("byte limit: %d %v", status, e)
	}
	fmt.Fprintln(out, "PASS  body above local byte ceiling rejected")
	fmt.Fprintln(out, "PASS  local test complete; server closed and staging removed on return")
	return nil
}
