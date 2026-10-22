package gateway

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type object struct {
	subject, path, digest, format string
	bytes                         int64
	expires                       time.Time
	ready                         bool
}
type Server struct {
	lock       *os.File
	rateWindow time.Time
	requests   int
	c          Config
	key        []byte
	storageKey []byte
	dir        string
	mu         sync.Mutex
	objects    map[string]object
	used       map[string]time.Time
	slots      chan struct{}
	now        func() time.Time
}

func New(c Config, key, storageKey []byte, dir string) (*Server, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if len(key) != 32 || len(storageKey) != 32 || string(key) == string(storageKey) {
		return nil, errors.New("distinct 32 byte keys required")
	}
	info, e := os.Lstat(dir)
	if e != nil {
		return nil, e
	}
	if !info.IsDir() || info.Mode()&0077 != 0 {
		return nil, errors.New("staging directory must be private and not a symlink")
	}
	// A new private session directory means restart never revives old tickets or objects.
	lock, e := lockSpool(dir)
	if e != nil {
		return nil, e
	}
	keepLock := false
	defer func() {
		if !keepLock {
			lock.Close()
		}
	}()
	entries, e := os.ReadDir(dir)
	if e != nil {
		return nil, e
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "aegis-session-") {
			if e := os.RemoveAll(dir + string(os.PathSeparator) + entry.Name()); e != nil {
				return nil, e
			}
		}
	}
	session, e := os.MkdirTemp(dir, "aegis-session-")
	if e != nil {
		return nil, e
	}
	c.Origins = append([]string(nil), c.Origins...)
	used, e := loadGrants(dir, time.Now())
	if e != nil {
		os.RemoveAll(session)
		return nil, e
	}
	keepLock = true
	return &Server{lock: lock, c: c, key: append([]byte(nil), key...), storageKey: append([]byte(nil), storageKey...), dir: session, objects: map[string]object{}, used: used, slots: make(chan struct{}, c.MaxConcurrent), now: time.Now}, nil
}

// Close is called after HTTP shutdown has drained handlers.
func (s *Server) Close() error {
	clear(s.key)
	clear(s.storageKey)
	e := os.RemoveAll(s.dir)
	if s.lock != nil {
		s.lock.Close()
	}
	return e
}
func (s *Server) sweep() {
	now := s.now()
	for id, o := range s.objects {
		if o.ready && !now.Before(o.expires) {
			if e := os.Remove(o.path); e == nil || os.IsNotExist(e) {
				delete(s.objects, id)
			}
		}
	}
	for id, exp := range s.used {
		if !now.Before(exp) {
			if e := os.Remove(grantPath(s.dir, id)); e == nil || os.IsNotExist(e) {
				delete(s.used, id)
			}
		}
	}
}
func (s *Server) Sweep()                     { s.mu.Lock(); defer s.mu.Unlock(); s.sweep() }
func fail(w http.ResponseWriter, status int) { http.Error(w, http.StatusText(status), status) }
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	s.mu.Lock()
	now := s.now()
	if s.rateWindow.IsZero() || !now.Before(s.rateWindow.Add(time.Second)) {
		s.rateWindow = now
		s.requests = 0
	}
	s.requests++
	limited := s.requests > 16
	s.mu.Unlock()
	if limited {
		fail(w, 429)
		return
	}
	if r.URL.RawQuery != "" || r.URL.RawPath != "" || r.URL.Path != "/v1/uploads" || r.Host == "" {
		fail(w, 404)
		return
	}
	if r.Method != "PUT" && r.Method != "GET" && r.Method != "DELETE" {
		w.Header().Set("Allow", "PUT, GET, DELETE")
		fail(w, 405)
		return
	}
	// Never use proxy headers for identity, size, scheme or admission decisions.
	if len(r.Header) > 32 {
		fail(w, 431)
		return
	}
	for k, v := range r.Header {
		lower := strings.ToLower(k)
		if len(v) != 1 || strings.HasPrefix(lower, "x-forwarded-") || lower == "forwarded" || lower == "x-real-ip" || lower == "php-value" || lower == "php-admin-value" || lower == "trailer" || lower == "content-encoding" {
			fail(w, 400)
			return
		}
	}
	if len(r.Trailer) > 0 || len(r.TransferEncoding) > 1 || (len(r.TransferEncoding) == 1 && r.TransferEncoding[0] != "chunked") {
		fail(w, 400)
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" {
		ok := false
		for _, v := range s.c.Origins {
			if origin == v {
				ok = true
			}
		}
		if !ok {
			fail(w, 403)
			return
		}
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		fail(w, 401)
		return
	}
	t, e := verify(s.key, strings.TrimPrefix(auth, "Bearer "), s.c, s.now())
	if e != nil {
		fail(w, 401)
		return
	}
	op := map[string]string{"PUT": "upload", "GET": "read", "DELETE": "delete"}[r.Method]
	if t.Operation != op {
		fail(w, 403)
		return
	}
	// Requests do not wait in an unbounded application queue.
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		fail(w, 503)
		return
	}
	controller := http.NewResponseController(w)
	deadline := s.now().Add(s.c.Deadline())
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline)
	if r.Method == "PUT" {
		s.upload(w, r, t)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		fail(w, 400)
		return
	}
	s.retrieve(w, r, t)
}
func (s *Server) upload(w http.ResponseWriter, r *http.Request, t Ticket) {
	if r.ContentLength > s.c.MaxBytes {
		fail(w, 413)
		return
	}
	format, params, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || format != s.c.ContentType {
		fail(w, 415)
		return
	}
	for k, v := range params {
		if format != "application/json" || k != "charset" || !strings.EqualFold(v, "utf-8") {
			fail(w, 415)
			return
		}
	}
	s.mu.Lock()
	s.sweep()
	count := 0
	for _, o := range s.objects {
		if o.subject == t.Subject {
			count++
		}
	}
	if _, ok := s.used[t.ID]; ok {
		s.mu.Unlock()
		fail(w, 409)
		return
	}
	if _, ok := s.objects[t.ID]; ok {
		s.mu.Unlock()
		fail(w, 409)
		return
	}
	if len(s.used) >= 1024 || len(s.objects) >= s.c.MaxStaged || count >= s.c.MaxPerSubject {
		s.mu.Unlock()
		fail(w, 429)
		return
	}
	// Burn the grant before reading any bytes, including failed attempts.
	if e := burnGrant(s.dir, t.ID, t.Expires); e != nil {
		s.mu.Unlock()
		if os.IsExist(e) {
			fail(w, 409)
		} else {
			fail(w, 500)
		}
		return
	}
	s.used[t.ID] = time.Unix(t.Expires, 0)
	s.objects[t.ID] = object{subject: t.Subject}
	s.mu.Unlock()
	complete := false
	var path string
	defer func() {
		if !complete {
			s.mu.Lock()
			defer s.mu.Unlock()
			if path != "" {
				if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
					s.objects[t.ID] = object{subject: t.Subject, path: path, expires: s.now(), ready: true}
					return
				}
			}
			delete(s.objects, t.ID)
		}
	}()

	file, e := os.CreateTemp(s.dir, "object-*.stage")
	if e != nil {
		fail(w, 500)
		return
	}
	path = file.Name()
	defer file.Close()
	h := sha256.New()
	a, e := s.objectAEAD(t.ID, t.Subject)
	if e != nil {
		fail(w, 500)
		return
	}
	ew := &encryptedWriter{w: file, a: a, id: t.ID, buf: make([]byte, 0, chunkSize)}
	defer clear(ew.buf)
	limited := http.MaxBytesReader(w, r.Body, s.c.MaxBytes)
	var bytesRead int64
	counted := &countReader{r: limited, n: &bytesRead}
	escapes := &escapeValidator{}
	var sink io.Writer = io.MultiWriter(ew, h)
	if format == "application/json" {
		sink = io.MultiWriter(escapes, ew, h)
	}
	input := io.TeeReader(counted, sink)
	if format == "application/json" {
		e = validateJSON(&utf8Reader{r: bufio.NewReaderSize(input, 4096)}, s.c)
	} else {
		_, e = io.CopyBuffer(io.Discard, input, make([]byte, chunkSize))
	}
	if e != nil {
		var tooBig *http.MaxBytesError
		if errors.As(e, &tooBig) {
			fail(w, 413)
		} else {
			fail(w, 400)
		}
		return
	}
	if format == "application/json" && escapes.Finish() != nil {
		fail(w, 400)
		return
	}
	if bytesRead == 0 {
		fail(w, 400)
		return
	}
	if e = ew.flush(); e != nil {
		fail(w, 500)
		return
	}
	if e = file.Close(); e != nil {
		fail(w, 500)
		return
	}
	digest := hex.EncodeToString(h.Sum(nil))
	expires := s.now().Add(time.Duration(s.c.RetentionSeconds) * time.Second)
	s.mu.Lock()
	s.objects[t.ID] = object{t.Subject, path, digest, format, bytesRead, expires, true}
	s.mu.Unlock()
	complete = true
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	json.NewEncoder(w).Encode(map[string]any{"id": t.ID, "bytes": bytesRead, "sha256": digest, "expires_at": expires.UTC().Format(time.RFC3339)})
}

type countReader struct {
	r io.Reader
	n *int64
}

func (c *countReader) Read(p []byte) (int, error) { n, e := c.r.Read(p); *c.n += int64(n); return n, e }
func (s *Server) retrieve(w http.ResponseWriter, r *http.Request, t Ticket) {
	s.mu.Lock()
	s.sweep()
	o, ok := s.objects[t.ID]
	if !ok || !o.ready || o.subject != t.Subject || !s.now().Before(o.expires) {
		s.mu.Unlock()
		fail(w, 404)
		return
	}
	var f *os.File
	if r.Method == "GET" {
		var e error
		f, e = os.Open(o.path)
		if e != nil {
			s.mu.Unlock()
			fail(w, 500)
			return
		}
	}
	if e := os.Remove(o.path); e != nil {
		if f != nil {
			f.Close()
		}
		s.mu.Unlock()
		fail(w, 500)
		return
	}
	delete(s.objects, t.ID)
	s.mu.Unlock()
	if r.Method == "DELETE" {
		w.WriteHeader(204)
		return
	}
	defer f.Close()

	a, e := s.objectAEAD(t.ID, t.Subject)
	if e != nil {
		fail(w, 500)
		return
	}
	// Authenticate every chunk and the complete expected length before releasing bytes.
	if e := decrypt(io.Discard, f, a, t.ID, o.bytes); e != nil {
		fail(w, 500)
		return
	}
	if _, e := f.Seek(0, io.SeekStart); e != nil {
		fail(w, 500)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=staged-upload.bin")
	w.Header().Set("Content-Length", fmt.Sprint(o.bytes))
	w.Header().Set("X-aegis-SHA256", o.digest)
	// The spool is private to the service user; OS sandboxing prevents other writers.
	if e := decrypt(w, f, a, t.ID, o.bytes); e != nil {
		panic(http.ErrAbortHandler)
	}
}

// A separate derived key per user, purpose and object keeps GCM nonce use small.
func (s *Server) objectAEAD(id, subject string) (cipher.AEAD, error) {
	mac := hmac.New(sha256.New, s.storageKey)
	mac.Write([]byte("aegis-object-v1\x00" + s.c.Purpose + "\x00" + subject + "\x00" + id))
	key := mac.Sum(nil)
	defer clear(key)
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
