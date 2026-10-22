package gateway

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const chunkSize = 32 * 1024

// Each independently authenticated chunk binds its order and object identity.
type encryptedWriter struct {
	w     io.Writer
	a     cipher.AEAD
	id    string
	buf   []byte
	index uint64
}

func (w *encryptedWriter) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		n := chunkSize - len(w.buf)
		if n > len(p) {
			n = len(p)
		}
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		if len(w.buf) == chunkSize {
			if e := w.flush(); e != nil {
				return 0, e
			}
		}
	}
	return total, nil
}
func (w *encryptedWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	nonce := make([]byte, w.a.NonceSize())
	if _, e := io.ReadFull(rand.Reader, nonce); e != nil {
		return e
	}
	aad := []byte(w.id)
	aad = binary.BigEndian.AppendUint64(aad, w.index)
	sealed := w.a.Seal(nil, nonce, w.buf, aad)
	frame := binary.BigEndian.AppendUint32(nil, uint32(len(sealed)))
	frame = append(frame, nonce...)
	frame = append(frame, sealed...)
	_, e := w.w.Write(frame)
	clear(w.buf)
	w.buf = w.buf[:0]
	w.index++
	return e
}
func decrypt(w io.Writer, r io.Reader, a cipher.AEAD, id string, expected int64) error {
	var index uint64
	var total int64
	for {
		var size [4]byte
		_, e := io.ReadFull(r, size[:])
		if e == io.EOF {
			if total != expected {
				return errors.New("truncated object")
			}
			return nil
		}
		if e != nil {
			return e
		}
		n := binary.BigEndian.Uint32(size[:])
		if n < uint32(a.Overhead()+1) || n > chunkSize+uint32(a.Overhead()) {
			return errors.New("invalid frame")
		}
		nonce := make([]byte, a.NonceSize())
		if _, e = io.ReadFull(r, nonce); e != nil {
			return e
		}
		b := make([]byte, n)
		if _, e = io.ReadFull(r, b); e != nil {
			return e
		}
		aad := binary.BigEndian.AppendUint64([]byte(id), index)
		plain, e := a.Open(nil, nonce, b, aad)
		if e != nil {
			return e
		}
		total += int64(len(plain))
		if total > expected {
			clear(plain)
			return errors.New("invalid length")
		}
		_, e = w.Write(plain)
		clear(plain)
		if e != nil {
			return e
		}
		index++
	}
}

// UTF8Reader validates across read boundaries before JSON can replace bad bytes.
type utf8Reader struct {
	r   *bufio.Reader
	err error
}

func (r *utf8Reader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	n := 0
	for len(p)-n >= utf8.UTFMax {
		v, size, e := r.r.ReadRune()
		if e != nil {
			r.err = e
			if e == io.EOF && n > 0 {
				return n, nil
			}
			return n, e
		}
		if v == utf8.RuneError && size == 1 {
			r.err = errors.New("invalid UTF-8")
			return n, r.err
		}
		n += utf8.EncodeRune(p[n:], v)
	}
	if n == 0 && len(p) > 0 {
		return 0, io.ErrShortBuffer
	}
	return n, nil
}

// validateJSON keeps parser state bounded and rejects duplicate keys and trailing values.
func validateJSON(r io.Reader, c Config) error {
	d := json.NewDecoder(r)
	d.UseNumber()
	count := 0
	var value func(int) error
	next := func() (json.Token, error) {
		count++
		if count > c.MaxTokens {
			return nil, errors.New("token limit")
		}
		t, e := d.Token()
		if number, ok := t.(json.Number); ok && len(number) > 128 {
			return nil, errors.New("number limit")
		}
		if s, ok := t.(string); ok && len(s) > c.MaxStringBytes {
			return nil, errors.New("string limit")
		}
		return t, e
	}
	value = func(depth int) error {
		if depth > c.MaxDepth {
			return errors.New("depth limit")
		}
		t, e := next()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		if delim != '{' && delim != '[' {
			return errors.New("invalid delimiter")
		}
		keys := map[string]bool{}
		for d.More() {
			if delim == '{' {
				k, e := next()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || keys[s] {
					return errors.New("duplicate or invalid key")
				}
				keys[s] = true
			}
			if e := value(depth + 1); e != nil {
				return e
			}
		}
		end, e := next()
		if e != nil {
			return e
		}
		if (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
			return errors.New("invalid close")
		}
		return nil
	}
	if e := value(1); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
