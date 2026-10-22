package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Starlit-Digital/aegis/internal/gateway"
	"github.com/Starlit-Digital/aegis/internal/structuralproxy"
)

var version = "0.2.0"

type localConfig struct {
	Mode           string                 `json:"mode"`
	Proxy          structuralproxy.Config `json:"proxy"`
	AdminListen    string                 `json:"admin_listen"`
	AdminKeyFile   string                 `json:"admin_key_file"`
	Enabled        bool                   `json:"enabled"`
	Listen         string                 `json:"listen"`
	StagingDir     string                 `json:"staging_dir"`
	TokenKeyFile   string                 `json:"token_key_file"`
	StorageKeyFile string                 `json:"storage_key_file"`
	Policy         gateway.Config         `json:"policy"`
}

func load(path string) (localConfig, error) {
	c := localConfig{Listen: "127.0.0.1:8098", Policy: gateway.DefaultConfig(), Mode: "staging", Proxy: structuralproxy.DefaultConfig()}
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > 16384 {
		return c, errors.New("config must be a regular file of at most 16 KiB")
	}
	d := json.NewDecoder(io.LimitReader(f, 16385))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("invalid config suffix")
	}
	if e = c.Policy.Validate(); e != nil {
		return c, e
	}
	host, _, e := net.SplitHostPort(c.Listen)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return c, errors.New("listen must be a literal loopback IP and port")
	}
	if c.Mode == "proxy" {
		if e = c.Proxy.Validate(); e != nil {
			return c, e
		}
		if (c.AdminListen == "") != (c.AdminKeyFile == "") {
			return c, errors.New("admin listener and key must be configured together")
		}
		if c.AdminListen != "" {
			h, _, err := net.SplitHostPort(c.AdminListen)
			if err != nil || net.ParseIP(h) == nil || !net.ParseIP(h).IsLoopback() || c.AdminListen == c.Listen || !filepath.IsAbs(c.AdminKeyFile) {
				return c, errors.New("separate loopback admin listener and local key required")
			}
		}
		return c, nil
	}
	if c.Mode != "staging" {
		return c, errors.New("unknown mode")
	}
	if c.AdminListen != "" || c.AdminKeyFile != "" {
		return c, errors.New("admin listener only supported in proxy mode")
	}
	if !filepath.IsAbs(c.StagingDir) || !filepath.IsAbs(c.TokenKeyFile) || !filepath.IsAbs(c.StorageKeyFile) {
		return c, errors.New("staging and key file paths required")
	}
	return c, nil
}
func readKey(path string) ([]byte, error) {
	st, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode()&0077 != 0 || st.Size() > 128 {
		return nil, errors.New("key must be a private regular file")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	key, e := hex.DecodeString(strings.TrimSpace(string(b)))
	clear(b)
	if e != nil || len(key) != 32 {
		return nil, errors.New("key must contain 64 hexadecimal characters")
	}
	return key, nil
}
func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "aegis:", e)
		os.Exit(1)
	}
}
func run(args []string) error {
	runtime.GOMAXPROCS(2)
	debug.SetMemoryLimit(32 << 20)
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Println("Aegis, the request and upload guardian\nUsage: aegis version | selftest | check --config FILE | serve --config FILE | plan --config FILE --server nginx|apache|caddy\nDisabled by default. Policy comes only from local configuration.")
		return nil
	}
	switch args[0] {
	case "version":
		fmt.Println("Aegis " + version)
		return nil
	case "selftest":
		return gateway.SelfTest(os.Stdout)
	}
	if args[0] != "serve" && args[0] != "check" && args[0] != "plan" {
		return errors.New("unknown command")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	path := fs.String("config", "", "local config file")
	server := fs.String("server", "nginx", "web server for read only plan")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if *path == "" || fs.NArg() != 0 {
		return errors.New("a local config file is required")
	}
	c, e := load(*path)
	if e != nil {
		return e
	}
	if args[0] == "plan" {
		if c.Mode != "proxy" {
			return errors.New("plan requires proxy mode")
		}
		return structuralproxy.Plan(os.Stdout, c.Proxy, c.Listen, *server)
	}
	if args[0] == "check" {
		fmt.Printf("Aegis config valid; mode=%s; enabled=%t; policy=local-only\n", c.Mode, c.Enabled)
		return nil
	}
	if !c.Enabled {
		return errors.New("service disabled in local configuration")
	}
	var g interface {
		http.Handler
		Sweep()
		Close() error
	}
	if c.Mode == "proxy" {
		g, e = structuralproxy.New(c.Proxy)
	} else {
		var token, storage []byte
		token, e = readKey(c.TokenKeyFile)
		if e != nil {
			return e
		}
		storage, e = readKey(c.StorageKeyFile)
		if e != nil {
			clear(token)
			return e
		}
		g, e = gateway.New(c.Policy, token, storage, c.StagingDir)
		clear(token)
		clear(storage)
	}
	if e != nil {
		return e
	}
	closed := false
	closeGateway := func() error {
		if closed {
			return nil
		}
		closed = true
		return g.Close()
	}
	defer closeGateway()
	var admin *http.Server
	if c.AdminListen != "" {
		key, err := readKey(c.AdminKeyFile)
		if err != nil {
			return err
		}
		handler, err := g.(*structuralproxy.Server).AdminHandler(key)
		clear(key)
		if err != nil {
			return err
		}
		ln, err := net.Listen("tcp", c.AdminListen)
		if err != nil {
			return err
		}
		admin = &http.Server{Handler: handler, ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, MaxHeaderBytes: 1024}
		admin.SetKeepAlivesEnabled(false)
		defer admin.Close()
		go func() { _ = admin.Serve(&limitedListener{Listener: ln, slots: make(chan struct{}, 2)}) }()
	}
	listener, e := net.Listen("tcp", c.Listen)
	if e != nil {
		closeGateway()
		return e
	}
	// Cap accepted connections independently of per request admission.
	ln := &limitedListener{Listener: listener, slots: make(chan struct{}, 32)}
	srv := &http.Server{Handler: g, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: deadline(c), WriteTimeout: deadline(c), IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(os.Stderr, "aegis http: ", 0)}
	srv.SetKeepAlivesEnabled(false)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	fmt.Printf("Aegis listening on %s; mode=%s; policy=local-only\n", listener.Addr(), c.Mode)
	var serveErr error
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case serveErr = <-done:
			break loop
		case <-tick.C:
			g.Sweep()
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), deadline(c)+time.Second)
	defer cancel()
	if e = srv.Shutdown(shutdown); e != nil {
		srv.Close()
		return e
	}
	if e = closeGateway(); e != nil {
		return e
	}
	if serveErr != nil && serveErr != http.ErrServerClosed {
		return serveErr
	}
	fmt.Println("Aegis stopped; temporary resources closed")
	return nil
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error { e := c.Conn.Close(); c.once.Do(c.release); return e }

func deadline(c localConfig) time.Duration {
	if c.Mode == "proxy" {
		return time.Duration(c.Proxy.RequestSeconds) * time.Second
	}
	return c.Policy.Deadline()
}
