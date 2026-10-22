// Package structuralproxy implements an opt in, locally configured normalization
// boundary. No request selects a socket, script, filesystem path or policy.
package structuralproxy

import (
	"errors"
	"net"
	"path/filepath"
	"regexp"
	"strings"
)

type Route struct {
	Protocol       string   `json:"protocol"`
	ScriptFilename string   `json:"script_filename"`
	ScriptName     string   `json:"script_name"`
	DocumentRoot   string   `json:"document_root"`
	ServerPort     int      `json:"server_port"`
	HTTPS          bool     `json:"https"`
	Prefix         string   `json:"prefix"`
	Socket         string   `json:"socket"`
	ServerName     string   `json:"server_name"`
	Methods        []string `json:"methods"`
	Formats        []string `json:"formats"`
}
type Config struct {
	MaxDepth         int      `json:"max_depth"`
	MaxTokens        int      `json:"max_tokens"`
	MaxStringBytes   int      `json:"max_string_bytes"`
	Hosts            []string `json:"hosts"`
	Routes           []Route  `json:"routes"`
	MaxBytes         int64    `json:"max_bytes"`
	MaxResponseBytes int64    `json:"max_response_bytes"`
	RequestSeconds   int      `json:"request_seconds"`
	MaxConcurrent    int      `json:"max_concurrent"`
}

func DefaultConfig() Config {
	return Config{MaxDepth: 16, MaxTokens: 10000, MaxStringBytes: 4096, MaxBytes: 1 << 20, MaxResponseBytes: 4 << 20, RequestSeconds: 15, MaxConcurrent: 2}
}

var fieldName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

func hostOK(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".-:[]", c)) {
			return false
		}
	}
	return true
}
func (c Config) Validate() error {
	if c.MaxDepth < 1 || c.MaxDepth > 16 || c.MaxTokens < 1 || c.MaxTokens > 10000 || c.MaxStringBytes < 1 || c.MaxStringBytes > 4096 {
		return errors.New("proxy JSON limits exceed compiled ceilings")
	}
	if c.MaxBytes < 1 || c.MaxBytes > 1<<20 || c.MaxResponseBytes < 1 || c.MaxResponseBytes > 4<<20 || c.RequestSeconds < 1 || c.RequestSeconds > 15 || c.MaxConcurrent < 1 || c.MaxConcurrent > 2 {
		return errors.New("proxy exceeds compiled ceilings")
	}
	if len(c.Hosts) < 1 || len(c.Hosts) > 8 || len(c.Routes) < 1 || len(c.Routes) > 16 {
		return errors.New("explicit bounded hosts and routes required")
	}
	seen := map[string]bool{}
	for _, h := range c.Hosts {
		if !hostOK(h) || seen[h] {
			return errors.New("invalid or duplicate host")
		}
		seen[h] = true
	}
	seen = map[string]bool{}
	for _, r := range c.Routes {
		if !validPath(r.Prefix) || (r.Prefix != "/" && strings.HasSuffix(r.Prefix, "/")) || seen[r.Prefix] {
			return errors.New("invalid or duplicate route prefix")
		}
		seen[r.Prefix] = true
		if !filepath.IsAbs(r.Socket) || filepath.Clean(r.Socket) != r.Socket || len(r.Socket) > 100 || !hostOK(r.ServerName) {
			return errors.New("fixed absolute Unix socket and server name required")
		}
		if r.Protocol != "http" && r.Protocol != "fastcgi" {
			return errors.New("explicit backend protocol required")
		}
		if r.Protocol == "fastcgi" {
			if !filepath.IsAbs(r.ScriptFilename) || filepath.Clean(r.ScriptFilename) != r.ScriptFilename || !strings.HasSuffix(r.ScriptFilename, ".php") || !filepath.IsAbs(r.DocumentRoot) || filepath.Clean(r.DocumentRoot) != r.DocumentRoot || !strings.HasPrefix(r.ScriptFilename, r.DocumentRoot+"/") || !validPath(r.ScriptName) || r.ServerPort < 1 || r.ServerPort > 65535 {
				return errors.New("fixed local FastCGI front controller required")
			}
		} else if r.ScriptFilename != "" || r.ScriptName != "" || r.DocumentRoot != "" || r.ServerPort != 0 || r.HTTPS {
			return errors.New("CGI settings only apply to FastCGI")
		}

		if len(r.Methods) < 1 || len(r.Methods) > 6 || len(r.Formats) < 1 || len(r.Formats) > 4 {
			return errors.New("explicit methods and formats required")
		}
		for _, m := range r.Methods {
			if !contains([]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}, m) {
				return errors.New("unsupported method")
			}
		}
		for _, f := range r.Formats {
			if !contains([]string{"none", "json", "form", "multipart"}, f) {
				return errors.New("unsupported format")
			}
		}
	}
	return nil
}
func contains(a []string, v string) bool {
	for _, s := range a {
		if s == v {
			return true
		}
	}
	return false
}
func peer(addr string) string {
	h, _, e := net.SplitHostPort(addr)
	if e != nil {
		return ""
	}
	return h
}
func validPath(s string) bool {
	if len(s) == 0 || s[0] != '/' || len(s) > 2048 || strings.Contains(s, "//") {
		return false
	}
	// A deliberately small route alphabet removes decoding and path alias ambiguity.
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("/_-.~", c)) {
			return false
		}
	}
	for _, p := range strings.Split(s, "/") {
		if p == "." || p == ".." {
			return false
		}
	}
	return true
}
