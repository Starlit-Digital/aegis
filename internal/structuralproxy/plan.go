package structuralproxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// Plan only writes a reviewable example. It never edits or reloads a web server.
func Plan(w io.Writer, c Config, listen, server string) error {
	if e := c.Validate(); e != nil {
		return e
	}
	h, _, e := net.SplitHostPort(listen)
	if e != nil || net.ParseIP(h) == nil || !net.ParseIP(h).IsLoopback() {
		return errors.New("literal loopback listen required")
	}
	fmt.Fprintln(w, "# Review only. TLS, authentication, application routing and rollback remain operator responsibilities.")
	switch server {
	case "nginx":
		fmt.Fprintf(w, "location / {\n    proxy_pass http://%s;\n    proxy_http_version 1.1;\n    proxy_request_buffering on;\n    client_max_body_size %d;\n    proxy_set_header Host %s;\n    proxy_set_header Connection close;\n", listen, c.MaxBytes, c.Hosts[0])
		for _, k := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-IP"} {
			fmt.Fprintf(w, "    proxy_set_header %s \"\";\n", k)
		}
		fmt.Fprintln(w, "}")
	case "apache":
		fmt.Fprintf(w, "ProxyPreserveHost On\nRequestHeader unset Forwarded\nRequestHeader unset X-Forwarded-For\nRequestHeader unset X-Forwarded-Host\nRequestHeader unset X-Forwarded-Proto\nProxyAddHeaders Off\nLimitRequestBody %d\nProxyPass / http://%s/\nProxyPassReverse / http://%s/\n", c.MaxBytes, listen, listen)
	case "caddy":
		fmt.Fprintf(w, "request_body {\n    max_size %d\n}\nreverse_proxy %s {\n    header_up Host %s\n    header_up -Forwarded\n    header_up -X-Forwarded-For\n    header_up -X-Forwarded-Host\n    header_up -X-Forwarded-Proto\n}\n", c.MaxBytes, listen, c.Hosts[0])
	default:
		return errors.New("server must be nginx, apache or caddy")
	}
	fmt.Fprintf(w, "# Allowed hosts: %s\n# Reserve /metrics, /healthz, /Q and /v1/uploads; do not expose the admin port.\n", strings.Join(c.Hosts, ", "))
	return nil
}
