package main

import (
	"encoding/json"
	"github.com/Starlit-Digital/aegis/internal/gateway"
	"os"
	"path/filepath"
	"testing"
)

func TestDisabledAndUnknownConfig(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "config.json")
	os.WriteFile(p, []byte(`{"listen":"127.0.0.1:8098","staging_dir":"/tmp/private","token_key_file":"/tmp/token","storage_key_file":"/tmp/storage"}`), 0600)
	if e := run([]string{"serve", "--config", p}); e == nil || e.Error() != "service disabled in local configuration" {
		t.Fatal(e)
	}
	os.WriteFile(p, []byte(`{"client_limits":true}`), 0600)
	if _, e := load(p); e == nil {
		t.Fatal("unknown config accepted")
	}
}
func TestKeyPermissions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	os.WriteFile(p, []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"), 0644)
	if _, e := readKey(p); e == nil {
		t.Fatal("public key file accepted")
	}
	os.Chmod(p, 0600)
	if _, e := readKey(p); e != nil {
		t.Fatal(e)
	}
}
func TestNonLoopbackAndRaisedLimits(t *testing.T) {
	for _, change := range []func(*localConfig){func(c *localConfig) { c.Listen = "0.0.0.0:8098" }, func(c *localConfig) { c.Policy.MaxBytes = 2 << 20 }} {
		d := t.TempDir()
		p := filepath.Join(d, "config.json")
		c := localConfig{Listen: "127.0.0.1:8098", StagingDir: d, TokenKeyFile: filepath.Join(d, "token"), StorageKeyFile: filepath.Join(d, "storage")}
		c.Policy = gateway.DefaultConfig()
		change(&c)
		b, _ := json.Marshal(c)
		os.WriteFile(p, b, 0600)
		if _, e := load(p); e == nil {
			t.Fatal("unsafe config accepted")
		}
	}
}

func TestProxyExamplesAndDisabledStartup(t *testing.T) {
	p := "../../config/aegis.proxy.example.json"
	c, e := load(p)
	if e != nil || c.Mode != "proxy" || c.Enabled {
		t.Fatal(c, e)
	}
	if e = run([]string{"serve", "--config", p}); e == nil || e.Error() != "service disabled in local configuration" {
		t.Fatal(e)
	}
	if e = run([]string{"plan", "--config", p, "--server", "nginx"}); e != nil {
		t.Fatal(e)
	}
	if e = run([]string{"plan", "--config", p, "--server", "unknown"}); e == nil {
		t.Fatal("unknown planner accepted")
	}
	c.AdminListen = "0.0.0.0:8100"
	c.AdminKeyFile = "/tmp/admin.key"
	b, _ := json.Marshal(c)
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, b, 0600)
	if _, e = load(bad); e == nil {
		t.Fatal("public admin listener accepted")
	}
}
