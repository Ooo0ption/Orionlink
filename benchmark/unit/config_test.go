// Unit tests for deployment configuration resolution: origins, CSP, listen
// addresses, profiles and config-directory seeding.
package unit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	orionconf "secure-sso/internal/config"
)

func TestBrowserOriginsIncludeLoopbackAliases(t *testing.T) {
	cfg := &orionconf.Config{
		IdP:    orionconf.Endpoint{Browser: "http://localhost:3000"},
		Broker: orionconf.Endpoint{Browser: "http://127.0.0.1:3001"},
		RP:     orionconf.Endpoint{Browser: "http://localhost:3002"},
		TCA:    orionconf.Endpoint{Browser: "http://localhost:3003"},
	}

	got := map[string]bool{}
	for _, o := range cfg.BrowserOrigins() {
		got[o] = true
	}

	for _, want := range []string{
		"http://localhost:3000", "http://127.0.0.1:3000",
		"http://localhost:3001", "http://127.0.0.1:3001",
		"http://localhost:3002", "http://127.0.0.1:3002",
		"http://localhost:3003", "http://127.0.0.1:3003",
	} {
		if !got[want] {
			t.Errorf("BrowserOrigins() missing %q; got %v", want, cfg.BrowserOrigins())
		}
	}
}

func TestBrowserOriginsNoLoopbackAliasForRealHost(t *testing.T) {
	cfg := &orionconf.Config{
		IdP: orionconf.Endpoint{Browser: "https://idp.example.org"},
	}
	for _, o := range cfg.BrowserOrigins() {
		if strings.Contains(o, "127.0.0.1") || strings.Contains(o, "localhost") {
			t.Errorf("BrowserOrigins() invented loopback origin %q for a public host", o)
		}
	}
}

func TestFrameSrcCSPPinsConfiguredTCAOrigin(t *testing.T) {
	cfg := &orionconf.Config{TCA: orionconf.Endpoint{Browser: "https://tca.example.org"}}
	csp := cfg.FrameSrcCSP()
	if !strings.HasPrefix(csp, "frame-src ") {
		t.Fatalf("FrameSrcCSP() = %q, want a frame-src directive", csp)
	}
	if !strings.Contains(csp, "https://tca.example.org") {
		t.Errorf("FrameSrcCSP() = %q, must contain the configured TCA origin", csp)
	}
	if strings.Contains(csp, "localhost") {
		t.Errorf("FrameSrcCSP() = %q leaked a hardcoded localhost origin", csp)
	}
}

func TestListenAddrFollowsConfiguredPort(t *testing.T) {
	cfg := &orionconf.Config{
		IdP:    orionconf.Endpoint{Browser: "http://localhost:9000"},
		Broker: orionconf.Endpoint{Browser: "http://localhost:9001"},
		RP:     orionconf.Endpoint{Browser: "http://localhost:9002"},
	}
	for role, want := range map[string]string{"idp": ":9000", "broker": ":9001", "rp": ":9002"} {
		if got := cfg.ListenAddr(role); got != want {
			t.Errorf("ListenAddr(%q) = %q, want %q", role, got, want)
		}
	}
}

func TestListenAddrExplicitOverrideWinsOverURL(t *testing.T) {
	t.Setenv("ORION_IDP_LISTEN", ":3000")
	cfg := &orionconf.Config{IdP: orionconf.Endpoint{Browser: "https://idp.example.org"}}
	if got := cfg.ListenAddr("idp"); got != ":3000" {
		t.Errorf("ListenAddr(\"idp\") = %q, want \":3000\" from ORION_IDP_LISTEN", got)
	}
}

func TestPubConfigJSCarriesNoSecretsAndEscapes(t *testing.T) {
	cfg := &orionconf.Config{
		Profile: orionconf.ProfileDemo,
		IdP:     orionconf.Endpoint{Browser: "http://localhost:3000"},
		Broker:  orionconf.Endpoint{Browser: "http://localhost:3001"},
		RP:      orionconf.Endpoint{Browser: "http://localhost:3002"},
		TCA:     orionconf.Endpoint{Browser: "http://localhost:3003"},
	}
	js := cfg.PubConfigJS()

	for _, want := range []string{"window.ORION", "idpOrigin", "tcaOrigin", "allowedOrigins"} {
		if !strings.Contains(js, want) {
			t.Errorf("PubConfigJS() missing %q", want)
		}
	}
	for _, forbidden := range []string{"sk_hex", "ks_hex", "password", "IdentitySk", "PRIVATE"} {
		if strings.Contains(js, forbidden) {
			t.Errorf("PubConfigJS() leaked %q", forbidden)
		}
	}
	evil := &orionconf.Config{IdP: orionconf.Endpoint{Browser: "http://x</script><script>alert(1)"}}
	if strings.Contains(evil.PubConfigJS(), "</script>") {
		t.Error("PubConfigJS() did not escape a </script> sequence in a configured URL")
	}
}

func TestRoleConfigPathSeedsDefaultsIntoDataDir(t *testing.T) {
	assetDir := t.TempDir()
	dataDir := t.TempDir()

	srcDir := filepath.Join(assetDir, "RP", "config")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	want := []byte(`{"marker":"shipped-default"}`)
	if err := os.WriteFile(filepath.Join(srcDir, "config.json"), want, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &orionconf.Config{AssetDir: assetDir, DataDir: dataDir}
	got := cfg.RoleConfigPath("RP", "config.json")

	if !strings.HasPrefix(got, dataDir) {
		t.Errorf("RoleConfigPath returned %q, want a path under the data dir %q", got, dataDir)
	}
	data, err := os.ReadFile(got)
	if err != nil {
		t.Fatalf("default was not seeded into the data dir: %v", err)
	}
	if string(data) != string(want) {
		t.Errorf("seeded content = %q, want %q", data, want)
	}
}

func TestRoleConfigPathDoesNotOverwriteExistingState(t *testing.T) {
	assetDir := t.TempDir()
	dataDir := t.TempDir()

	for dir, content := range map[string]string{
		filepath.Join(assetDir, "RP", "config"): `{"marker":"shipped-default"}`,
		filepath.Join(dataDir, "RP", "config"):  `{"marker":"live-state"}`,
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cfg := &orionconf.Config{AssetDir: assetDir, DataDir: dataDir}
	data, err := os.ReadFile(cfg.RoleConfigPath("RP", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "live-state") {
		t.Errorf("existing runtime state was overwritten by the shipped default: %q", data)
	}
}

func TestTestEndpointsGatedToBenchProfile(t *testing.T) {
	demo := &orionconf.Config{Profile: orionconf.ProfileDemo}
	if demo.TestEndpointsEnabled() {
		t.Error("demo profile must not enable the check-bypassing test endpoints")
	}
	bench := &orionconf.Config{Profile: orionconf.ProfileBench}
	if !bench.TestEndpointsEnabled() {
		t.Error("bench profile must enable the test endpoints for load testing")
	}
}

func TestRoleConfigPathNeverSeedsRuntimeSecrets(t *testing.T) {
	assetDir := t.TempDir()
	dataDir := t.TempDir()

	srcDir := filepath.Join(assetDir, "IdP", "config")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"key_storage.json", "registration_data.json"} {
		if err := os.WriteFile(filepath.Join(srcDir, name), []byte(`{"secret":"authors"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := &orionconf.Config{AssetDir: assetDir, DataDir: dataDir}
	for _, name := range []string{"key_storage.json", "registration_data.json"} {
		path := cfg.RoleConfigPath("IdP", name)
		if _, err := os.Stat(path); err == nil {
			t.Errorf("%s was seeded into the data dir; runtime secrets must never be copied", name)
		}
	}
}
