// Package config centralizes every deployment-dependent value in OrionLink: the
// four service URLs, the asset and data directories, and the run profile. All of
// it derives from ORION_* environment variables, with the shipped JSON files
// supplying defaults.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Endpoint is one service's address. Browser and Server differ whenever a browser
// and a peer server reach the service by different names, as under Docker.
type Endpoint struct {
	Browser string
	Server  string
}

// Config is the fully resolved deployment configuration.
type Config struct {
	Profile  Profile
	AssetDir string
	DataDir  string

	IdP    Endpoint
	Broker Endpoint
	RP     Endpoint
	TCA    Endpoint
}

// Default browser-reachable URLs, matching the documented local stack.
const (
	defaultIdPURL    = "http://localhost:3000"
	defaultBrokerURL = "http://localhost:3001"
	defaultRPURL     = "http://localhost:3002"
	defaultTCAURL    = "http://localhost:3003"
)

var (
	once    sync.Once
	loaded  *Config
	loadErr error
)

// Get returns the process-wide configuration, resolving it on first call. A
// malformed ORION_*_URL is fatal rather than silently replaced by a default.
func Get() *Config {
	once.Do(func() {
		loaded, loadErr = resolve()
	})
	if loadErr != nil {
		panic(fmt.Sprintf("orion config: %v", loadErr))
	}
	return loaded
}

// resolve builds the configuration once from the environment: profile, asset and
// data directories, and the browser/server URL pair of each role.
func resolve() (*Config, error) {
	c := &Config{Profile: profileFromEnv()}

	var err error
	if c.AssetDir, err = resolveAssetDir(); err != nil {
		return nil, err
	}
	if c.DataDir, err = resolveDataDir(c.AssetDir); err != nil {
		return nil, err
	}

	for _, spec := range []struct {
		name       string
		envBrowser string
		envServer  string
		def        string
		dst        *Endpoint
	}{
		{"IdP", "ORION_IDP_URL", "ORION_IDP_SERVER_URL", defaultIdPURL, &c.IdP},
		{"Broker", "ORION_BROKER_URL", "ORION_BROKER_SERVER_URL", defaultBrokerURL, &c.Broker},
		{"RP", "ORION_RP_URL", "ORION_RP_SERVER_URL", defaultRPURL, &c.RP},
		{"TCA", "ORION_TCA_URL", "", defaultTCAURL, &c.TCA},
	} {
		ep, err := endpointFromEnv(spec.envBrowser, spec.envServer, spec.def)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", spec.name, err)
		}
		*spec.dst = ep
	}

	return c, nil
}

// endpointFromEnv reads a browser URL and its optional server-side counterpart.
// An unset server variable means the same address is used from both sides.
func endpointFromEnv(envBrowser, envServer, def string) (Endpoint, error) {
	browser, err := normalizeURL(firstNonEmpty(os.Getenv(envBrowser), def), envBrowser)
	if err != nil {
		return Endpoint{}, err
	}
	server := browser
	if envServer != "" {
		if raw := os.Getenv(envServer); raw != "" {
			if server, err = normalizeURL(raw, envServer); err != nil {
				return Endpoint{}, err
			}
		}
	}
	return Endpoint{Browser: browser, Server: server}, nil
}

// normalizeURL validates a service URL and strips any trailing slash, so callers
// can concatenate paths without producing a double slash.
func normalizeURL(raw, envName string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(raw), "/")
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("%s=%q is not a valid URL: %w", envName, raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%s=%q must use http or https", envName, raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%s=%q must include a host", envName, raw)
	}
	return trimmed, nil
}

// resolveAssetDir locates the read-only source tree holding the per-role static
// directories and shipped default configs. It walks up from the working directory
// looking for go.mod, so the binary runs from any subdirectory.
func resolveAssetDir() (string, error) {
	if dir := os.Getenv("ORION_ASSET_DIR"); dir != "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", fmt.Errorf("ORION_ASSET_DIR=%q: %w", dir, err)
		}
		return abs, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("cannot determine working directory: %w", err)
	}
	if root, ok := findModuleRoot(cwd); ok {
		return root, nil
	}
	return cwd, nil
}

// resolveDataDir locates the directory holding mutable runtime state: key storage
// and registration data. It is separate from the asset directory so a container
// can mount a volume for state, and defaults to the asset directory.
func resolveDataDir(assetDir string) (string, error) {
	dir := os.Getenv("ORION_DATA_DIR")
	if dir == "" {
		return assetDir, nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("ORION_DATA_DIR=%q: %w", dir, err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return "", fmt.Errorf("ORION_DATA_DIR=%q: %w", abs, err)
	}
	return abs, nil
}

// findModuleRoot walks up from start looking for the directory holding go.mod.
func findModuleRoot(start string) (string, bool) {
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// RoleConfigDir returns the writable config directory for a role, creating it if
// absent. Runtime state files such as key_storage.json live here.
func (c *Config) RoleConfigDir(role string) string {
	dir := filepath.Join(c.DataDir, role, "config")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}

// RoleConfigPath returns one file inside a role's writable config directory,
// seeding a shipped default into place first if the file is absent.
func (c *Config) RoleConfigPath(role, name string) string {
	path := filepath.Join(c.RoleConfigDir(role), name)
	if c.DataDir != c.AssetDir && seedableDefaults[name] {
		seedDefault(filepath.Join(c.AssetDir, role, "config", name), path)
	}
	return path
}

// seedableDefaults is the allow-list of files that may be copied from the source
// tree into a fresh data directory. Runtime secrets such as key_storage.json and
// registration_data.json are never seeded.
var seedableDefaults = map[string]bool{
	"config.json": true,
	"users.json":  true,
}

// seedDefault copies a shipped default into the data directory when the target is
// absent, leaving any failure for the caller's own open to report.
func seedDefault(src, dst string) {
	if _, err := os.Stat(dst); err == nil {
		return
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return
	}
	_ = os.WriteFile(dst, data, 0o600)
}

// StaticDir returns the directory a role's HTML, CSS and JS are served from. They
// are read-only, so they come from the source tree; every profile serves the same
// pages.
func (c *Config) StaticDir(role string) string {
	return filepath.Join(c.AssetDir, role, "static")
}

// Issuer returns the IdP's OIDC issuer identifier, which is the browser-facing
// URL because it appears in the tokens the RP validates.
func (c *Config) Issuer() string { return c.IdP.Browser }

// BrowserOrigins lists every origin a browser may present in this deployment,
// including the 127.0.0.1 alias of a localhost URL. It feeds the CORS allow-list
// and the CSP frame-src permitting the TCA iframe.
func (c *Config) BrowserOrigins() []string {
	seen := map[string]bool{}
	var out []string
	add := func(raw string) {
		for _, o := range originAliases(raw) {
			if o != "" && !seen[o] {
				seen[o] = true
				out = append(out, o)
			}
		}
	}
	add(c.IdP.Browser)
	add(c.Broker.Browser)
	add(c.RP.Browser)
	add(c.TCA.Browser)
	return out
}

// originAliases returns a URL's origin plus its localhost/127.0.0.1 twin, which
// browsers treat as distinct origins.
func originAliases(raw string) []string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil
	}
	origin := u.Scheme + "://" + u.Host
	out := []string{origin}
	switch u.Hostname() {
	case "localhost":
		out = append(out, strings.Replace(origin, "localhost", "127.0.0.1", 1))
	case "127.0.0.1":
		out = append(out, strings.Replace(origin, "127.0.0.1", "localhost", 1))
	}
	return out
}

// ListenAddr returns the ":port" a role binds to: an explicit
// ORION_<ROLE>_LISTEN if set, otherwise the port of that role's browser URL, and
// finally the role's default. The override serves deployments behind a reverse
// proxy, where the public URL carries no port.
func (c *Config) ListenAddr(role string) string {
	if addr := os.Getenv("ORION_" + strings.ToUpper(role) + "_LISTEN"); addr != "" {
		if !strings.HasPrefix(addr, ":") && !strings.Contains(addr, ":") {
			return ":" + addr
		}
		return addr
	}

	var ep Endpoint
	var fallback string
	switch strings.ToLower(role) {
	case "idp":
		ep, fallback = c.IdP, ":3000"
	case "broker":
		ep, fallback = c.Broker, ":3001"
	case "rp":
		ep, fallback = c.RP, ":3002"
	default:
		return ""
	}

	if u, err := url.Parse(ep.Browser); err == nil {
		if port := u.Port(); port != "" {
			return ":" + port
		}
	}
	return fallback
}

// Origin returns the scheme://host of a URL, discarding any path.
func Origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

// PublicConfig is the browser-visible subset of the configuration, served at
// /ssso/pubconfig so no page needs a compiled-in address. It carries public
// routing information only: never keys, never PII.
type PublicConfig struct {
	Profile string `json:"profile"`
	IdP     string `json:"idp"`
	Broker  string `json:"broker"`
	RP      string `json:"rp"`
	TCA     string `json:"tca"`
}

// PublicConfig extracts the browser-visible subset of the configuration.
func (c *Config) PublicConfig() PublicConfig {
	return PublicConfig{
		Profile: string(c.Profile),
		IdP:     c.IdP.Browser,
		Broker:  c.Broker.Browser,
		RP:      c.RP.Browser,
		TCA:     c.TCA.Browser,
	}
}

// firstNonEmpty returns the first non-empty string, or "" if there is none.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
