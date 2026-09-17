// Run profiles: the demo and bench presentations of the same protocol implementation.
package config

import "os"

// Profile selects how the single OrionLink implementation presents itself. It
// changes presentation and fixtures only, never the protocol path: which static
// assets are served, how many users are seeded at startup, and whether the
// check-bypassing load-test endpoints are mounted.
type Profile string

const (
	ProfileDemo Profile = "demo"

	ProfileBench Profile = "bench"
)

// profileFromEnv reads ORION_PROFILE, defaulting to the demo profile.
func profileFromEnv() Profile {
	if os.Getenv("ORION_PROFILE") == string(ProfileBench) {
		return ProfileBench
	}
	return ProfileDemo
}

// IsBench reports whether measurement fixtures and load-test endpoints are active.
func (c *Config) IsBench() bool { return c.Profile == ProfileBench }

// TestEndpointsEnabled gates the check-bypassing load-test endpoints, kept as its
// own predicate so the security-relevant decision lives in one place.
func (c *Config) TestEndpointsEnabled() bool { return c.Profile == ProfileBench }
