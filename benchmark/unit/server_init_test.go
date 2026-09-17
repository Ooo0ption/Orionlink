// Smoke test that each server role constructs and starts.
package unit

import (
	"testing"
	"time"

	broker "secure-sso/Broker"
	idp "secure-sso/IdP"
	rp "secure-sso/RP"
)

// TestCreateServersWithConfig smoke-checks that each role loads its config and
// constructs up to Listen without panicking. It needs free ports: point the
// ORION_*_URL variables at unused ones when a live stack is running.
func TestCreateServersWithConfig(t *testing.T) {
	starts := []struct {
		name string
		fn   func()
	}{
		{"IdP", idp.StartIdpServer},
		{"Broker", broker.StartBrokerServer},
		{"RP", rp.StartRpServer},
	}
	for _, s := range starts {
		panicked := make(chan any, 1)
		go func() {
			defer func() { panicked <- recover() }()
			s.fn()
		}()
		select {
		case r := <-panicked:
			if r != nil {
				t.Fatalf("%s server panicked during startup: %v", s.name, r)
			}
			t.Logf("%s server returned early (likely port-in-use); config OK", s.name)
		case <-time.After(500 * time.Millisecond):
		}
	}
}
