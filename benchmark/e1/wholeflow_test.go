// Test entry point for the E1 local-overhead measurement.
package e1

import (
	"os"
	"strconv"
	"testing"
)

// TestAllPartsLocal runs the local-overhead measurement behind paper §6 Table III.
// It defaults to 10 iterations; set ORION_ITERATIONS=1000 (and raise -timeout) for
// the publication figures. Per-stage means are printed under -v.
func TestAllPartsLocal(t *testing.T) {
	iterations := 10
	if raw := os.Getenv("ORION_ITERATIONS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			t.Fatalf("ORION_ITERATIONS=%q is not a positive integer", raw)
		}
		iterations = n
	}
	if err := WholeFlowLocal(iterations); err != nil {
		t.Fatalf("WholeFlowLocal: %v", err)
	}
}
