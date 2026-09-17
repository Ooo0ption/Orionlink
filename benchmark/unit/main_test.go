// Test setup shared by the unit-test package.
package unit

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestMain runs the package's tests from the repository root, which is where the
// server packages resolve their configuration paths from.
func TestMain(m *testing.M) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
	if err := os.Chdir(repoRoot); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
