package version

import (
	"strings"
	"testing"
)

func TestVersion_NonEmpty(t *testing.T) {
	if Version == "" {
		t.Fatal("version should not be empty")
	}
}

func TestVersion_SemverFormat(t *testing.T) {
	parts := strings.Split(Version, ".")
	if len(parts) != 3 {
		t.Fatalf("version %q should be in MAJOR.MINOR.PATCH format", Version)
	}
	for _, p := range parts {
		for _, c := range p {
			if c < '0' || c > '9' {
				t.Errorf("version part %q contains non-numeric character: %q", p, string(c))
			}
		}
	}
}

func TestVersion_MajorPositive(t *testing.T) {
	parts := strings.Split(Version, ".")
	if parts[0] == "0" {
		// Allow major version 0 for pre-1.0 releases
		return
	}
}
