package rules

import (
	"os"
	"testing"
)

func TestEngine_LoadAndMatch(t *testing.T) {
	path := "/tmp/test_rules.yaml"
	defer os.Remove(path)

	content := `
version: "1.0"
rules:
  - id: R001
    name: Test Rule
    description: Test
    phase: request
    pattern: "attack"
    action: block
    severity: high
    enabled: true
    targets:
      - url
`
	os.WriteFile(path, []byte(content), 0644)

	eng := NewEngine(path, false)
	if err := eng.Load(); err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if eng.Count() != 1 {
		t.Fatalf("expected 1 rule, got %d", eng.Count())
	}

	matched, rule := eng.MatchRequest("request", map[string]string{"url": "http://example.com/?q=attack"})
	if !matched {
		t.Fatal("expected match")
	}
	if rule.ID != "R001" {
		t.Fatalf("expected R001, got %s", rule.ID)
	}
}

func TestEngine_MatchRequest_NoTargets(t *testing.T) {
	path := "/tmp/test_rules_notargets.yaml"
	defer os.Remove(path)

	content := `
version: "1.0"
rules:
  - id: R001
    name: Test Rule
    phase: request
    pattern: "badword"
    action: block
    enabled: true
`
	os.WriteFile(path, []byte(content), 0644)

	eng := NewEngine(path, false)
	if err := eng.Load(); err != nil {
		t.Fatalf("load failed: %v", err)
	}

	matched, _ := eng.MatchRequest("request", map[string]string{"url": "http://example.com/?q=badword"})
	if !matched {
		t.Fatal("expected match when no targets specified")
	}
}

func TestEngine_MatchRequest_WrongPhase(t *testing.T) {
	path := "/tmp/test_rules_phase.yaml"
	defer os.Remove(path)

	content := `
version: "1.0"
rules:
  - id: R001
    name: Test Rule
    phase: response
    pattern: "badword"
    action: block
    enabled: true
`
	os.WriteFile(path, []byte(content), 0644)

	eng := NewEngine(path, false)
	if err := eng.Load(); err != nil {
		t.Fatalf("load failed: %v", err)
	}

	matched, _ := eng.MatchRequest("request", map[string]string{"url": "http://example.com/?q=badword"})
	if matched {
		t.Fatal("expected no match for wrong phase")
	}
}

func TestEngine_DisabledRule(t *testing.T) {
	path := "/tmp/test_rules_disabled.yaml"
	defer os.Remove(path)

	content := `
version: "1.0"
rules:
  - id: R001
    name: Test Rule
    phase: request
    pattern: "badword"
    action: block
    enabled: false
`
	os.WriteFile(path, []byte(content), 0644)

	eng := NewEngine(path, false)
	if err := eng.Load(); err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if eng.Count() != 0 {
		t.Fatalf("expected 0 rules (disabled), got %d", eng.Count())
	}
}

func TestEngine_InvalidPattern(t *testing.T) {
	path := "/tmp/test_rules_invalid.yaml"
	defer os.Remove(path)

	content := `
version: "1.0"
rules:
  - id: R001
    name: Test Rule
    phase: request
    pattern: "[invalid("
    action: block
    enabled: true
`
	os.WriteFile(path, []byte(content), 0644)

	eng := NewEngine(path, false)
	if err := eng.Load(); err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if eng.Count() != 0 {
		t.Fatalf("expected 0 rules (invalid pattern), got %d", eng.Count())
	}
}

func TestEngine_DefaultRulesCreated(t *testing.T) {
	path := "/tmp/test_rules_default.yaml"
	defer os.Remove(path)
	// Make sure file doesn't exist
	os.Remove(path)

	eng := NewEngine(path, false)
	if err := eng.Load(); err != nil {
		t.Fatalf("load failed: %v", err)
	}
	// Should create default rules file
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("expected default rules file to be created")
	}
}

func TestEngine_NoReloadIfNotModified(t *testing.T) {
	path := "/tmp/test_rules_noreload.yaml"
	defer os.Remove(path)

	content := `
version: "1.0"
rules:
  - id: R001
    name: Test Rule
    phase: request
    pattern: "attack"
    action: block
    enabled: true
`
	os.WriteFile(path, []byte(content), 0644)

	eng := NewEngine(path, false)
	if err := eng.Load(); err != nil {
		t.Fatalf("load failed: %v", err)
	}
	count := eng.Count()

	// Load again without modification
	if err := eng.Load(); err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if eng.Count() != count {
		t.Fatalf("expected same count after no-modification reload")
	}
}

func BenchmarkEngine_MatchRequest(b *testing.B) {
	path := "/tmp/test_rules_bench.yaml"
	defer os.Remove(path)

	content := `
version: "1.0"
rules:
  - id: R001
    name: Test Rule
    phase: request
    pattern: "attack"
    action: block
    enabled: true
    targets:
      - url
`
	os.WriteFile(path, []byte(content), 0644)

	eng := NewEngine(path, false)
	eng.Load()

	targets := map[string]string{"url": "http://example.com/?q=attack"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eng.MatchRequest("request", targets)
	}
}
