package rules

import (
	"os"
	"testing"
)

func TestRuleEngine(t *testing.T) {
	content := `
version: "1.0"
rules:
  - id: R001
    name: Test Rule
    pattern: "attack"
    phase: request
    action: block
    enabled: true
    targets:
      - url
`
	f, err := os.CreateTemp("", "rules*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	e := NewEngine(f.Name(), false)
	if err := e.Load(); err != nil {
		t.Fatal(err)
	}
	if e.Count() != 1 {
		t.Fatalf("expected 1 rule, got %d", e.Count())
	}

	matched, rule := e.MatchRequest("request", map[string]string{"url": "/api/attack"})
	if !matched {
		t.Fatal("expected match")
	}
	if rule.ID != "R001" {
		t.Fatalf("unexpected rule id: %s", rule.ID)
	}

	matched, _ = e.MatchRequest("request", map[string]string{"url": "/api/safe"})
	if matched {
		t.Fatal("expected no match")
	}
}
