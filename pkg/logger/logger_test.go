package logger

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	l, err := New("info", "json", "stderr")
	if err != nil {
		t.Fatalf("new logger failed: %v", err)
	}
	defer l.Close()
	if l == nil {
		t.Fatal("logger is nil")
	}
}

func TestNewLogger_File(t *testing.T) {
	path := "/tmp/test_logger.json"
	defer os.Remove(path)

	l, err := New("info", "json", path)
	if err != nil {
		t.Fatalf("new logger failed: %v", err)
	}
	defer l.Close()

	l.Info("test_message", map[string]interface{}{"key": "value"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "test_message") {
		t.Fatalf("expected test_message in log, got %s", string(data))
	}
}

func TestLogger_Levels(t *testing.T) {
	l, err := New("warn", "json", "stderr")
	if err != nil {
		t.Fatalf("new logger failed: %v", err)
	}
	defer l.Close()

	// Debug should be skipped because level is warn
	l.Debug("debug_msg", nil)
	// Warn should be logged
	l.Warn("warn_msg", nil)
	// Info should be skipped
	l.Info("info_msg", nil)
	// Error should be logged
	l.Error("error_msg", nil)
}

func TestLogger_TextFormat(t *testing.T) {
	path := "/tmp/test_logger_text.log"
	defer os.Remove(path)

	l, err := New("info", "text", path)
	if err != nil {
		t.Fatalf("new logger failed: %v", err)
	}
	defer l.Close()

	l.Info("text_test", map[string]interface{}{"foo": "bar"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "text_test") {
		t.Fatalf("expected text_test in log, got %s", string(data))
	}
	if !strings.Contains(string(data), "foo=bar") {
		t.Fatalf("expected foo=bar in text log, got %s", string(data))
	}
}

func TestParseLevel(t *testing.T) {
	cases := []struct {
		input    string
		expected Level
	}{
		{"debug", Debug},
		{"info", Info},
		{"warn", Warn},
		{"error", Error},
		{"fatal", Fatal},
		{"unknown", Info},
		{"", Info},
	}
	for _, c := range cases {
		got := parseLevel(c.input)
		if got != c.expected {
			t.Errorf("parseLevel(%q) = %v, want %v", c.input, got, c.expected)
		}
	}
}

func TestLevel_String(t *testing.T) {
	cases := []struct {
		level    Level
		expected string
	}{
		{Debug, "debug"},
		{Info, "info"},
		{Warn, "warn"},
		{Error, "error"},
		{Fatal, "fatal"},
		{Level(99), "unknown"},
	}
	for _, c := range cases {
		got := c.level.String()
		if got != c.expected {
			t.Errorf("Level(%d).String() = %q, want %q", c.level, got, c.expected)
		}
	}
}

func TestLogger_JSONStructure(t *testing.T) {
	path := "/tmp/test_logger_structured.json"
	defer os.Remove(path)

	l, err := New("info", "json", path)
	if err != nil {
		t.Fatalf("new logger failed: %v", err)
	}
	defer l.Close()

	l.Info("structured_test", map[string]interface{}{
		"ip":     "192.168.1.1",
		"path":   "/api/test",
		"status": 200,
	})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if entry["message"] != "structured_test" {
		t.Fatalf("unexpected message: %v", entry["message"])
	}
	if entry["ip"] != "192.168.1.1" {
		t.Fatalf("unexpected ip: %v", entry["ip"])
	}
}

func BenchmarkLogger_Info(b *testing.B) {
	l, _ := New("info", "json", "stderr")
	defer l.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l.Info("benchmark", map[string]interface{}{"n": i})
	}
}
