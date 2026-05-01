package alert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shield/shield/pkg/logger"
)

func TestNotifier_Notify_Disabled(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	n := NewNotifier(false, "", 1, log)
	// Should not panic or send anything
	n.Notify(Event{Type: "test", IP: "1.2.3.4", Message: "test event"})
}

func TestNotifier_NotifyBlock(t *testing.T) {
	received := make(chan bool, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var evt Event
		if err := json.NewDecoder(r.Body).Decode(&evt); err != nil {
			t.Errorf("decode failed: %v", err)
		}
		if evt.Type != "block" {
			t.Errorf("expected type=block, got %s", evt.Type)
		}
		if evt.IP != "192.168.1.1" {
			t.Errorf("expected ip=192.168.1.1, got %s", evt.IP)
		}
		w.WriteHeader(http.StatusOK)
		received <- true
	}))
	defer ts.Close()

	log, _ := logger.New("warn", "json", "stderr")
	n := NewNotifier(true, ts.URL, 1, log)
	n.NotifyBlock("192.168.1.1", "/login", "brute force")

	select {
	case <-received:
		// ok
	case <-time.After(2 * time.Second):
		t.Fatal("expected webhook to be called")
	}
}

func TestNotifier_Notify_WithoutWebhook(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	n := NewNotifier(true, "", 1, log)
	// Should not panic even without webhook
	n.Notify(Event{Type: "test", IP: "1.2.3.4", Message: "test event"})
}

func TestNotifier_SendWebhook_InvalidURL(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	n := NewNotifier(true, "://invalid-url", 1, log)
	// Should not panic
	n.Notify(Event{Type: "test", IP: "1.2.3.4", Message: "test event"})
	time.Sleep(100 * time.Millisecond)
}

func TestNotifier_SendWebhook_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	log, _ := logger.New("warn", "json", "stderr")
	n := NewNotifier(true, ts.URL, 1, log)
	n.Notify(Event{Type: "test", IP: "1.2.3.4", Message: "test event"})
	time.Sleep(100 * time.Millisecond)
}

func TestNotifier_EventJSON(t *testing.T) {
	evt := Event{
		Type:      "block",
		IP:        "10.0.0.1",
		Path:      "/admin",
		Message:   "SQL injection detected",
		Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	data, err := json.Marshal(evt)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	if !strings.Contains(string(data), "SQL injection detected") {
		t.Fatalf("expected message in json, got %s", string(data))
	}
}

func BenchmarkNotifier_Notify(b *testing.B) {
	log, _ := logger.New("warn", "json", "stderr")
	n := NewNotifier(true, "", 1, log)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n.Notify(Event{Type: "block", IP: "1.2.3.4", Message: "test"})
	}
}
