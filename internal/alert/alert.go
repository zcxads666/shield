package alert

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/shield/shield/internal/logger"
)

// Notifier sends alerts for security events.
type Notifier struct {
	enabled   bool
	webhook   string
	threshold int
	logger    *logger.Logger
}

// NewNotifier creates an alert notifier.
func NewNotifier(enabled bool, webhook string, threshold int, log *logger.Logger) *Notifier {
	return &Notifier{
		enabled:   enabled,
		webhook:   webhook,
		threshold: threshold,
		logger:    log,
	}
}

// Event represents a security event.
type Event struct {
	Type      string    `json:"type"`
	IP        string    `json:"ip"`
	Path      string    `json:"path"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// Notify sends an alert if enabled.
func (n *Notifier) Notify(event Event) {
	if !n.enabled {
		return
	}
	if n.logger != nil {
		n.logger.Warn("alert_triggered", map[string]interface{}{
			"type":    event.Type,
			"ip":      event.IP,
			"message": event.Message,
		})
	}
	if n.webhook != "" {
		go n.sendWebhook(event)
	}
}

func (n *Notifier) sendWebhook(event Event) {
	payload, err := json.Marshal(event)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", n.webhook, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// NotifyBlock sends a block notification.
func (n *Notifier) NotifyBlock(ip, path, reason string) {
	n.Notify(Event{
		Type:      "block",
		IP:        ip,
		Path:      path,
		Message:   fmt.Sprintf("Blocked: %s", reason),
		Timestamp: time.Now(),
	})
}
