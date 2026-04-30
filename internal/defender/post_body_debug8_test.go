package defender

import (
    "fmt"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestXSS_PostBodyDebug8(t *testing.T) {
    xss := NewXSSDetector(true, "block", false, nil)
    
    // Test POST with URL-encoded ERB body
    body := strings.NewReader("content=%3C%25%3Dalert%281%29%25%3E")
    r := httptest.NewRequest("POST", "/", body)
    r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    
    matched, pattern := xss.InspectRequest(r)
    fmt.Printf("POST encoded ERB: matched=%v pattern=%q\n", matched, pattern)
    
    if !matched {
        t.Error("Expected encoded ERB POST to be blocked")
    }
}
