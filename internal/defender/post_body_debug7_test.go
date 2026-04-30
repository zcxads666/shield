package defender

import (
    "fmt"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestXSS_PostBodyDebug7(t *testing.T) {
    xss := NewXSSDetector(true, "block", false, nil)
    
    // Test POST with URL-encoded script tag body
    body := strings.NewReader("content=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
    r := httptest.NewRequest("POST", "/", body)
    r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    
    matched, pattern := xss.InspectRequest(r)
    fmt.Printf("POST encoded script: matched=%v pattern=%q\n", matched, pattern)
    
    if !matched {
        t.Error("Expected encoded script POST to be blocked")
    }
}
