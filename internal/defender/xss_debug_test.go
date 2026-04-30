package defender

import (
    "fmt"
    "net/http"
    "strings"
    "testing"
)

func TestXSS_Erb_Live(t *testing.T) {
    xss := NewXSSDetector(true, "block", false, nil)
    
    // Test GET with ERB
    r1, _ := http.NewRequest("GET", "/?content=%3C%25%3Dalert%281%29%25%3E", nil)
    matched1, pattern1 := xss.InspectRequest(r1)
    fmt.Printf("GET ERB: matched=%v pattern=%q\n", matched1, pattern1)
    if !matched1 {
        t.Error("Expected ERB payload to be detected in GET")
    }
    
    // Test POST with ERB
    r2, _ := http.NewRequest("POST", "/", strings.NewReader("content=%3C%25%3Dalert%281%29%25%3E"))
    r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    matched2, pattern2 := xss.InspectRequest(r2)
    fmt.Printf("POST ERB: matched=%v pattern=%q\n", matched2, pattern2)
    if !matched2 {
        t.Error("Expected ERB payload to be detected in POST")
    }
}
