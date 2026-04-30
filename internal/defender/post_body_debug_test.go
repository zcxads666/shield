package defender

import (
    "fmt"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestXSS_PostBody(t *testing.T) {
    xss := NewXSSDetector(true, "block", false, nil)
    
    // Test POST with script tag body
    bodyStr := "content=<script>alert(1)</script>"
    body := strings.NewReader(bodyStr)
    r := httptest.NewRequest("POST", "/", body)
    r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    
    matched, pattern := xss.InspectRequestWithBody(r, []byte(bodyStr))
    fmt.Printf("POST script: matched=%v pattern=%q\n", matched, pattern)
    
    // Test POST with ERB body
    bodyStr2 := "content=<%=alert(1)%>"
    body2 := strings.NewReader(bodyStr2)
    r2 := httptest.NewRequest("POST", "/", body2)
    r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    
    matched2, pattern2 := xss.InspectRequestWithBody(r2, []byte(bodyStr2))
    fmt.Printf("POST ERB: matched=%v pattern=%q\n", matched2, pattern2)
    
    if !matched {
        t.Error("Expected script tag POST to be blocked")
    }
    if !matched2 {
        t.Error("Expected ERB POST to be blocked")
    }
}
