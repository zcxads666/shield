package defender

import (
    "fmt"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestXSS_PostBodyDebug(t *testing.T) {
    xss := NewXSSDetector(true, "block", false, nil)
    
    // Test POST with ERB body
    body2 := strings.NewReader("content=<%=alert(1)%>")
    r2 := httptest.NewRequest("POST", "/", body2)
    r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    
    // Debug: print what collectParams returns
    params := collectParams(r2)
    for _, p := range params {
        fmt.Printf("  param: %q\n", p)
    }
    
    matched2, pattern2 := xss.InspectRequest(r2)
    fmt.Printf("POST ERB: matched=%v pattern=%q\n", matched2, pattern2)
}
