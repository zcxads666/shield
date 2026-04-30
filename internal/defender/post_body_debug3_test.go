package defender

import (
    "fmt"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestXSS_PostBodyDebug3(t *testing.T) {
    // Test POST with ERB body
    body2 := strings.NewReader("content=<%=alert(1)%>")
    r2 := httptest.NewRequest("POST", "/", body2)
    r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    
    // Debug: print what collectParams returns
    params := collectParams(r2)
    fmt.Printf("Params count: %d\n", len(params))
    for i, p := range params {
        fmt.Printf("  param[%d]: %q\n", i, p)
    }
}
