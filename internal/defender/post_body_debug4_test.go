package defender

import (
    "fmt"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestXSS_PostBodyDebug4(t *testing.T) {
    // Test POST with ERB body
    body2 := strings.NewReader("content=<%=alert(1)%>")
    r2 := httptest.NewRequest("POST", "/", body2)
    r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    
    // Need to call ParseForm first
    err := r2.ParseForm()
    fmt.Printf("ParseForm error: %v\n", err)
    
    // Debug: print what collectParams returns
    params := collectParams(r2)
    fmt.Printf("Params count: %d\n", len(params))
    for i, p := range params {
        fmt.Printf("  param[%d]: %q\n", i, p)
    }
}
