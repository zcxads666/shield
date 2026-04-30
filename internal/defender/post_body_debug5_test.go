package defender

import (
    "fmt"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestXSS_PostBodyDebug5(t *testing.T) {
    // Test POST with URL-encoded ERB body
    body := strings.NewReader("content=%3C%25%3Dalert%281%29%25%3E")
    r := httptest.NewRequest("POST", "/", body)
    r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    
    // Need to call ParseForm first
    err := r.ParseForm()
    fmt.Printf("ParseForm error: %v\n", err)
    
    // Debug: print what collectParams returns
    params := collectParams(r)
    fmt.Printf("Params count: %d\n", len(params))
    for i, p := range params {
        fmt.Printf("  param[%d]: %q\n", i, p)
    }
}
