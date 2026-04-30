package defender

import (
    "fmt"
    "net/http"
    "net/url"
    "testing"
)

func TestXSS_ErbBypass(t *testing.T) {
    xss := NewXSSDetector(true, "block", false, nil)
    
    testCases := []struct {
        name      string
        rawQuery  string
        wantMatch bool
    }{
        {"script_tag", "content=%3Cscript%3Ealert%281%29%3C%2Fscript%3E", true},
        {"erb_plus", "content=%3C%25%3D+alert%281%29+%25%3E", true},
        {"erb_space", "content=%3C%25%3D%20alert%281%29%20%25%3E", true},
        {"erb_nospace", "content=%3C%25%3Dalert%281%29%25%3E", true},
    }
    
    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            u, _ := url.Parse("http://127.0.0.1:18080/?" + tc.rawQuery)
            r := &http.Request{
                URL:    u,
                Method: "GET",
            }
            
            // Debug: print what collectParams returns
            params := collectParams(r)
            for _, p := range params {
                fmt.Printf("  param: %q\n", p)
            }
            
            matched, pattern := xss.InspectRequest(r)
            fmt.Printf("Test %s: matched=%v pattern=%q\n", tc.name, matched, pattern)
            
            if matched != tc.wantMatch {
                t.Errorf("InspectRequest() matched=%v, want %v", matched, tc.wantMatch)
            }
        })
    }
}
