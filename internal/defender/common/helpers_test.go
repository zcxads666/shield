package common

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCollectParams_URLQuery(t *testing.T) {
	req := httptest.NewRequest("GET", "/search?q=test&page=1", nil)
	vals := CollectParams(req)
	found := false
	for _, v := range vals {
		if v == "test" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected query param 'test' in collected values")
	}
}

func TestCollectParamsWithBody_POSTForm(t *testing.T) {
	req := httptest.NewRequest("POST", "/login", strings.NewReader("user=admin&pass=123456"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	vals := CollectParamsWithBody(req, nil)
	foundUser := false
	foundPass := false
	for _, v := range vals {
		if v == "admin" {
			foundUser = true
		}
		if v == "123456" {
			foundPass = true
		}
	}
	if !foundUser || !foundPass {
		t.Fatalf("expected post form params in collected values, got %v", vals)
	}
}

func TestCollectParamsWithBody_RawBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/api", strings.NewReader("param=<script>alert(1)</script>"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	body := []byte("param=<script>alert(1)</script>")
	vals := CollectParamsWithBody(req, body)
	found := false
	for _, v := range vals {
		if strings.Contains(v, "<script>") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected body payload in collected values")
	}
}

func TestCollectParamsWithBody_GET(t *testing.T) {
	req := httptest.NewRequest("GET", "/search?q=hello", nil)
	vals := CollectParamsWithBody(req, nil)
	found := false
	for _, v := range vals {
		if v == "hello" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected GET query param in collected values")
	}
}

func TestCollectHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Referer", "https://example.com")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("Accept-Language", "en-US")
	vals := CollectHeaders(req)
	if len(vals) < 4 {
		t.Fatalf("expected at least 4 header values, got %d", len(vals))
	}
}

func TestCollectHeaders_Empty(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	// CollectHeaders returns nil/empty when no headers are present.
	// Just ensure CollectHeaders doesn't panic.
	_ = CollectHeaders(req)
}

func TestCollectCookies(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: "abc123"})
	req.AddCookie(&http.Cookie{Name: "token", Value: "xyz789"})
	vals := CollectCookies(req)
	if len(vals) < 2 {
		t.Fatalf("expected at least 2 cookie values, got %d: %v", len(vals), vals)
	}
}

func TestCollectCookies_None(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	vals := CollectCookies(req)
	if len(vals) > 0 {
		t.Fatalf("expected 0 cookie values, got %d", len(vals))
	}
}

func TestNormalizeInput_URLDecode(t *testing.T) {
	result := NormalizeInput("%27%20OR%201%3D1")
	if !strings.Contains(result, "'") || !strings.Contains(result, "1=1") {
		t.Errorf("expected URL decode, got %q", result)
	}
}

func TestNormalizeInput_DoubleEncoding(t *testing.T) {
	result := NormalizeInput("%2527")
	if !strings.Contains(result, "'") {
		t.Errorf("expected double URL decode to produce single quote, got %q", result)
	}
}

func TestNormalizeInput_HexEscapes(t *testing.T) {
	result := NormalizeInput(`\x27\x20\x4F\x52`)
	if !strings.Contains(result, "'") {
		t.Errorf("expected hex escape decode, got %q", result)
	}
}

func TestNormalizeInput_UnicodeEscapes(t *testing.T) {
	result := NormalizeInput(`' OR`)
	if !strings.Contains(result, "'") {
		t.Errorf("expected unicode escape decode, got %q", result)
	}
}

func TestNormalizeInput_HTMLEntitiesDecimal(t *testing.T) {
	result := NormalizeInput("&#60;script&#62;")
	if !strings.Contains(result, "<") || !strings.Contains(result, ">") {
		t.Errorf("expected HTML decimal entity decode, got %q", result)
	}
}

func TestNormalizeInput_HTMLEntitiesHex(t *testing.T) {
	result := NormalizeInput("&#x3C;script&#x3E;")
	if !strings.Contains(result, "<") || !strings.Contains(result, ">") {
		t.Errorf("expected HTML hex entity decode, got %q", result)
	}
}

func TestNormalizeInput_NullByteRemoval(t *testing.T) {
	result := NormalizeInput("test\x00payload")
	if strings.Contains(result, "\x00") {
		t.Error("expected null bytes to be removed")
	}
}

func TestNormalizeInput_WhitespaceNormalization(t *testing.T) {
	result := NormalizeInput("a\x0bb\x0cc\xa0d")
	if strings.Contains(result, "\x0b") || strings.Contains(result, "\x0c") || strings.Contains(result, "\xa0") {
		t.Error("expected special whitespace to be normalized to space")
	}
}

func TestNormalizeInput_PercentUUnicode(t *testing.T) {
	result := NormalizeInput("%u0027")
	if !strings.Contains(result, "'") {
		t.Errorf("expected %%uXXXX unicode decode, got %q", result)
	}
}

func TestNormalizeInput_MultipleTransformations(t *testing.T) {
	result := NormalizeInput("%u0027%20OR%201=1")
	if !strings.Contains(result, "'") {
		t.Errorf("expected combined decode, got %q", result)
	}
}

func TestExtractRawQueryValues(t *testing.T) {
	vals := ExtractRawQueryValues("q=test&page=1&name=hello")
	found := false
	for _, v := range vals {
		if v == "test" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to find 'test' in raw query values, got %v", vals)
	}
}

func TestExtractRawQueryValues_Empty(t *testing.T) {
	vals := ExtractRawQueryValues("")
	if len(vals) != 0 {
		t.Fatalf("expected 0 values for empty query, got %d", len(vals))
	}
}

func TestExtractRawQueryValues_HTMLEncodingInQuery(t *testing.T) {
	vals := ExtractRawQueryValues("name&#61;value&x=y")
	foundX := false
	for _, v := range vals {
		if v == "y" {
			foundX = true
			break
		}
	}
	if !foundX {
		t.Fatalf("expected to find 'y' in values, got %v", vals)
	}
}

func TestSmartAmpSplit(t *testing.T) {
	parts := SmartAmpSplit("a=1&b=2&c=3")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts, got %d: %v", len(parts), parts)
	}
}

func TestSmartAmpSplit_Single(t *testing.T) {
	parts := SmartAmpSplit("single")
	if len(parts) != 1 {
		t.Fatalf("expected 1 part, got %d", len(parts))
	}
	if parts[0] != "single" {
		t.Errorf("expected 'single', got %q", parts[0])
	}
}
