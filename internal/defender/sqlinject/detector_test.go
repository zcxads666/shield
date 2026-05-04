package sqlinject

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/shield/shield/pkg/logger"
)

func TestSQLInjector(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewDetector(true, "block", log)

	cases := []struct {
		name    string
		query   string
		blocked bool
	}{
		{"union select", "?id=1 UNION SELECT * FROM users", true},
		{"or 1=1", "?user=admin OR 1=1", true},
		{"normal", "?id=123", false},
		{"comment", "?id=1--", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/" + c.query)
			r := &http.Request{URL: u, Method: "GET"}
			matched, _ := inj.Inspect(r)
			if matched != c.blocked {
				t.Fatalf("expected blocked=%v, got=%v", c.blocked, matched)
			}
		})
	}
}

func TestMySQLFunctions(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewDetector(true, "block", log)

	cases := []struct {
		name    string
		payload string
	}{
		{"extractvalue basic", "?id=1 AND extractvalue(1,concat(0x7e,database()))"},
		{"extractvalue no space", "?id=1'AND extractvalue(1,concat(0x7e,(SELECT user())))--"},
		{"updatexml basic", "?id=1 AND updatexml(1,concat(0x7e,version()),1)"},
		{"updatexml union", "?id=1' UNION SELECT updatexml(1,concat(0x7e,database()),3)--"},
		{"mid function", "?id=1 AND mid((SELECT group_concat(schema_name) FROM information_schema.schemata),1,1)='a'"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/" + c.payload)
			r := &http.Request{URL: u, Method: "GET"}
			matched, pat := inj.Inspect(r)
			if !matched {
				t.Errorf("MySQL function %s not detected, payload=%s", c.name, c.payload)
			} else {
				t.Logf("detected by: %s", pat)
			}
		})
	}
}

func TestSQLInjectionHeaderDetection(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewDetector(true, "block", log)

	cases := []struct {
		name   string
		header string
		value  string
	}{
		{"User-Agent SQL injection", "User-Agent", "1' UNION SELECT * FROM users--"},
		{"X-Forwarded-For SQL injection", "X-Forwarded-For", "127.0.0.1' OR '1'='1"},
		{"Referer SQL injection", "Referer", "http://evil.com/1' AND 1=1--"},
		{"Custom header SQL injection", "X-Custom", "1; DROP TABLE users--"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?id=1")
			r := &http.Request{URL: u, Method: "GET", Header: make(http.Header)}
			r.Header.Set(c.header, c.value)
			matched, pat := inj.Inspect(r)
			if !matched {
				t.Errorf("%s not detected via header %s: %s", c.name, c.header, c.value)
			} else {
				t.Logf("header %s detected by: %s", c.header, pat)
			}
		})
	}
}

func TestSQLInjectionCookieDetection(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewDetector(true, "block", log)

	cases := []struct {
		name  string
		value string
	}{
		{"Cookie SQL injection OR", "session=1' OR '1'='1"},
		{"Cookie SQL injection UNION", "session=1 UNION SELECT password FROM users"},
		{"Cookie SQL injection comment", "session=1'; DROP TABLE users--"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?id=1")
			r := &http.Request{URL: u, Method: "GET", Header: make(http.Header)}
			// Use raw Cookie header to simulate real attack (AddCookie sanitizes values)
			r.Header.Set("Cookie", c.value)
			matched, pat := inj.Inspect(r)
			if !matched {
				t.Errorf("cookie injection not detected: %s", c.value)
			} else {
				t.Logf("cookie detected by: %s", pat)
			}
		})
	}
}

func TestSQLInjectionHashComment(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewDetector(true, "block", log)

	cases := []string{
		"?id=1'%23",
		"?id=1' UNION SELECT password FROM users%23",
		"?id=1'%23 SELECT password FROM users",
	}

	for _, payload := range cases {
		t.Run(payload[:min(25, len(payload))], func(t *testing.T) {
			u, _ := url.Parse("http://example.com/" + payload)
			r := &http.Request{URL: u, Method: "GET"}
			matched, pat := inj.Inspect(r)
			if !matched {
				t.Errorf("# comment injection not detected: %s", payload)
			} else {
				t.Logf("detected by: %s", pat)
			}
		})
	}
}

func TestSQLInjectionOrderByBypass(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewDetector(true, "block", log)

	cases := []string{
		"?order=1 ASC--",
		"?sort=1 DESC--",
		"?order=2 ASC%23 DROP TABLE--",
		"?id=1 ORDER BY 10--",
	}

	for _, payload := range cases {
		t.Run(payload[:min(25, len(payload))], func(t *testing.T) {
			u, _ := url.Parse("http://example.com/" + payload)
			r := &http.Request{URL: u, Method: "GET"}
			matched, pat := inj.Inspect(r)
			if !matched {
				t.Errorf("ORDER BY bypass not detected: %s", payload)
			} else {
				t.Logf("detected by: %s", pat)
			}
		})
	}
}

func TestSQLInjectionTautologyBypass(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewDetector(true, "block", log)

	cases := []string{
		"?id=1'||1=1",
		"?id=1'%26%261'='1",
		"?id=1%27%7c%7c1%3d1",
		"?id=1'||'1'='1'--",
	}

	for _, payload := range cases {
		t.Run(payload[:min(25, len(payload))], func(t *testing.T) {
			u, _ := url.Parse("http://example.com/" + payload)
			r := &http.Request{URL: u, Method: "GET"}
			matched, pat := inj.Inspect(r)
			if !matched {
				t.Errorf("tautology bypass not detected: %s", payload)
			} else {
				t.Logf("detected by: %s", pat)
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
