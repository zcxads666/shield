package defender

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/shield/shield/internal/logger"
)

func TestPayloadFileCoverage(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewSQLInjector(true, "block", log)

	payloads := []string{
		"1' UNION SELECT username, password FROM users--",
		"1' UNION ALL SELECT null, version()--",
		"' UNION SELECT * FROM information_schema.tables--",
		"-1 UNION SELECT 1,2,3--",
		"1' UNION SELECT null, load_file('/etc/passwd')--",
		"1 UNION SELECT user, password FROM mysql.user--",
		"' UNION SELECT banner FROM v$version--",
		"1 UNION SELECT name, sql FROM sqlite_master--",
		"1' AND extractvalue(1, concat(0x7e, (SELECT @@version)))--",
		"1' AND updatexml(1, concat(0x7e, (SELECT database())), 1)--",
		"1' AND 1=convert(int, (SELECT @@version))--",
		"1' AND 1=1--",
		"1' AND 1=2--",
		"1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
		"1' AND (SELECT COUNT(*) FROM users)>0--",
		"1' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'--",
		"1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
		"1'; WAITFOR DELAY '0:0:5'--",
		"1' AND pg_sleep(5)--",
		"1' AND benchmark(10000000, md5('test'))--",
		"1; DROP TABLE users--",
		"1; INSERT INTO logs VALUES ('hacked')--",
		"1; DELETE FROM users WHERE '1'='1'--",
		"1; UPDATE users SET password='hacked' WHERE username='admin'--",
		"1; CREATE USER hacker IDENTIFIED BY 'password'--",
		"1/**/UNION/**/SELECT/**/username,password/**/FROM/**/users--",
		"1'/*!50000UNION*/ SELECT username, password FROM users--",
		"1'--\nUNION SELECT * FROM users--",
		"1' /* comment */ UNION SELECT * FROM users--",
		"1%27%20UNION%20SELECT%20*%20FROM%20users--",
		"1\x27 UNION SELECT * FROM users--",
		"1%2527 UNION SELECT * FROM users--",
		"1'+%55%4E%49%4F%4E+SELECT+*+FROM+users--",
		"1%2527%2520UNION%2520SELECT%2520*%2520FROM%2520users--",
		"1%df' UNION SELECT * FROM users--",
		"1%df%5c' UNION SELECT * FROM users--",
		"1 AND 1=1",
		"1 AND 1=2",
		"-1 OR 1=1",
		"1 AND 1=convert(int,@@version)",
		"1 ORDER BY 1--",
		"1 ORDER BY 10--",
		"1 ORDER BY (SELECT @@version)--",
		"1 LIMIT 1 OFFSET (SELECT COUNT(*) FROM users)--",
		"1 LIMIT (SELECT COUNT(*) FROM passwords)--",
		"1' UNION SELECT 'hacked' INTO OUTFILE '/var/www/html/shell.php'--",
		"1' UNION SELECT '<?php eval($_POST[1]);?>' INTO OUTFILE '/tmp/shell.php'--",
		"1 AND (SELECT COUNT(*) FROM information_schema.tables)>0",
		"1 AND (SELECT LENGTH(password) FROM users LIMIT 1)>5",
		"1 AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'",
		"1' HAVING 1=1--",
		"1' GROUP BY users.id HAVING 1=1--",
		"1'; EXEC master..xp_cmdshell 'whoami'--",
		"1'; EXEC xp_cmdshell 'dir'--",
		"1'; CALL shell('whoami')--",
		"1' || '1'='1",
		"1' && '1'='1",
		"1' OR 'x'='x",
		"1' AND 'x'='x",
	}

	blocked := 0
	for _, p := range payloads {
		u, _ := url.Parse("http://example.com/?q=" + url.QueryEscape(p))
		r := &http.Request{URL: u, Method: "GET"}
		matched, _ := inj.Inspect(r)
		if matched {
			blocked++
		} else {
			t.Logf("NOT BLOCKED: %s", p)
		}
	}
	rate := float64(blocked) / float64(len(payloads)) * 100
	t.Logf("Block rate: %.1f%% (%d/%d)", rate, blocked, len(payloads))
	if rate < 95.0 {
		t.Errorf("Block rate %.1f%% < 95%%", rate)
	}
}

func TestBenignFileCoverage(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewSQLInjector(true, "block", log)

	benign := []string{
		"GET / HTTP/1.1",
		"GET /index.html HTTP/1.1",
		"GET /about HTTP/1.1",
		"GET /contact HTTP/1.1",
		"GET /products HTTP/1.1",
		"GET /products/123 HTTP/1.1",
		"GET /search?q=laptop HTTP/1.1",
		"GET /search?q=hello+world HTTP/1.1",
		"GET /user/profile HTTP/1.1",
		"GET /api/v1/users?page=1&limit=20 HTTP/1.1",
		"username=alice&password=MySecureP@ss123",
		"email=alice@example.com&password=MySecureP@ss123&confirm=MySecureP@ss123",
		"name=Alice&email=alice@example.com&message=Hello, I have a question about your product.",
		`{"title": "Introduction to Go", "content": "Go is a statically typed, compiled programming language..."}`,
		`{"post_id": 42, "content": "Great article! Thanks for sharing."}`,
		"q=C++ programming & algorithms",
		`content=I love using div tags in HTML!`,
		`{"language": "python", "code": "def hello():\n    print('Hello, World!')\n"}`,
		`{"markdown": "# Hello\n\nThis is **bold** and *italic*."}`,
		"------WebKitFormBoundary",
		`{"items": [{"product_id": "SKU-001", "quantity": 2, "price": 19.99}]}`,
		`{"query": "query GetUser($id: ID!) { user(id: $id) { name email posts { title } } }", "variables": {"id": "123"}}`,
		"GET /api/v1/products?category=electronics&price_min=100&price_max=500&sort=price_desc&filter=brand:Apple,Samsung HTTP/1.1",
		`{"event": "payment.success", "data": {"order_id": "ORD-12345", "amount": 99.99, "currency": "USD"}}`,
		"GET /auth/callback?code=abc123&state=xyz789 HTTP/1.1",
		"GET /search?q=how+to+use+SELECT+statement+in+SQL&category=tutorial HTTP/1.1",
		"SELECT * FROM candidates WHERE name = 'Alice' AND status = 'active'",
		"UPDATE users SET last_login = NOW() WHERE id = 42",
		"DELETE FROM sessions WHERE expired = true",
		"INSERT INTO audit_log VALUES (1, 'login', '192.168.1.1')",
		"DROP TABLE IF EXISTS temp_table",
		"CREATE INDEX idx_email ON users(email)",
		"ALTER TABLE users ADD COLUMN phone VARCHAR(20)",
		"In SQL, you can use UNION to combine results from multiple queries.",
		"To prevent SQL injection, always use parameterized queries like: SELECT * FROM users WHERE id = ?",
		"The HAVING clause is used with GROUP BY to filter groups.",
		"/usr/local/bin/go",
		"/var/log/nginx/access.log",
		"C:\\Program Files\\Go\\bin\\go.exe",
		"../assets/logo.png",
		"../../images/photo.jpg",
		`#include <stdio.h>\nint main() { printf("Hello, World!\n"); return 0; }`,
		`<script src="/app.js"></script>`,
		`<link rel="stylesheet" href="/style.css">`,
		"https://example.com/search?q=hello&page=1",
		"mailto:test@example.com?subject=Hello&body=World",
		"file:///etc/hosts",
		"1 < 2 && 3 > 1",
		"a <= b || c >= d",
		"x != y && z == w",
		`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
		`\d{3}-\d{2}-\d{4}`,
		`<div onclick="handleClick()">Click me</div>`,
		`<button onmouseover="showTooltip()">Hover</button>`,
	}

	fp := 0
	for _, b := range benign {
		u, _ := url.Parse("http://example.com/?q=" + url.QueryEscape(b))
		r := &http.Request{URL: u, Method: "GET"}
		matched, pattern := inj.Inspect(r)
		if matched {
			fp++
			t.Logf("FP: %s (pattern=%s)", b, pattern)
		}
	}
	fpRate := float64(fp) / float64(len(benign)) * 100
	t.Logf("False positive rate: %.1f%% (%d/%d)", fpRate, fp, len(benign))
	if fpRate > 10.0 {
		t.Errorf("FP rate %.1f%% > 10%%", fpRate)
	}
}

func TestEdgeCases(t *testing.T) {
	log, _ := logger.New("warn", "json", "")
	inj := NewSQLInjector(true, "block", log)

	cases := []struct {
		input       string
		shouldBlock bool
		desc        string
	}{
		// Multipart boundaries should NOT be blocked
		{"------WebKitFormBoundary", false, "WebKit boundary"},
		{"------WebKitFormBoundary--", false, "WebKit boundary end"},
		{"------Boundary--", false, "generic boundary"},
		{"----boundary--", false, "short boundary"},
		{"----b--", false, "minimal boundary"},
		{"----b", false, "minimal boundary no trailing"},
		{"----boundary", false, "boundary no trailing"},
		
		// SQL comments SHOULD be blocked
		{"1'; DROP TABLE users--", true, "SQL comment attack"},
		{"admin'--", true, "admin comment"},
		{"1'--", true, "simple comment"},
		{"';--", true, "semicolon comment"},
		{"'; DROP TABLE users --", true, "spaced comment"},
		{"1'; EXEC xp_cmdshell 'dir'--", true, "exec comment"},
		
		// Pure dashes - not really SQL injection without context
		{"------", false, "pure dashes 6"},
		{"----", false, "pure dashes 4"},
		{"--------", false, "pure dashes 8"},
		
		// Edge cases that should NOT be blocked
		{"--markdown header", false, "markdown header"},
		{"-- \n", false, "dash space newline"},
		{"--boundary", false, "dash boundary"},
		{"---boundary", false, "triple dash boundary"},
		{"--boundary--", false, "dash boundary dash"},
		{"--boundary\n", false, "dash boundary newline"},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			u, _ := url.Parse("http://example.com/?q=" + url.QueryEscape(c.input))
			r := &http.Request{URL: u, Method: "GET"}
			matched, pattern := inj.Inspect(r)
			if matched != c.shouldBlock {
				if c.shouldBlock {
					t.Errorf("FN: %s expected BLOCK, got PASS", c.desc)
				} else {
					t.Errorf("FP: %s expected PASS, got BLOCK (pattern=%s)", c.desc, pattern)
				}
			}
		})
	}
}
