package defender

import (
	"bufio"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/shield/shield/internal/logger"
)

func loadPayloads(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open payload file %s: %v", path, err)
	}
	defer f.Close()

	var payloads []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		payloads = append(payloads, line)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read payload file: %v", err)
	}
	return payloads
}

func makeRequestWithParam(t *testing.T, param, value string) *http.Request {
	t.Helper()
	req, _ := http.NewRequest("GET", "http://localhost/?"+url.QueryEscape(param)+"="+url.QueryEscape(value), nil)
	return req
}

func makePostRequestWithParam(t *testing.T, param, value string) *http.Request {
	t.Helper()
	req, _ := http.NewRequest("POST", "http://localhost/", strings.NewReader(url.QueryEscape(param)+"="+url.QueryEscape(value)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// TestSQLInjection_PayloadFile 使用测试数据文件验证 SQL 注入拦截率
func TestSQLInjection_PayloadFile(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	injector := NewSQLInjector(true, "block", log)

	payloads := loadPayloads(t, "../../testdata/payloads/sql_injection.txt")
	if len(payloads) == 0 {
		t.Fatal("no payloads loaded")
	}

	blocked := 0
	for _, p := range payloads {
		req := makeRequestWithParam(t, "q", p)
		if matched, _ := injector.Inspect(req); matched {
			blocked++
		}
	}

	rate := float64(blocked) / float64(len(payloads))
	t.Logf("SQL Injection: total=%d, blocked=%d, rate=%.2f%%", len(payloads), blocked, rate*100)
	if rate < 0.70 {
		t.Fatalf("SQL 注入拦截率 %.2f%% 低于 70%% 标准", rate*100)
	}
}

// TestSQLInjection_PostPayloadFile 验证 POST 参数中的 SQL 注入检测
func TestSQLInjection_PostPayloadFile(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	injector := NewSQLInjector(true, "block", log)

	payloads := loadPayloads(t, "../../testdata/payloads/sql_injection.txt")
	blocked := 0
	for _, p := range payloads {
		req := makePostRequestWithParam(t, "q", p)
		if matched, _ := injector.Inspect(req); matched {
			blocked++
		}
	}

	rate := float64(blocked) / float64(len(payloads))
	t.Logf("SQL Injection POST: total=%d, blocked=%d, rate=%.2f%%", len(payloads), blocked, rate*100)
	if rate < 0.70 {
		t.Fatalf("POST SQL 注入拦截率 %.2f%% 低于 70%% 标准", rate*100)
	}
}

// TestSQLInjection_BenignNotBlocked 验证正常请求不被误拦截
func TestSQLInjection_BenignNotBlocked(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	injector := NewSQLInjector(true, "block", log)

	benign := loadPayloads(t, "../../testdata/benign/normal_requests.txt")
	edge := loadPayloads(t, "../../testdata/benign/edge_cases.txt")
	all := append(benign, edge...)

	falsePositives := 0
	for _, input := range all {
		req := makeRequestWithParam(t, "q", input)
		if matched, _ := injector.Inspect(req); matched {
			falsePositives++
			t.Logf("false positive: %s", input)
		}
	}

	fpRate := float64(falsePositives) / float64(len(all))
	t.Logf("SQL Injection False Positives: total=%d, fp=%d, rate=%.2f%%", len(all), falsePositives, fpRate*100)
	if fpRate > 0.10 {
		t.Fatalf("SQL 注入误报率 %.2f%% 高于 10%% 标准", fpRate*100)
	}
}

// TestXSS_PayloadFile 使用测试数据文件验证 XSS 拦截率
func TestXSS_PayloadFile(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	detector := NewXSSDetector(true, "block", false, log)

	payloads := loadPayloads(t, "../../testdata/payloads/xss.txt")
	if len(payloads) == 0 {
		t.Fatal("no payloads loaded")
	}

	blocked := 0
	for _, p := range payloads {
		req := makeRequestWithParam(t, "content", p)
		if matched, _ := detector.InspectRequest(req); matched {
			blocked++
		}
	}

	rate := float64(blocked) / float64(len(payloads))
	t.Logf("XSS: total=%d, blocked=%d, rate=%.2f%%", len(payloads), blocked, rate*100)
	if rate < 0.60 {
		t.Fatalf("XSS 拦截率 %.2f%% 低于 60%% 标准", rate*100)
	}
}

// TestXSS_BenignNotBlocked 验证正常请求不被 XSS 误拦截
func TestXSS_BenignNotBlocked(t *testing.T) {
	log, _ := logger.New("warn", "json", "stderr")
	detector := NewXSSDetector(true, "block", false, log)

	benign := loadPayloads(t, "../../testdata/benign/normal_requests.txt")
	edge := loadPayloads(t, "../../testdata/benign/edge_cases.txt")
	all := append(benign, edge...)

	falsePositives := 0
	for _, input := range all {
		req := makeRequestWithParam(t, "content", input)
		if matched, _ := detector.InspectRequest(req); matched {
			falsePositives++
			t.Logf("false positive: %s", input)
		}
	}

	fpRate := float64(falsePositives) / float64(len(all))
	t.Logf("XSS False Positives: total=%d, fp=%d, rate=%.2f%%", len(all), falsePositives, fpRate*100)
	if fpRate > 0.05 {
		t.Fatalf("XSS 误报率 %.2f%% 高于 5%% 标准", fpRate*100)
	}
}

// TestSanitize 验证 XSS Sanitize 函数
func TestSanitize_Comprehensive(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"<script>alert(1)</script>", "&lt;script&gt;alert(1)&lt;&#x2F;script&gt;"},
		{"<img src=x onerror=alert(1)>", "&lt;img src=x onerror=alert(1)&gt;"},
		{"\"quoted\"", "&quot;quoted&quot;"},
		{"it's", "it&#x27;s"},
		{"path/to/file", "path&#x2F;to&#x2F;file"},
	}
	for _, c := range cases {
		got := Sanitize(c.input)
		if got != c.expected {
			t.Errorf("Sanitize(%q) = %q, want %q", c.input, got, c.expected)
		}
	}
}

// BenchmarkSQLInjection_Detect 检测性能基准
func BenchmarkSQLInjection_Detect(b *testing.B) {
	log, _ := logger.New("warn", "json", "stderr")
	injector := NewSQLInjector(true, "block", log)
	req, _ := http.NewRequest("GET", "http://localhost/?q=1'+UNION+SELECT+*+FROM+users--", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		injector.Inspect(req)
	}
}

// BenchmarkXSS_Detect 检测性能基准
func BenchmarkXSS_Detect(b *testing.B) {
	log, _ := logger.New("warn", "json", "stderr")
	detector := NewXSSDetector(true, "block", false, log)
	req, _ := http.NewRequest("GET", "http://localhost/?content=<script>alert(1)</script>", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.InspectRequest(req)
	}
}
