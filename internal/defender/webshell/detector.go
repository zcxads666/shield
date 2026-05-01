package webshell

import (
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/shield/shield/pkg/logger"
	"github.com/shield/shield/pkg/metrics"
)

// WebShellDetector detects web shell upload attempts.
type Detector struct {
	enabled  bool
	action   string
	logger   *logger.Logger
	mu       sync.RWMutex
	patterns []*regexp.Regexp
}

// Dangerous file extensions that may contain executable code.
var dangerousExts = map[string]bool{
	".php": true, ".php3": true, ".php4": true, ".php5": true,
	".phtml": true, ".phar": true,
	".jsp": true, ".jspx": true, ".jsw": true, ".jsv": true, ".jspf": true,
	".asp": true, ".aspx": true, ".ascx": true, ".ashx": true, ".asmx": true,
	".cer": true, ".cdx": true, ".asa": true,
	".sh": true, ".bash": true, ".zsh": true,
	".py": true, ".pyc": true, ".pyo": true,
	".pl": true, ".cgi": true, ".cmd": true, ".bat": true,
	".war": true, ".ear": true,
}

// Double-extension bypass patterns: executable + image/text extension.
var doubleExtPatterns = []string{
	`(?i)\.(php|jsp|asp|aspx|sh|py|pl|cgi)\.(jpg|jpeg|png|gif|bmp|txt|pdf|doc|docx|zip|rar|7z|html|htm|xml|json)$`,
}

// Web shell content patterns (dangerous functions / code signatures).
var defaultWebShellPatterns = []string{
	// PHP dangerous functions
	`(?i)<\?php\s+.*\b(eval|assert|system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec|base64_decode)\s*\(`,
	`(?i)<\?php\s+.*\b(passthru|shell_exec|system|exec|proc_open|popen)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)`,
	`(?i)<\?php\s+.*@\s*(eval|assert|system|exec|shell_exec|passthru)\s*\(`,
	`(?i)<\?\s+.*\beval\s*\(\s*\$`,
	// JSP dangerous patterns
	`(?i)<%\s*.*Runtime\.getRuntime\(\)\.exec`,
	`(?i)<%\s*.*ProcessBuilder\s*\(`,
	`(?i)<%\s*.*request\.getParameter`,
	`(?i)<%\s*.*out\.println`,
	// ASP dangerous patterns
	`(?i)<%\s*.*Server\.CreateObject`,
	`(?i)<%\s*.*WScript\.Shell`,
	`(?i)<%\s*.*Scripting\.FileSystemObject`,
	// Generic backdoor signatures
	`(?i)\b(eval|assert|system|exec|shell_exec|passthru)\s*\(\s*(base64_decode|str_rot13|gzinflate|gzuncompress)`,
	`(?i)file_put_contents\s*\(.*\$_(GET|POST|REQUEST)`,
	`(?i)fopen\s*\(.*\$_(GET|POST|REQUEST)`,
	// Common obfuscation
	`(?i)\\x65\\x76\\x61\\x6c`, // hex encoded "eval"
	`(?i)\\x73\\x79\\x73\\x74\\x65\\x6d`, // hex encoded "system"
}

// NewWebShellDetector creates a web shell upload detector.
func NewDetector(enabled bool, action string, log *logger.Logger) *Detector {
	w := &Detector{
		enabled: enabled,
		action:  action,
		logger:  log,
	}
	w.ReloadPatterns(defaultWebShellPatterns)
	return w
}

// ReloadPatterns updates detection patterns.
func (w *Detector) ReloadPatterns(patterns []string) {
	regs := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile(p); err == nil {
			regs = append(regs, re)
		}
	}
	w.mu.Lock()
	w.patterns = regs
	w.mu.Unlock()
}

// InspectRequest checks a request for web shell upload attempts.
// It examines multipart file uploads, raw body uploads, and filename headers.
func (w *Detector) InspectRequest(r *http.Request) (bool, string) {
	if !w.enabled {
		return false, ""
	}

	// Check X-Filename header for direct uploads
	if filename := r.Header.Get("X-Filename"); filename != "" {
		if matched, reason := w.checkFilename(filename); matched {
			return true, reason
		}
	}

	// Check Content-Disposition filename for multipart uploads
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") {
		// Parse multipart form to extract filenames
		if err := r.ParseMultipartForm(32 << 20); err == nil { // 32MB max
			if r.MultipartForm != nil {
				for _, files := range r.MultipartForm.File {
					for _, fh := range files {
						if matched, reason := w.checkFilename(fh.Filename); matched {
							// Also check file content if available
							if f, err := fh.Open(); err == nil {
								defer f.Close()
								buf := make([]byte, 4096)
								n, _ := f.Read(buf)
								if matched2, reason2 := w.checkContent(string(buf[:n])); matched2 {
									return true, reason2
								}
							}
							return true, reason
						}
						// Check content even if extension looks safe
						if f, err := fh.Open(); err == nil {
							defer f.Close()
							buf := make([]byte, 4096)
							n, _ := f.Read(buf)
							if matched, reason := w.checkContent(string(buf[:n])); matched {
								return true, reason
							}
						}
					}
				}
			}
		}
	}

	// Check raw body content for non-multipart uploads
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		// Try to read body content
		bodyBytes := make([]byte, 4096)
		n, _ := r.Body.Read(bodyBytes)
		if n > 0 {
			if matched, reason := w.checkContent(string(bodyBytes[:n])); matched {
				return true, reason
			}
		}
	}

	return false, ""
}

// InspectRequestWithBody checks request with pre-read body bytes.
func (w *Detector) InspectRequestWithBody(r *http.Request, bodyBytes []byte) (bool, string) {
	if !w.enabled {
		return false, ""
	}

	// Check X-Filename header for direct uploads
	if filename := r.Header.Get("X-Filename"); filename != "" {
		if matched, reason := w.checkFilename(filename); matched {
			// Also check body content
			if len(bodyBytes) > 0 {
				if matched2, reason2 := w.checkContent(string(bodyBytes)); matched2 {
					return true, reason2
				}
			}
			return true, reason
		}
	}

	// Check multipart form data from body
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") && len(bodyBytes) > 0 {
		// Extract boundary
		boundary := ""
		for _, part := range strings.Split(contentType, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "boundary=") {
				boundary = strings.TrimPrefix(part, "boundary=")
				boundary = strings.Trim(boundary, `"`)
				break
			}
		}
		if boundary != "" {
			if matched, reason := w.checkMultipartBody(bodyBytes, boundary); matched {
				return true, reason
			}
		}
	}

	// Check raw body content
	if len(bodyBytes) > 0 {
		if matched, reason := w.checkContent(string(bodyBytes)); matched {
			return true, reason
		}
	}

	return false, ""
}

// checkMultipartBody parses multipart body manually to extract filename and content.
func (w *Detector) checkMultipartBody(bodyBytes []byte, boundary string) (bool, string) {
	body := string(bodyBytes)
	// Find all Content-Disposition headers with filename
	lines := strings.Split(body, "\r\n")
	var currentFilename string
	inContent := false
	var contentParts []string

	for i, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "content-disposition") && strings.Contains(lower, "filename=") {
			// Extract filename
			start := strings.Index(line, "filename=")
			if start >= 0 {
				fname := line[start+9:]
				fname = strings.Trim(fname, `"`)
				fname = strings.Trim(fname, `'`) 
				currentFilename = fname
				if matched, reason := w.checkFilename(currentFilename); matched {
					return true, reason
				}
			}
		}
		if line == "" && currentFilename != "" {
			inContent = true
			continue
		}
		if inContent && strings.HasPrefix(line, "--"+boundary) {
			// End of part, check collected content
			if len(contentParts) > 0 {
				content := strings.Join(contentParts, "\r\n")
				if matched, reason := w.checkContent(content); matched {
					return true, reason
				}
			}
			currentFilename = ""
			inContent = false
			contentParts = nil
			continue
		}
		if inContent {
			contentParts = append(contentParts, line)
		}
		// Also check the last part
		if i == len(lines)-1 && inContent && len(contentParts) > 0 {
			content := strings.Join(contentParts, "\r\n")
			if matched, reason := w.checkContent(content); matched {
				return true, reason
			}
		}
	}
	return false, ""
}

// checkFilename checks if a filename indicates a dangerous upload.
func (w *Detector) checkFilename(filename string) (bool, string) {
	ext := strings.ToLower(filepath.Ext(filename))
	if dangerousExts[ext] {
		metrics.Get().IncWebShellUploads()
		if w.logger != nil {
			w.logger.Warn("webshell_upload_detected", map[string]interface{}{
				"reason":   "dangerous_extension",
				"filename": filename,
				"ext":      ext,
			})
		}
		return true, "dangerous_extension:" + ext
	}

	// Check double extension bypass
	for _, pattern := range doubleExtPatterns {
		if re, err := regexp.Compile(pattern); err == nil && re.MatchString(filename) {
			metrics.Get().IncWebShellUploads()
			if w.logger != nil {
				w.logger.Warn("webshell_upload_detected", map[string]interface{}{
					"reason":   "double_extension_bypass",
					"filename": filename,
				})
			}
			return true, "double_extension_bypass"
		}
	}

	return false, ""
}

// checkContent checks file/body content for web shell signatures.
func (w *Detector) checkContent(content string) (bool, string) {
	w.mu.RLock()
	patterns := w.patterns
	w.mu.RUnlock()

	for _, re := range patterns {
		if re.MatchString(content) {
			metrics.Get().IncWebShellUploads()
			if w.logger != nil {
				w.logger.Warn("webshell_upload_detected", map[string]interface{}{
					"reason":  "dangerous_content",
					"pattern": re.String(),
				})
			}
			return true, "dangerous_content:" + re.String()
		}
	}

	// Check for PHP/JSP tags in image files (image horse)
	lowerContent := strings.ToLower(content)
	if strings.HasPrefix(lowerContent, "gif89a") || strings.HasPrefix(lowerContent, "\x89png") || strings.HasPrefix(lowerContent, "\xff\xd8") {
		if strings.Contains(lowerContent, "<?php") || strings.Contains(lowerContent, "<%") {
			metrics.Get().IncWebShellUploads()
			if w.logger != nil {
				w.logger.Warn("webshell_upload_detected", map[string]interface{}{
					"reason": "image_horse",
				})
			}
			return true, "image_horse"
		}
	}

	return false, ""
}

// ExtractFilenameFromMultipart extracts filenames from multipart form.
func ExtractFilenameFromMultipart(r *http.Request) []string {
	var filenames []string
	if err := r.ParseMultipartForm(32 << 20); err == nil && r.MultipartForm != nil {
		for _, files := range r.MultipartForm.File {
			for _, fh := range files {
				filenames = append(filenames, fh.Filename)
			}
		}
	}
	return filenames
}

// IsDangerousExt checks if an extension is dangerous.
func IsDangerousExt(ext string) bool {
	return dangerousExts[strings.ToLower(ext)]
}
