package common

import (
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

func CollectParams(r *http.Request) []string {
	return CollectParamsWithBody(r, nil)
}

// collectParamsWithBody extracts all parameter values from the request,
// including URL query, POST form, and raw body bytes as fallback.
func CollectParamsWithBody(r *http.Request, bodyBytes []byte) []string {
	var vals []string
	for k, v := range r.URL.Query() {
		vals = append(vals, k)
		vals = append(vals, v...)
	}
	// Also extract raw query values to handle semicolons that Go's ParseQuery splits on
	vals = append(vals, ExtractRawQueryValues(r.URL.RawQuery)...)
	if r.Method == http.MethodPost {
		// Try ParseForm first (consumes body)
		err := r.ParseForm()
		if err == nil {
			for k, v := range r.PostForm {
				vals = append(vals, k)
				vals = append(vals, v...)
			}
		}
		// Fallback: also scan raw body bytes for payloads that ParseForm
		// couldn't decode (e.g., invalid URL escapes like "<%=...%>").
		if len(bodyBytes) > 0 {
			bodyStr := string(bodyBytes)
			for _, part := range strings.Split(bodyStr, "&") {
				if idx := strings.Index(part, "="); idx >= 0 {
					vals = append(vals, part[idx+1:])
				}
			}
		}
	}
	return vals
}

var (
	entityStart   = regexp.MustCompile(`^#\d+;|^#x[0-9a-fA-F]+;`)
	normReHex     = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
	normReUnicode = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	normReDec     = regexp.MustCompile(`&#(\d+);`)
	normReHexEnt  = regexp.MustCompile(`&#x([0-9a-fA-F]+);`)
	normReUXXXX   = regexp.MustCompile(`%u([0-9a-fA-F]{4})`)
)

func ExtractRawQueryValues(rawQuery string) []string {
	var vals []string
	if rawQuery == "" {
		return vals
	}
	// Split on & but preserve HTML entities like &#60; or &#x3C;
	pairs := SmartAmpSplit(rawQuery)
	for _, pair := range pairs {
		if idx := strings.IndexByte(pair, '='); idx >= 0 {
			key, err := UrlQueryUnescape(pair[:idx])
			if err != nil {
				key = pair[:idx]
			}
			val, err := UrlQueryUnescape(pair[idx+1:])
			if err != nil {
				val = pair[idx+1:]
			}
			vals = append(vals, key, val)
		} else {
			key, err := UrlQueryUnescape(pair)
			if err != nil {
				key = pair
			}
			vals = append(vals, key)
		}
	}
	return vals
}

func SmartAmpSplit(rawQuery string) []string {
	parts := strings.Split(rawQuery, "&")
	var result []string
	var current string
	for _, part := range parts {
		if current != "" && entityStart.MatchString(part) {
			current += "&" + part
			continue
		}
		if current != "" {
			result = append(result, current)
		}
		current = part
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func UrlQueryUnescape(s string) (string, error) {
	return url.QueryUnescape(s)
}

// normalizeInput decodes common encoding bypasses for detection.
func NormalizeInput(input string) string {
	s := input

	// Decode %uXXXX unicode escapes (ASP/IIS style) FIRST
	// before url.QueryUnescape, because %u0027 mixed with %20
	// causes url.QueryUnescape to fail on the %u sequence.
	s = normReUXXXX.ReplaceAllStringFunc(s, func(m string) string {
		r, _ := strconv.ParseUint(m[2:], 16, 32)
		return string(rune(r))
	})

	// Recursive URL decode (handles double encoding)
	for i := 0; i < 3; i++ {
		d, err := url.QueryUnescape(s)
		if err != nil || d == s {
			break
		}
		s = d
	}
	if s == "" {
		s = input
	}

	// Remove null bytes
	s = strings.ReplaceAll(s, "\x00", "")

	// Decode \xNN hex escapes
	s = normReHex.ReplaceAllStringFunc(s, func(m string) string {
		b, _ := strconv.ParseUint(m[2:], 16, 8)
		return string(byte(b))
	})

	// Decode \uNNNN unicode escapes
	s = normReUnicode.ReplaceAllStringFunc(s, func(m string) string {
		r, _ := strconv.ParseUint(m[2:], 16, 32)
		return string(rune(r))
	})

	// Decode HTML decimal entities &#NN;
	s = normReDec.ReplaceAllStringFunc(s, func(m string) string {
		matches := normReDec.FindStringSubmatch(m)
		if len(matches) > 1 {
			n, _ := strconv.Atoi(matches[1])
			if n > 0 && n <= 0x10FFFF {
				return string(rune(n))
			}
		}
		return m
	})

	// Decode HTML hex entities &#xNN;
	s = normReHexEnt.ReplaceAllStringFunc(s, func(m string) string {
		matches := normReHexEnt.FindStringSubmatch(m)
		if len(matches) > 1 {
			n, _ := strconv.ParseUint(matches[1], 16, 32)
			if n > 0 && n <= 0x10FFFF {
				return string(rune(n))
			}
		}
		return m
	})

	// Normalize whitespace: VT(0x0b), FF(0x0c), NBSP(0xa0) → space
	for _, c := range []string{"\x0b", "\x0c", "\xa0"} {
		s = strings.ReplaceAll(s, c, " ")
	}

	return s
}
