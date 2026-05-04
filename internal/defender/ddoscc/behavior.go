package ddoscc

import (
	"net/http"
	"strings"
)

// BehaviorFingerprint captures request characteristics that distinguish
// real browsers from automated attack tools.
type BehaviorFingerprint struct {
	HasCookie        bool
	HasSession       bool
	CookieValid      bool
	HasReferer       bool
	RefererNatural   bool
	AcceptEncoding   bool
	AcceptLanguage   bool
	HeaderEntropy    float64
	TimingRandomness float64
	PathDiversity    float64
}

// ExtractBehaviorFingerprint builds a behavior fingerprint from an HTTP request.
func ExtractBehaviorFingerprint(r *http.Request) *BehaviorFingerprint {
	bf := &BehaviorFingerprint{}

	cookies := r.Cookies()
	bf.HasCookie = len(cookies) > 0

	for _, c := range cookies {
		name := strings.ToLower(c.Name)
		if strings.HasPrefix(name, "session") ||
			strings.HasPrefix(name, "sess") ||
			strings.Contains(name, "sessionid") ||
			strings.Contains(name, "sessid") {
			bf.HasSession = true
			break
		}
	}
	bf.CookieValid = bf.HasCookie

	referer := r.Header.Get("Referer")
	bf.HasReferer = referer != ""
	if bf.HasReferer {
		host := r.Host
		if host == "" {
			host = r.URL.Host
		}
		if strings.Contains(referer, host) || strings.HasPrefix(referer, "/") {
			bf.RefererNatural = true
		}
	}

	bf.AcceptEncoding = r.Header.Get("Accept-Encoding") != ""
	bf.AcceptLanguage = r.Header.Get("Accept-Language") != ""
	bf.HeaderEntropy = calcHeaderEntropy(r)

	return bf
}

// Score returns a 0–100 score where higher means more likely human.
func (bf *BehaviorFingerprint) Score() float64 {
	score := 100.0

	if !bf.HasCookie {
		score -= 5
	}
	if !bf.HasSession {
		score -= 5
	}
	if !bf.RefererNatural {
		score -= 5
	}
	if !bf.HasReferer {
		score -= 3
	}
	if !bf.AcceptEncoding {
		score -= 10
	}
	if !bf.AcceptLanguage {
		score -= 5
	}
	if bf.HeaderEntropy < 2.0 {
		score -= 30
	}

	if score < 0 {
		score = 0
	}
	return score
}

func calcHeaderEntropy(r *http.Request) float64 {
	interesting := []string{
		"User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
		"Referer", "Cookie", "Connection", "Cache-Control",
	}
	present := 0
	for _, h := range interesting {
		if r.Header.Get(h) != "" {
			present++
		}
	}
	if present == 0 {
		return 0
	}
	return float64(present) / float64(len(interesting)) * 4.0
}
