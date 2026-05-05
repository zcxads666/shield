package ddoscc

import (
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ChallengeLevel represents the strength of the challenge.
type ChallengeLevel int

const (
	ChallengeNone           ChallengeLevel = 0
	ChallengeJS             ChallengeLevel = 1
	ChallengeCaptcha        ChallengeLevel = 2
	ChallengeStrict         ChallengeLevel = 3
	ChallengeBlock          ChallengeLevel = 4
	ChallengeEnvFingerprint ChallengeLevel = 5
	ChallengePoW            ChallengeLevel = 6
)

func (l ChallengeLevel) String() string {
	switch l {
	case ChallengeNone:
		return "none"
	case ChallengeJS:
		return "js"
	case ChallengeCaptcha:
		return "captcha"
	case ChallengeStrict:
		return "strict_captcha"
	case ChallengeBlock:
		return "block"
	case ChallengeEnvFingerprint:
		return "env_fingerprint"
	case ChallengePoW:
		return "pow"
	default:
		return "unknown"
	}
}

// ChallengeState tracks a client's challenge progress.
type ChallengeState struct {
	SessionID    string
	Level        ChallengeLevel
	FailCount    int
	PassedLevels []ChallengeLevel
	CreatedAt    time.Time
	LastAttempt  time.Time
}

// ChallengeManager generates and verifies anti-bot challenges.
type ChallengeManager struct {
	mu        sync.RWMutex
	states    map[string]*ChallengeState
	secretKey []byte
	maxStates int
	// graceMap tracks per-IP last challenge pass time for grace period.
	// IPs that recently passed a challenge are exempt from re-challenge
	// to prevent infinite challenge loops during IP drift or unstable networks.
	graceMap map[string]time.Time
}

// NewChallengeManager creates a new challenge manager.
func NewChallengeManager(secretKey string, maxStates int) *ChallengeManager {
	return &ChallengeManager{
		states:    make(map[string]*ChallengeState),
		secretKey: []byte(secretKey),
		maxStates: maxStates,
		graceMap:  make(map[string]time.Time),
	}
}

// GetSession returns or creates a challenge state for the given session cookie.
func (cm *ChallengeManager) GetSession(cookie string) *ChallengeState {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if state, ok := cm.states[cookie]; ok {
		return state
	}

	if len(cm.states) >= cm.maxStates {
		cm.evictOldest()
	}

	state := &ChallengeState{
		SessionID:   cookie,
		Level:       ChallengeNone,
		CreatedAt:   time.Now(),
		LastAttempt: time.Now(),
	}
	cm.states[cookie] = state
	return state
}

// NextChallenge determines the next challenge level based on scores.
func (cm *ChallengeManager) NextChallenge(behaviorScore float64, suspicionScore float64, behaviorThreshold, blockThreshold, suspicionChallengeThreshold float64) ChallengeLevel {
	switch {
	case behaviorScore < 30:
		return ChallengePoW
	case behaviorScore < 50:
		return ChallengeEnvFingerprint
	case suspicionScore > 80:
		return ChallengeBlock
	case suspicionScore > 50:
		return ChallengePoW
	case behaviorScore < behaviorThreshold:
		return ChallengeEnvFingerprint
	default:
		return ChallengeNone
	}
}

// RecordChallengeResult updates the challenge state after a verification attempt.
func (cm *ChallengeManager) RecordChallengeResult(sessionID string, passed bool) ChallengeLevel {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	state, ok := cm.states[sessionID]
	if !ok {
		return ChallengeNone
	}

	state.LastAttempt = time.Now()

	if passed {
		state.PassedLevels = append(state.PassedLevels, state.Level)
		state.FailCount = 0
		state.Level = ChallengeNone
		return ChallengeNone
	}

	state.FailCount++
	switch state.FailCount {
	case 1:
		state.Level = ChallengePoW
	default:
		state.Level = ChallengeBlock
	}
	return state.Level
}

// RecordGracePass records that an IP successfully passed a challenge, granting
// a grace period during which re-challenges are suppressed. This prevents
// infinite challenge loops for users on unstable networks with IP drift.
func (cm *ChallengeManager) RecordGracePass(ip string) {
	cm.mu.Lock()
	cm.graceMap[ip] = time.Now()
	cm.mu.Unlock()
}

// IsInGracePeriod returns true if the IP passed a challenge recently and should
// not be re-challenged yet. This gives legitimate users on unstable networks
// (mobile IP drift, carrier-grade NAT) a window of normal access.
func (cm *ChallengeManager) IsInGracePeriod(ip string) bool {
	cm.mu.RLock()
	lastPass, ok := cm.graceMap[ip]
	cm.mu.RUnlock()
	if !ok {
		return false
	}
	return time.Since(lastPass) < challengeGracePeriod
}

// EscalateLevel raises the challenge level for repeat offenders.
func (cm *ChallengeManager) EscalateLevel(sessionID string, currentLevel ChallengeLevel) ChallengeLevel {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	state, ok := cm.states[sessionID]
	if !ok {
		return currentLevel + 1
	}

	switch currentLevel {
	case ChallengeNone:
		state.Level = ChallengeEnvFingerprint
	case ChallengeEnvFingerprint:
		state.Level = ChallengePoW
	case ChallengePoW:
		state.Level = ChallengeBlock
	default:
		state.Level = ChallengeBlock
	}
	return state.Level
}

// GenerateChallengeCookie creates a signed session cookie for challenge tracking.
func (cm *ChallengeManager) GenerateChallengeCookie(ip string) string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		log.Printf("challenge random read failed: %v", err)
		panic("crypto/rand: insufficient entropy")
	}
	sessionID := hex.EncodeToString(b)

	mac := hmac.New(sha256.New, cm.secretKey)
	mac.Write([]byte(sessionID + "|" + ip))
	sig := hex.EncodeToString(mac.Sum(nil))

	return sessionID + "." + sig
}

// VerifyChallengeCookie validates a challenge cookie's signature and returns the session ID.
func (cm *ChallengeManager) VerifyChallengeCookie(cookie, ip string) (string, bool) {
	parts := strings.SplitN(cookie, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	sessionID := parts[0]
	sig := parts[1]

	mac := hmac.New(sha256.New, cm.secretKey)
	mac.Write([]byte(sessionID + "|" + ip))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", false
	}
	return sessionID, true
}

// GenerateJSChallengeHTML returns a JS challenge page.
func (cm *ChallengeManager) GenerateJSChallengeHTML(sessionID, originalURL string) string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		log.Printf("challenge random read failed: %v", err)
		panic("crypto/rand: insufficient entropy")
	}
	challengeToken := hex.EncodeToString(b)

	mac := hmac.New(sha256.New, cm.secretKey)
	mac.Write([]byte(challengeToken + "|" + sessionID))
	expectedAnswer := hex.EncodeToString(mac.Sum(nil))[:16]

	cm.mu.Lock()
	if state, ok := cm.states[sessionID]; ok {
		state.Level = ChallengeJS
		state.LastAttempt = time.Now()
	}
	cm.mu.Unlock()

	return generateJSChallengePage(challengeToken, expectedAnswer, sessionID, originalURL)
}

// VerifyJSChallengeAnswer checks a JS challenge response.
func (cm *ChallengeManager) VerifyJSChallengeAnswer(sessionID, token, answer string) bool {
	mac := hmac.New(sha256.New, cm.secretKey)
	mac.Write([]byte(token + "|" + sessionID))
	expected := hex.EncodeToString(mac.Sum(nil))[:16]
	return hmac.Equal([]byte(answer), []byte(expected))
}

func (cm *ChallengeManager) evictOldest() {
	var oldestKey string
	var oldestTime time.Time
	for key, s := range cm.states {
		if oldestKey == "" || s.CreatedAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = s.CreatedAt
		}
	}
	if oldestKey != "" {
		delete(cm.states, oldestKey)
	}
}

// RestoreSession recreates a session state for a returning user whose valid
// cookie survived longer than the in-memory session. No virtual challenge pass
// is granted — the cookie provides elevated rate limits, not total bypass.
func (cm *ChallengeManager) RestoreSession(sessionID string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if _, ok := cm.states[sessionID]; ok {
		return
	}

	if len(cm.states) >= cm.maxStates {
		cm.evictOldest()
	}

	cm.states[sessionID] = &ChallengeState{
		SessionID:    sessionID,
		Level:        ChallengeNone,
		PassedLevels: nil,
		CreatedAt:    time.Now(),
		LastAttempt:  time.Now(),
	}
}

// Cleanup removes expired challenge states and grace period entries.
// Sessions where the user has passed at least one challenge are kept for
// a much longer TTL (cookieMaxAge) to avoid re-challenging legitimate users.
func (cm *ChallengeManager) Cleanup(maxAge time.Duration) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	shortCutoff := time.Now().Add(-maxAge)
	cookieMaxAge := 24 * time.Hour

	for key, s := range cm.states {
		if s.Level != ChallengeNone {
			continue
		}
		if len(s.PassedLevels) > 0 {
			if s.CreatedAt.Before(time.Now().Add(-cookieMaxAge)) {
				delete(cm.states, key)
			}
			continue
		}
		if s.CreatedAt.Before(shortCutoff) {
			delete(cm.states, key)
		}
	}

	// Cleanup grace period entries older than the grace window.
	graceCutoff := time.Now().Add(-challengeGracePeriod * 2)
	for ip, lastPass := range cm.graceMap {
		if lastPass.Before(graceCutoff) {
			delete(cm.graceMap, ip)
		}
	}
}

func generateJSChallengePage(token, expectedAnswer, sessionID, originalURL string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verifying...</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f5f5;color:#333}
.card{background:#fff;padding:32px 48px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);text-align:center;max-width:400px}
.spinner{width:40px;height:40px;margin:16px auto;border:4px solid #e0e0e0;border-top-color:#4285f4;border-radius:50%%;animation:s .8s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
h1{font-size:18px;margin:0}
p{font-size:13px;color:#666}
.retry{display:none;margin-top:16px;padding:10px 24px;font-size:14px;background:#4285f4;color:#fff;border:none;border-radius:4px;cursor:pointer}
.retry:hover{background:#3367d6}
.hint{display:none;font-size:12px;color:#999;margin-top:12px}
</style>
</head>
<body>
<div class="card">
<h1>Verifying your browser</h1>
<div class="spinner" id="spinner"></div>
<p id="msg">Please wait a moment...</p>
<button class="retry" id="retry" onclick="location.reload()">Retry</button>
<p class="hint" id="hint">If this page keeps appearing, your network may be unstable. Try switching to a more stable connection or waiting a moment before refreshing.</p>
</div>
<script>
(function(){
	var _t="%s", _e="%s", _s="%s", _u="%s";
	var d=Date.now(),n=navigator.userAgent||"",w=innerWidth||0;
	var raw=_t+":"+d+":"+n.length+":"+w;
	var sep=_u.indexOf("?")>=0?"&":"?";
	var redir=_u+sep+"__shield_verify="+encodeURIComponent(_e)+"&__shield_token="+encodeURIComponent(_t)+"&__shield_sid="+encodeURIComponent(_s);
	var _done=false;
	function go(){if(!_done){_done=true;window.location.href=redir}}
	setTimeout(go,800+Math.floor(Math.random()*400));
	// Show retry if redirect hasn't happened after 8 seconds (weak network)
	setTimeout(function(){
		if(!_done){
			document.getElementById("spinner").style.display="none";
			document.getElementById("msg").textContent="Verification is taking longer than expected.";
			document.getElementById("retry").style.display="inline-block";
			document.getElementById("hint").style.display="block";
		}
	},8000);
})();
</script>
</body>
</html>`, token, expectedAnswer, sessionID, originalURL)
}

// GenerateCaptchaHTML returns a math CAPTCHA page.
func (cm *ChallengeManager) GenerateCaptchaHTML(sessionID, originalURL string) string {
	a := int(rand.Int63()%20) + 1
	b := int(rand.Int63()%20) + 1
	answer := a + b

	mac := hmac.New(sha256.New, cm.secretKey)
	mac.Write([]byte(strconv.Itoa(answer) + "|" + sessionID))
	sig := hex.EncodeToString(mac.Sum(nil))[:16]

	cm.mu.Lock()
	if state, ok := cm.states[sessionID]; ok {
		state.Level = ChallengeCaptcha
		state.LastAttempt = time.Now()
	}
	cm.mu.Unlock()

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f5f5;color:#333}
.card{background:#fff;padding:32px 48px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);text-align:center;max-width:400px}
h1{font-size:18px;margin:0 0 16px}
.question{font-size:28px;font-weight:bold;margin:16px 0;color:#4285f4}
input[type=text]{font-size:18px;padding:8px 12px;width:120px;text-align:center;border:2px solid #ddd;border-radius:4px;margin:8px 0}
input[type=text]:focus{outline:none;border-color:#4285f4}
button{font-size:16px;padding:10px 32px;background:#4285f4;color:#fff;border:none;border-radius:4px;cursor:pointer;margin-top:12px}
button:hover{background:#3367d6}
.error{color:#d93025;font-size:13px;margin-top:8px;display:none}
</style>
</head>
<body>
<div class="card">
<h1>Security Check</h1>
<p>Please solve this simple math problem:</p>
<div class="question">%d + %d = ?</div>
<form id="f" method="GET" action="%s">
<input type="hidden" name="__shield_sid" value="%s">
<input type="hidden" name="__shield_sig" value="%s">
<input type="text" name="__shield_answer" placeholder="?" autocomplete="off" autofocus>
<br><button type="submit">Verify</button>
<div class="error" id="err">Incorrect answer, please try again.</div>
</form>
</div>
<script>
(function(){
	var u=new URL(window.location.href);
	if(u.searchParams.get("__shield_retry")==="1"){
		document.getElementById("err").style.display="block";
	}
})();
</script>
</body>
</html>`, a, b, originalURL, sessionID, sig)
}

// VerifyCaptchaAnswer checks a math CAPTCHA response.
func (cm *ChallengeManager) VerifyCaptchaAnswer(sessionID, answerStr, sig string) bool {
	answer, err := strconv.Atoi(answerStr)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, cm.secretKey)
	mac.Write([]byte(strconv.Itoa(answer) + "|" + sessionID))
	expected := hex.EncodeToString(mac.Sum(nil))[:16]
	return hmac.Equal([]byte(sig), []byte(expected))
}

// GenerateEnvFingerprintHTML returns a Stage 1 environment fingerprint challenge page.
// The client must compute SHA-256(verificationToken + "|" + base64(fpData)) and
// send it as __shield_verify — no pre-computed signature is embedded in the page.
func (cm *ChallengeManager) GenerateEnvFingerprintHTML(sessionID, originalURL string) string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		log.Printf("challenge random read failed: %v", err)
		panic("crypto/rand: insufficient entropy")
	}
	verificationToken := hex.EncodeToString(b)

	cm.mu.Lock()
	if state, ok := cm.states[sessionID]; ok {
		state.Level = ChallengeEnvFingerprint
		state.LastAttempt = time.Now()
	}
	cm.mu.Unlock()

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Verifying...</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f5f5;color:#333}
.card{background:#fff;padding:32px 48px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);text-align:center;max-width:420px}
.spinner{width:40px;height:40px;margin:16px auto;border:4px solid #e0e0e0;border-top-color:#4285f4;border-radius:50%%;animation:s .8s linear infinite}
@keyframes s{to{transform:rotate(360deg)}}
h1{font-size:18px;margin:0}
p{font-size:13px;color:#666}
.retry{display:none;margin-top:16px;padding:10px 24px;font-size:14px;background:#4285f4;color:#fff;border:none;border-radius:4px;cursor:pointer}
.retry:hover{background:#3367d6}
.hint{display:none;font-size:12px;color:#999;margin-top:12px}
</style>
</head>
<body>
<div class="card">
<h1>Verifying your browser</h1>
<div class="spinner" id="spinner"></div>
<p id="msg">Checking browser environment...</p>
<button class="retry" id="retry" onclick="location.reload()">Retry</button>
<p class="hint" id="hint">If this page keeps appearing, your network may be unstable. Try switching to a more stable connection or waiting a moment before refreshing.</p>
</div>
<canvas id="fp_canvas" style="display:none"></canvas>
<canvas id="fp_webgl" style="display:none"></canvas>
<script>
(function(){
	var _s="%s",_u="%s",_t="%s";

	function hash(str){
		var h=0;for(var i=0;i<str.length;i++){h=(h<<5)-h+str.charCodeAt(i);h|=0}
		return Math.abs(h).toString(16);
	}

	async function sha256hex(msg){
		var enc=new TextEncoder().encode(msg);
		var buf=await crypto.subtle.digest("SHA-256",enc);
		var arr=Array.from(new Uint8Array(buf));
		return arr.map(function(b){return b.toString(16).padStart(2,"0")}).join("");
	}

	var fp={};

	try{
		var c=document.getElementById("fp_canvas");
		c.width=280;c.height=60;
		var ctx=c.getContext("2d");
		ctx.textBaseline="top";
		ctx.font='14px "Arial"';
		ctx.fillStyle="#f60";ctx.fillRect(10,10,50,30);
		ctx.fillStyle="#069";ctx.fillRect(60,5,80,40);
		ctx.fillStyle="#000";ctx.fillText("Browser Check",5,25);
		ctx.fillStyle="#888";ctx.fillText("!@#$%%^&*()",15,45);
		ctx.strokeStyle="#f00";ctx.beginPath();ctx.moveTo(5,10);ctx.lineTo(100,5);ctx.stroke();
		fp.canvas=c.toDataURL().length+":"+hash(c.toDataURL().substring(0,200));
	}catch(e){fp.canvas="err"}

	try{
		var wc=document.getElementById("fp_webgl");
		var gl=wc.getContext("webgl")||wc.getContext("experimental-webgl");
		if(gl){
			var dbg=gl.getExtension("WEBGL_debug_renderer_info");
			if(dbg){
				fp.webgl_renderer=gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL)||"";
				fp.webgl_vendor=gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)||"";
			}
			fp.webgl_version=gl.getParameter(gl.VERSION)||"";
			fp.webgl_shading=gl.getParameter(gl.SHADING_LANGUAGE_VERSION)||"";
			fp.webgl_extensions=gl.getSupportedExtensions().slice(0,20).join(",");
		}else{fp.webgl_renderer="none"}
	}catch(e){fp.webgl_renderer="err"}

	fp.screen=screen.width+"x"+screen.height+"x"+screen.colorDepth;
	fp.pixelRatio=window.devicePixelRatio||1;
	fp.timezone=(new Date()).getTimezoneOffset();

	fp.platform=navigator.platform||"";
	fp.language=navigator.language||"";
	fp.hwConcurrency=navigator.hardwareConcurrency||0;
	fp.deviceMemory=navigator.deviceMemory||0;
	fp.maxTouchPoints=navigator.maxTouchPoints||0;
	fp.vendor=navigator.vendor||"";
	fp.productSub=navigator.productSub||"";

	fp.webdriver=!!navigator.webdriver;
	fp.chrome=!!window.chrome;
	fp.phantom=!!window.callPhantom||!!window._phantom;
	fp.selenium=!!document.__selenium_unwrapped||!!document.__webdriver_evaluate;
	fp.domAutomation=!!document.__domAutomation||!!document.__driver_unwrapped;
	fp.plugins=(navigator.plugins||[]).length;
	fp.languages=(navigator.languages||[]).join(",");

	var raw=[];
	for(var k in fp){
		if(fp.hasOwnProperty(k))raw.push(k+":"+fp[k]);
	}
	var fpStr=raw.join(";");
	var fpB64=btoa(fpStr);

	var sep=_u.indexOf("?")>=0?"&":"?";

	var _done=false;
	function doRedirect(verifyHash){
		if(_done)return;_done=true;
		var redir=_u+sep+"__shield_verify="+encodeURIComponent(verifyHash)+
			"&__shield_token="+encodeURIComponent(_t)+
			"&__shield_sid="+encodeURIComponent(_s)+
			"&__shield_fp="+encodeURIComponent(fpB64);
		var msg=document.getElementById("msg");
		msg.textContent="Environment check passed. Redirecting...";
		setTimeout(function(){window.location.href=redir},300);
	}

	var hInput=_t+"|"+fpB64;
	if(window.crypto&&window.crypto.subtle){
		sha256hex(hInput).then(doRedirect).catch(function(){
			doRedirect(hash(hInput));
		});
	}else{
		doRedirect(hash(hInput));
	}
})
	// Show retry if redirect hasn't happened after 10 seconds (weak network / slow crypto)
	setTimeout(function(){
		if(!_done){
			document.getElementById("spinner").style.display="none";
			document.getElementById("msg").textContent="Verification is taking longer than expected.";
			document.getElementById("retry").style.display="inline-block";
			document.getElementById("hint").style.display="block";
		}
	},10000);
	})();
</script>
</body>
</html>`, sessionID, originalURL, verificationToken)
}

// VerifyEnvFingerprint validates a Stage 1 environment fingerprint response.
// The client computes SHA-256(token + "|" + base64(fpData)) and sends it as __shield_verify.
// We re-compute the hash over the base64-encoded fpData (matching the client) and compare.
func (cm *ChallengeManager) VerifyEnvFingerprint(sessionID, token, fingerprintHash, fpDataB64 string) bool {
	_ = sessionID // kept for API compatibility; token binds to fpData via client hash

	// Client hashes token + "|" + base64(fpData) — match that exactly.
	expectedHash := sha256Hex(token + "|" + fpDataB64)
	if fingerprintHash != expectedHash {
		return false
	}

	// Decode base64 to get raw fpStr for fingerprint validation.
	fpDataBytes, err := base64.StdEncoding.DecodeString(fpDataB64)
	if err != nil {
		return false
	}
	fpData := string(fpDataBytes)

	fpMap := make(map[string]string)
	pairs := strings.Split(fpData, ";")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, ":", 2)
		if len(kv) == 2 {
			fpMap[kv[0]] = kv[1]
		}
	}

	if fpMap["webdriver"] == "true" || fpMap["phantom"] == "true" || fpMap["selenium"] == "true" {
		return false
	}

	score := 0
	if fpMap["webgl_renderer"] != "none" && fpMap["webgl_renderer"] != "err" && fpMap["webgl_renderer"] != "" {
		score++
	}
	if fpMap["canvas"] != "" && fpMap["canvas"] != "err" {
		score++
	}
	if fpMap["screen"] != "" {
		score++
	}
	if fpMap["plugins"] != "" {
		pluginCount := 0
		if _, err := fmt.Sscanf(fpMap["plugins"], "%d", &pluginCount); err != nil {
			pluginCount = 0
		}
		if pluginCount > 0 {
			score++
		}
	}
	if fpMap["language"] != "" {
		score++
	}
	return score >= 2
}

// GeneratePoWHTML returns a Stage 2 Proof-of-Work challenge page.
func (cm *ChallengeManager) GeneratePoWHTML(sessionID, originalURL string, difficulty int) string {
	b := make([]byte, 16)
	if _, err := crand.Read(b); err != nil {
		log.Printf("challenge random read failed: %v", err)
		panic("crypto/rand: insufficient entropy")
	}
	challengeNonce := hex.EncodeToString(b)

	cm.mu.Lock()
	if state, ok := cm.states[sessionID]; ok {
		state.Level = ChallengePoW
		state.LastAttempt = time.Now()
	}
	cm.mu.Unlock()

	prefix := strings.Repeat("0", difficulty)

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f5f5;color:#333}
.card{background:#fff;padding:32px 48px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);text-align:center;max-width:440px}
h1{font-size:18px;margin:0 0 12px}
p{font-size:13px;color:#666;margin:8px 0}
.progress{width:100%%;height:6px;background:#e0e0e0;border-radius:3px;overflow:hidden;margin:16px 0}
.progress-bar{height:100%%;background:#4285f4;border-radius:3px;transition:width .3s;width:0%%}
button{font-size:16px;padding:12px 36px;background:#4285f4;color:#fff;border:none;border-radius:4px;cursor:pointer;margin-top:12px;display:none}
button:hover{background:#3367d6}
button:disabled{background:#ccc;cursor:not-allowed}
.hash-display{font-family:monospace;font-size:11px;color:#999;word-break:break-all;margin-top:8px;max-height:60px;overflow-y:auto}
</style>
</head>
<body>
<div class="card">
<h1>Security Check</h1>
<p>Please wait while we verify your connection...</p>
<div class="progress"><div class="progress-bar" id="bar"></div></div>
<p id="status">Computing proof of work...</p>
<div class="hash-display" id="hash"></div>
<button id="btn" onclick="submitPoW()">Verify &amp; Continue</button>
<p style="font-size:12px;color:#999;margin-top:12px">If verification is taking too long, your network may be unstable. Try refreshing the page or switching to a more stable connection.</p>
</div>
<script>
(function(){
	var _s="%s",_u="%s",_nonce="%s",_diff=%d;
	var _prefix="%s";
	var _found=false,_result="",_resultNonce=0;
	var _total=Math.pow(16,_diff);

	async function sha256hex(msg){
		var enc=new TextEncoder().encode(msg);
		var buf=await crypto.subtle.digest("SHA-256",enc);
		var arr=Array.from(new Uint8Array(buf));
		return arr.map(b=>b.toString(16).padStart(2,"0")).join("");
	}

	async function doWork(){
		var batchSize=200;
		for(var n=0;n<_total;n+=batchSize){
			var end=Math.min(n+batchSize,_total);
			var tasks=[];
			for(var i=n;i<end;i++){
				(function(idx){
					tasks.push(sha256hex(_nonce+":"+idx+":"+_s).then(function(h){
						return {hash:h,nonce:idx};
					}));
				})(i);
			}
			var results=await Promise.all(tasks);
			for(var j=0;j<results.length;j++){
				if(results[j].hash.startsWith(_prefix)){
					_found=true;_result=results[j].hash;_resultNonce=results[j].nonce;
					return;
				}
			}
			var pct=Math.min(100,Math.round(end/_total*100));
			document.getElementById("bar").style.width=pct+"%%";
		}
	}

	async function startWork(){
		var _timeout=setTimeout(function(){
			if(!_found){
				document.getElementById("status").textContent="Verification timed out. Your network may be slow. Please refresh the page to try again.";
				document.getElementById("btn").style.display="inline-block";
				document.getElementById("btn").textContent="Refresh Page";
				document.getElementById("btn").onclick=function(){location.reload()};
			}
		},30000);
		doWork().then(function(){
			clearTimeout(_timeout);
			if(_found){
				document.getElementById("status").textContent="Verification complete. Click below to continue.";
				document.getElementById("bar").style.width="100%%";
				document.getElementById("hash").textContent="Hash: "+_result;
				document.getElementById("btn").style.display="inline-block";
			}else{
				document.getElementById("status").textContent="Verification failed. Please refresh.";
			}
		});
	}

	window.submitPoW=function(){
		if(!_found)return;
		var sep=_u.indexOf("?")>=0?"&":"?";
		var redir=_u+sep+"__shield_answer="+encodeURIComponent(_resultNonce)+
			"&__shield_sid="+encodeURIComponent(_s)+
			"&__shield_token="+encodeURIComponent(_nonce)+
			"&__shield_hash="+encodeURIComponent(_result);
		window.location.href=redir;
	};

	startWork();
})();
</script>
</body>
</html>`, sessionID, originalURL, challengeNonce, difficulty, prefix)
}

// VerifyPoW validates a Stage 2 Proof-of-Work response.
func (cm *ChallengeManager) VerifyPoW(sessionID, token, answerNonce, answerHash string, difficulty int) bool {
	prefix := strings.Repeat("0", difficulty)

	if !strings.HasPrefix(answerHash, prefix) {
		return false
	}

	hashInput := token + ":" + answerNonce + ":" + sessionID
	hash := sha256.Sum256([]byte(hashInput))
	computedHash := hex.EncodeToString(hash[:])

	return hmac.Equal([]byte(answerHash), []byte(computedHash))
}

// sha256Hex returns the lowercase hex encoding of SHA-256(data).
func sha256Hex(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
