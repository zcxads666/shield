package waitingroom

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// ServeWaitingPage writes the waiting room HTML page.
func (wr *WaitingRoom) ServeWaitingPage(w http.ResponseWriter, r *http.Request, sessionID, originalURL string) {
	initialPos := wr.Position(sessionID)
	html := wr.waitingPageHTML(sessionID, originalURL, initialPos)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

// SSEHandler returns a handler that streams position updates via Server-Sent Events.
func (wr *WaitingRoom) SSEHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.URL.Query().Get("session")
		if sessionID == "" {
			http.Error(w, "missing session", http.StatusBadRequest)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		ctx := r.Context()
		lastPosition := -1

		for {
			select {
			case <-ticker.C:
				pos := wr.Position(sessionID)
				if pos != lastPosition {
					lastPosition = pos
					if pos == 0 {
						if _, err := fmt.Fprintf(w, "event: release\ndata: released\n\n"); err != nil {
							return
						}
						flusher.Flush()
						return
					}
					estimated := wr.EstimatedWait(pos)
					qlen := wr.QueueLength()
					if _, err := fmt.Fprintf(w, "event: position\ndata: {\"position\":%d,\"estimated\":%d,\"queue_length\":%d}\n\n",
						pos, int(estimated.Seconds()), qlen); err != nil {
						return
					}
					flusher.Flush()
				} else {
					if _, err := fmt.Fprintf(w, ": keepalive\n\n"); err != nil {
						return
					}
					flusher.Flush()
				}
			case <-ctx.Done():
				return
			}
		}
	}
}

// StatusHandler returns queue metrics as JSON for monitoring.
func (wr *WaitingRoom) StatusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		qlen := wr.QueueLength()
		active := wr.IsActive()
		if _, err := fmt.Fprintf(w, `{"active":%v,"queue_length":%d,"release_per_sec":%.1f}`,
			active, qlen, wr.cfg.ReleasePerSec); err != nil {
			log.Printf("waitingroom status write error: %v", err)
		}
	}
}

func (wr *WaitingRoom) waitingPageHTML(sessionID, originalURL string, initialPos int) string {
	initialPosJSON := "null"
	if initialPos > 0 {
		initialPosJSON = fmt.Sprintf("%d", initialPos)
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>排队等待中</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC",sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f0f2f5;color:#333}
.card{background:#fff;padding:40px 48px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.08);text-align:center;max-width:420px;width:90%%}
.icon{width:40px;height:40px;margin:0 auto 24px}
.icon svg{width:100%%;height:100%%;color:#1a1a1a;animation:spin 1.2s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
h1{font-size:20px;font-weight:600;margin-bottom:8px;color:#1a1a1a}
.subtitle{font-size:14px;color:#666;margin-bottom:32px}
.queue-info{background:#f7f8fa;border-radius:8px;padding:24px;margin-bottom:24px}
.queue-position{font-size:42px;font-weight:700;color:#1a1a1a;line-height:1}
.queue-label{font-size:13px;color:#888;margin-top:6px}
.queue-details{display:flex;justify-content:space-around;margin-top:20px;padding-top:20px;border-top:1px solid #e8e8e8}
.detail-item{text-align:center}
.detail-value{font-size:18px;font-weight:600;color:#333}
.detail-label{font-size:12px;color:#999;margin-top:4px}
.progress-container{margin-bottom:20px}
.progress-bar{width:100%%;height:4px;background:#e8e8e8;border-radius:2px;overflow:hidden}
.progress-fill{height:100%%;background:#1a1a1a;border-radius:2px;transition:width .5s ease;width:0%%}
.status{font-size:13px;color:#666;margin-top:20px;display:flex;align-items:center;justify-content:center;gap:6px}
.status .dot{width:6px;height:6px;background:#22c55e;border-radius:50%%;animation:pulse 1.5s ease infinite}
@keyframes pulse{0%%,100%%{opacity:1}50%%{opacity:.4}}
.tips{font-size:12px;color:#aaa;margin-top:24px;line-height:1.6}
</style>
</head>
<body>
<div class="card">
<div class="icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4m0 12v4M4.93 4.93l2.83 2.83m8.48 8.48l2.83 2.83M2 12h4m12 0h4M4.93 19.07l2.83-2.83m8.48-8.48l2.83-2.83"/></svg></div>
<h1>排队等待中</h1>
<p class="subtitle">当前访问人数较多，请耐心等待</p>
<div class="queue-info">
<div class="queue-position" id="position">%d</div>
<div class="queue-label">您前面还有</div>
<div class="queue-details">
<div class="detail-item">
<div class="detail-value" id="estimated">--</div>
<div class="detail-label">预计等待(秒)</div>
</div>
<div class="detail-item">
<div class="detail-value" id="queueLen">--</div>
<div class="detail-label">队列总人数</div>
</div>
</div>
</div>
<div class="progress-container">
<div class="progress-bar"><div class="progress-fill" id="progress"></div></div>
</div>
<div class="status"><span class="dot"></span><span id="statusText">实时更新中</span></div>
<p class="tips">请勿关闭或刷新页面<br>排到您时将自动跳转</p>
</div>
<script>
(function(){
var sid="%s";
var origURL="%s";
var initPos=%s;
var maxPos=initPos||0;

var pe=document.getElementById("position");
var ee=document.getElementById("estimated");
var qe=document.getElementById("queueLen");
var pb=document.getElementById("progress");
var st=document.getElementById("statusText");

function update(p,est,qlen){
pe.textContent=p>0?p:"排到了";
ee.textContent=est;
qe.textContent=qlen;
if(qlen>0&&p>0){
var pct=Math.round((1-(p-1)/qlen)*100);
pb.style.width=Math.max(0,Math.min(100,pct))+"%%";
}
}

if(initPos>0){
maxPos=initPos;
pe.textContent=initPos;
ee.textContent=Math.ceil(initPos/5);
qe.textContent=initPos;
update(initPos,Math.ceil(initPos/5),initPos);
}

var es=new EventSource("/__shield_wait_stream?session="+encodeURIComponent(sid));

es.addEventListener("position",function(e){
try{var d=JSON.parse(e.data)}catch(ex){return}
if(d.position>maxPos)maxPos=d.position;
update(d.position,d.estimated,d.queue_length);
});

es.addEventListener("release",function(e){
st.textContent="排到了，正在跳转...";
setTimeout(function(){
window.location.href=origURL+"?__shield_wr_release=1";
},500);
});

es.onerror=function(){
st.textContent="连接中断，正在重连...";
setTimeout(function(){window.location.reload()},3000);
};

window.addEventListener("beforeunload",function(){
es.close();
});
})();
</script>
</body>
</html>`, initialPos, sessionID, originalURL, initialPosJSON)
}
