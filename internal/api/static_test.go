package api

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// 静态文件：按内容给出 ETag、没有变化时返回 304，预压缩结果只压缩一次且外层不再重复压缩。
func TestStaticFiles(t *testing.T) {
	js := strings.Repeat("console.log('netsa');\n", 200)
	fsys := fstest.MapFS{
		"index.html":            {Data: []byte("<!doctype html><title>netsa</title>" + strings.Repeat("<p>x</p>", 200))},
		"app.js":                {Data: []byte(js)},
		"vendor/echarts.min.js": {Data: []byte(js)},
		"vendor/china/a.json":   {Data: []byte(`{"a":1}`)},
	}
	h := gzipHandler(newStaticFiles(fsys))
	get := func(url string, hdr map[string]string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", url, nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}

	w := get("/app.js", nil)
	etag := w.Header().Get("ETag")
	if w.Code != 200 || etag == "" || w.Body.String() != js || !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("普通请求: %d etag=%q type=%q", w.Code, etag, w.Header().Get("Content-Type"))
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Fatalf("页面脚本每次确认: %q", cc)
	}
	if w := get("/app.js", map[string]string{"If-None-Match": etag}); w.Code != http.StatusNotModified || w.Body.Len() != 0 {
		t.Fatalf("没有变化应返回 304: %d", w.Code)
	}
	if w := get("/app.js", map[string]string{"If-None-Match": `W/"other", ` + etag}); w.Code != http.StatusNotModified {
		t.Fatal("多个 ETag 中包含当前值也应返回 304")
	}

	w = get("/app.js", map[string]string{"Accept-Encoding": "gzip, br"})
	if w.Header().Get("Content-Encoding") != "gzip" || w.Body.Len() >= len(js) {
		t.Fatalf("应返回预压缩结果: enc=%q len=%d", w.Header().Get("Content-Encoding"), w.Body.Len())
	}
	zr, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatal("外层不应重复压缩：", err)
	}
	plain, _ := io.ReadAll(zr)
	if string(plain) != js {
		t.Fatal("解压后内容不一致")
	}

	if w := get("/", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "<title>netsa</title>") || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("首页: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if cc := get("/vendor/echarts.min.js", nil).Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=604800") {
		t.Fatalf("第三方库可缓存: %q", cc)
	}
	if w := get("/vendor/china/a.json", nil); w.Body.String() != `{"a":1}` {
		t.Fatalf("小文件不预压缩，原样返回: %q", w.Body.String())
	}
	if w := get("/missing.js", nil); w.Code != http.StatusNotFound {
		t.Fatalf("不存在的文件: %d", w.Code)
	}
	r := httptest.NewRequest("HEAD", "/app.js", nil)
	hw := httptest.NewRecorder()
	h.ServeHTTP(hw, r)
	if hw.Code != 200 || hw.Body.Len() != 0 || hw.Header().Get("Content-Length") == "" {
		t.Fatalf("HEAD: %d len=%d", hw.Code, hw.Body.Len())
	}

	// 文件变化后（-web 目录）重新读取，ETag 随之变化
	fsys["app.js"] = &fstest.MapFile{Data: []byte(js + "// v2\n")}
	if w := get("/app.js", map[string]string{"If-None-Match": etag}); w.Code != 200 || w.Header().Get("ETag") == etag {
		t.Fatalf("内容变化后应返回新内容: %d", w.Code)
	}
}
