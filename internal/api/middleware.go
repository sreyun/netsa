package api

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------------- 响应缓存 ----------------

// respCache 对聚合类只读接口做短时缓存：多个大屏同时刷新时只计算一次，避免重复遍历全部画像并占用状态库读锁。
// 同一个键的并发请求只有一个会真正计算，其余等待其结果（防止缓存击穿）。
type respCache struct {
	mu      sync.Mutex
	entries map[string]*cacheEntry
}

type cacheEntry struct {
	mu      sync.Mutex
	body    []byte
	ctype   string
	expires time.Time
}

func newRespCache() *respCache { return &respCache{entries: map[string]*cacheEntry{}} }

type captureWriter struct {
	header http.Header
	buf    bytes.Buffer
	code   int
}

func (c *captureWriter) Header() http.Header         { return c.header }
func (c *captureWriter) Write(b []byte) (int, error) { return c.buf.Write(b) }
func (c *captureWriter) WriteHeader(code int)        { c.code = code }

// wrap 返回带缓存的处理器；只缓存 200 响应。
func (rc *respCache) wrap(ttl time.Duration, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path + "?" + r.URL.RawQuery
		rc.mu.Lock()
		e := rc.entries[key]
		if e == nil {
			if len(rc.entries) > 1024 { // 查询参数组合过多时整体清空，防止内存增长
				rc.entries = map[string]*cacheEntry{}
			}
			e = &cacheEntry{}
			rc.entries[key] = e
		}
		rc.mu.Unlock()

		e.mu.Lock()
		if time.Now().After(e.expires) {
			cw := &captureWriter{header: http.Header{}, code: http.StatusOK}
			h(cw, r)
			if cw.code != http.StatusOK {
				e.mu.Unlock()
				for k, v := range cw.header {
					w.Header()[k] = v
				}
				w.WriteHeader(cw.code)
				w.Write(cw.buf.Bytes())
				return
			}
			e.body, e.ctype, e.expires = cw.buf.Bytes(), cw.header.Get("Content-Type"), time.Now().Add(ttl)
		}
		body, ctype := e.body, e.ctype
		e.mu.Unlock()
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", "no-store")
		w.Write(body)
	}
}

// ---------------- gzip 压缩 ----------------

var gzPool = sync.Pool{New: func() any {
	w, _ := gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
	return w
}}

type gzipWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	wroteHeader bool
	compress    bool // 304/204 等无响应体的状态不压缩
}

func (g *gzipWriter) WriteHeader(code int) {
	if !g.wroteHeader {
		g.wroteHeader = true
		g.compress = code >= 200 && code != http.StatusNoContent && code != http.StatusNotModified
		if g.compress {
			g.Header().Del("Content-Length")
			g.Header().Set("Content-Encoding", "gzip")
		}
	}
	g.ResponseWriter.WriteHeader(code)
}

// Unwrap 返回底层的 ResponseWriter，供 http.ResponseController 调整连接期限、刷新缓冲。
func (g *gzipWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

func (g *gzipWriter) Write(b []byte) (int, error) {
	if !g.wroteHeader {
		g.WriteHeader(http.StatusOK)
	}
	if !g.compress {
		return g.ResponseWriter.Write(b)
	}
	return g.gz.Write(b)
}

// gzipHandler 压缩 JSON 与静态资源（ECharts、地图数据压缩后约为原来的 1/3~1/5），SSE 与分段请求除外。
func gzipHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/stream" {
			w.Header().Add("Vary", "Accept-Encoding") // 无论是否压缩都声明，避免共享缓存把未压缩版本发给所有客户端
		}
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") || r.Header.Get("Range") != "" ||
			r.URL.Path == "/api/stream" || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		gz := gzPool.Get().(*gzip.Writer)
		gz.Reset(w)
		gw := &gzipWriter{ResponseWriter: w, gz: gz}
		defer func() {
			if gw.compress {
				gz.Close()
			}
			gzPool.Put(gz)
		}()
		next.ServeHTTP(gw, r)
	})
}
