package api

import (
	"bytes"
	"compress/gzip"
	"container/list"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ---------------- 响应缓存 ----------------

// respCache 对聚合类只读接口做短时缓存：多个大屏同时刷新时只计算一次，避免重复遍历全部画像并占用状态库读锁。
// 同一个键的并发请求只有一个会真正计算，其余等待其结果（防止缓存击穿）。
//
// 容量用 LRU 控制：命中即前移，超限淘汰最久未使用的键。此前是「超过 1024 个键整体清空」，
// 带查询参数的接口（不同筛选条件、分页）很容易把键数推高，周期性地把缓存全部丢光，
// 大屏刷新会出现规律性的卡顿尖峰；LRU 只淘汰冷键，热键始终保留。
type respCache struct {
	mu    sync.Mutex
	order *list.List               // 队首为最近使用
	items map[string]*list.Element // 键 → 链表节点
	max   int
	hits  atomic.Int64
	miss  atomic.Int64
}

type cacheEntry struct {
	key     string
	mu      sync.Mutex
	body    []byte
	ctype   string
	expires time.Time
}

func newRespCache() *respCache {
	return &respCache{order: list.New(), items: map[string]*list.Element{}, max: 1024}
}

// entry 返回键对应的缓存条目（不存在则新建并淘汰最久未使用的键）。
func (rc *respCache) entry(key string) *cacheEntry {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if el, ok := rc.items[key]; ok {
		rc.order.MoveToFront(el)
		return el.Value.(*cacheEntry)
	}
	e := &cacheEntry{key: key}
	rc.items[key] = rc.order.PushFront(e)
	for rc.order.Len() > rc.max {
		back := rc.order.Back()
		if back == nil {
			break
		}
		rc.order.Remove(back)
		delete(rc.items, back.Value.(*cacheEntry).key)
	}
	return e
}

// stats 返回当前条目数与命中 / 未命中次数（未命中即重新计算）。
func (rc *respCache) stats() (entries int, hits, misses int64) {
	rc.mu.Lock()
	entries = rc.order.Len()
	rc.mu.Unlock()
	return entries, rc.hits.Load(), rc.miss.Load()
}

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
		e := rc.entry(r.URL.Path + "?" + r.URL.RawQuery)
		body, ctype, failed := rc.load(e, ttl, h, r)
		if failed != nil { // 非 200 响应原样返回，不缓存
			for k, v := range failed.header {
				w.Header()[k] = v
			}
			w.WriteHeader(failed.code)
			w.Write(failed.buf.Bytes())
			return
		}
		w.Header().Set("Content-Type", ctype)
		w.Header().Set("Cache-Control", "no-store")
		w.Write(body)
	}
}

// load 返回条目的缓存内容，过期时调用处理器重新计算（同一个键只有一个请求在计算，其余等待）。
// 用 defer 释放条目锁：处理器 panic 时 net/http 只结束该请求，锁若不释放，之后这个键的请求会全部永久挂起。
func (rc *respCache) load(e *cacheEntry, ttl time.Duration, h http.HandlerFunc, r *http.Request) (body []byte, ctype string, failed *captureWriter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !time.Now().After(e.expires) {
		rc.hits.Add(1)
		return e.body, e.ctype, nil
	}
	rc.miss.Add(1)
	cw := &captureWriter{header: http.Header{}, code: http.StatusOK}
	h(cw, r)
	if cw.code != http.StatusOK {
		return nil, "", cw
	}
	e.body, e.ctype, e.expires = cw.buf.Bytes(), cw.header.Get("Content-Type"), time.Now().Add(ttl)
	return e.body, e.ctype, nil
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
		// 已经压缩好的响应（静态文件的预压缩结果）原样输出
		g.compress = code >= 200 && code != http.StatusNoContent && code != http.StatusNotModified && g.Header().Get("Content-Encoding") == ""
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
