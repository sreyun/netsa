package api

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 前端静态文件：内容、ETag 与 gzip 压缩结果缓存在内存中。
//
//   - 内嵌文件没有修改时间，http.FileServer 不给 Last-Modified，页面又是 no-cache：每次打开都要重新下载
//     app.js、ops.js、样式和页面（约 430KB），现在按内容哈希给出 ETag，没有变化时返回 304；
//   - 每次请求都要重新压缩（ECharts、世界地图各约 1MB），现在只压缩一次；
//   - 使用 -web 目录（开发调试）时按修改时间与大小判断文件是否变化，变化后重新读取。
//
// 范围请求、目录与不存在的文件交给 http.FileServer 处理。
type staticFiles struct {
	fsys     fs.FS
	fallback http.Handler
	mu       sync.Mutex
	cache    map[string]*staticEntry
}

type staticEntry struct {
	raw, gz []byte
	etag    string
	ctype   string
	mod     time.Time
	size    int64
}

func newStaticFiles(fsys fs.FS) *staticFiles {
	return &staticFiles{fsys: fsys, fallback: http.FileServer(http.FS(fsys)), cache: map[string]*staticEntry{}}
}

// compressible 判断是否值得压缩（文本类资源）。
func compressible(ctype string) bool {
	return strings.HasPrefix(ctype, "text/") || strings.Contains(ctype, "javascript") || strings.Contains(ctype, "json") ||
		strings.Contains(ctype, "svg") || strings.Contains(ctype, "xml")
}

// load 返回文件的缓存条目；文件不存在、是目录或读取失败时返回 nil（交给 FileServer）。
func (sf *staticFiles) load(name string) *staticEntry {
	fi, err := fs.Stat(sf.fsys, name)
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	sf.mu.Lock()
	e := sf.cache[name]
	sf.mu.Unlock()
	if e != nil && e.mod.Equal(fi.ModTime()) && e.size == fi.Size() {
		return e
	}
	raw, err := fs.ReadFile(sf.fsys, name)
	if err != nil {
		return nil
	}
	sum := sha256.Sum256(raw)
	e = &staticEntry{raw: raw, etag: `"` + hex.EncodeToString(sum[:12]) + `"`, mod: fi.ModTime(), size: fi.Size()}
	e.ctype = mime.TypeByExtension(path.Ext(name))
	if e.ctype == "" {
		e.ctype = http.DetectContentType(raw)
	}
	if compressible(e.ctype) && len(raw) > 512 {
		var b bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&b, gzip.BestCompression) // 只压缩一次，用最高压缩率
		zw.Write(raw)
		zw.Close()
		if b.Len() < len(raw) {
			e.gz = b.Bytes()
		}
	}
	sf.mu.Lock()
	sf.cache[name] = e
	sf.mu.Unlock()
	return e
}

func (sf *staticFiles) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 第三方库与地图数据很少变化，可缓存一周；页面与脚本每次用 ETag 确认（升级后立即生效）
	if strings.HasPrefix(r.URL.Path, "/vendor/") {
		w.Header().Set("Cache-Control", "public, max-age=604800")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" {
		name = "index.html"
	}
	var e *staticEntry
	if r.Header.Get("Range") == "" && name != "." && !strings.HasSuffix(r.URL.Path, "/index.html") {
		e = sf.load(name)
	}
	if e == nil {
		sf.fallback.ServeHTTP(w, r)
		return
	}
	h := w.Header()
	h.Set("ETag", e.etag)
	if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatch(inm, e.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Type", e.ctype)
	body := e.raw
	if e.gz != nil && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		h.Set("Content-Encoding", "gzip") // 外层 gzipHandler 见到已压缩的响应不再压缩
		body = e.gz
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodHead {
		return
	}
	w.Write(body)
}

// etagMatch 判断 If-None-Match 是否包含该 ETag（支持逗号分隔的多个值与 W/ 前缀）。
func etagMatch(header, etag string) bool {
	for _, v := range strings.Split(header, ",") {
		v = strings.TrimPrefix(strings.TrimSpace(v), "W/")
		if v == etag || v == "*" {
			return true
		}
	}
	return false
}
