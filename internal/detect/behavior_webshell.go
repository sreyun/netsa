package detect

import (
	"fmt"
	"path"
	"strings"
	"time"

	"netsa/internal/model"
)

// WebShell 行为画像（bhv-webshell）：不依赖文件名、参数名等特征（攻击者可以随意改名），按访问行为识别。
//   - 新出现的脚本：站点已观察 24 小时以上，这个动态脚本此前从未被访问过；
//   - 只被极少的来源访问（不超过 2 个；被更多来源访问的是正常页面，不再跟踪）；
//   - 以 POST 为主（80% 以上），至少 5 次；
//   - 响应大小（或请求大小）随请求变化：执行不同命令、浏览不同目录，输出各不相同；
//   - 与此前的上传关联：同一站点 24 小时内出现过上传请求（路径含 upload / file，或请求体较大的 POST），
//     同一来源上传后访问的，按有证据处理。
// 只凭行为判断有误报的可能（新上线的后台页面只有管理员在用），没有上传关联时按高危提示核实。
// 已知的脚本一直保留（达到上限后不再跟踪新脚本）：清理后再出现会被当成新脚本。行为统计不持久化，重启后重新观察 24 小时。

const (
	maxScripts     = 50000
	maxShellSites  = 5000
	maxUploads     = 16
	shellSiteAge   = 24 * time.Hour // 站点观察多久之后，新出现的脚本才算“新”
	shellMinReqs   = 5
	shellMaxSrcs   = 2
	uploadWindow   = 24 * time.Hour
	uploadBodySize = 64 << 10 // 请求体较大的 POST 视为上传（日志记录了 $request_length 时）
)

// scriptExt 是会被服务端执行的脚本扩展名。
var scriptExt = map[string]bool{".php": true, ".php3": true, ".php4": true, ".php5": true, ".phtml": true, ".pht": true,
	".jsp": true, ".jspx": true, ".jspf": true, ".asp": true, ".aspx": true, ".ashx": true, ".asmx": true, ".asa": true, ".cer": true,
	".cfm": true, ".cgi": true, ".pl": true}

type scriptStat struct {
	first, last time.Time
	srcs        [shellMaxSrcs]string
	reqs, posts int
	sizes       map[int64]struct{} // 不同的响应大小（最多 8 个）
	reqSizes    map[int64]struct{} // 不同的请求大小（日志记录了 $request_length 时）
	popular     bool               // 被多个来源访问的正常页面
	fresh       bool               // 首次出现时站点已观察足够久
	fired       bool
}

type uploadMark struct {
	src, path string
	size      int64
	at        time.Time
}

type shellSite struct {
	first   time.Time
	uploads []uploadMark
}

// observeWebShell 按访问行为识别 WebShell（调用方持锁）。
func (b *Behavior) observeWebShell(ev *model.Event) (model.Hit, bool) {
	host := ev.Host
	if host == "" {
		host = "-"
	}
	site := b.shellSites[host]
	if site == nil {
		if len(b.shellSites) >= maxShellSites {
			return model.Hit{}, false
		}
		site = &shellSite{first: ev.Time}
		b.shellSites[host] = site
	}
	if ev.Time.Before(site.first) {
		site.first = ev.Time
	}
	p := ev.URI
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	lp := strings.ToLower(p)
	post := ev.Method == "POST" || ev.Method == "PUT"
	ok2xx := ev.Status >= 200 && ev.Status < 300
	if post && ok2xx && (strings.Contains(lp, "upload") || strings.Contains(lp, "file") || strings.Contains(lp, "attach") ||
		ev.ReqLength >= uploadBodySize || ev.Method == "PUT") {
		site.noteUpload(uploadMark{src: ev.SrcIP, path: Printable(p, 120), size: ev.ReqLength, at: ev.Time})
	}
	// 兜底页面（对不存在的路径返回首页的站点）上的随机脚本路径不是真实存在的脚本，不跟踪
	if !ok2xx || !scriptExt[path.Ext(lp)] || b.softMiss(ev, host, p) {
		return model.Hit{}, false
	}
	key := host + " " + p
	st := b.scripts[key]
	if st == nil {
		if len(b.scripts) >= maxScripts {
			return model.Hit{}, false
		}
		st = &scriptStat{first: ev.Time, fresh: ev.Time.Sub(site.first) >= shellSiteAge}
		b.scripts[key] = st
	}
	if st.popular || st.fired {
		return model.Hit{}, false
	}
	if !st.addSource(ev.SrcIP) {
		st.popular, st.sizes, st.reqSizes = true, nil, nil // 正常页面：不再跟踪
		return model.Hit{}, false
	}
	st.last = ev.Time
	st.reqs++
	if post {
		st.posts++
	}
	addSize(&st.sizes, ev.Bytes)
	if ev.ReqLength > 0 {
		addSize(&st.reqSizes, ev.ReqLength)
	}
	if !st.fresh || st.reqs < shellMinReqs || st.posts*10 < st.reqs*8 || len(st.sizes) < 3 && len(st.reqSizes) < 3 {
		return model.Hit{}, false
	}
	st.fired = true
	h := model.Hit{RuleID: "bhv-webshell", Name: "疑似 WebShell 交互（新脚本只被个别来源以 POST 访问）", Category: CatWebShell,
		Severity: model.SevHigh, Phase: model.PhasePersistence, Result: model.ResultSuccess}
	srcs := st.srcs[0]
	if st.srcs[1] != "" {
		srcs += "、" + st.srcs[1]
	}
	h.Evidence = fmt.Sprintf("%s 首次出现于 %s（站点此前已观察 %s），只被 %s 访问 %d 次，其中 POST %d 次，响应大小有 %d 种",
		Printable(p, 120), st.first.Format("01-02 15:04"), fmtDur(st.first.Sub(site.first).Round(time.Hour)), srcs, st.reqs, st.posts, len(st.sizes))
	if len(st.reqSizes) >= 3 {
		h.Evidence += fmt.Sprintf("、请求大小有 %d 种", len(st.reqSizes))
	}
	if up, same := site.uploadBefore(st.first, ev.SrcIP, Printable(p, 120)); up != nil {
		h.Evidence += fmt.Sprintf("；此前 %s %s 向 %s 上传过文件", fmtDur(st.first.Sub(up.at).Round(time.Second)), up.src, up.path)
		if up.size > 0 {
			h.Evidence += "（请求 " + fmtBytes(up.size) + "）"
		}
		if same {
			h.Proven = true // 同一来源上传后访问新脚本：上传与交互两份证据
			h.Evidence += "，上传者就是访问者"
		}
	} else {
		h.Evidence += "；没有发现此前的上传，请核实是否为新上线的页面"
	}
	return h, true
}

// addSource 记录访问来源，超过 shellMaxSrcs 个时返回 false。
func (st *scriptStat) addSource(ip string) bool {
	for i, s := range st.srcs {
		switch s {
		case ip:
			return true
		case "":
			st.srcs[i] = ip
			return true
		}
	}
	return false
}

func addSize(m *map[int64]struct{}, n int64) {
	if *m == nil {
		*m = map[int64]struct{}{}
	}
	if len(*m) < 8 {
		(*m)[n] = struct{}{}
	}
}

func (s *shellSite) noteUpload(u uploadMark) {
	if len(s.uploads) >= maxUploads {
		s.uploads = append(s.uploads[:0], s.uploads[1:]...)
	}
	s.uploads = append(s.uploads, u)
}

// uploadBefore 返回脚本首次出现之前 24 小时内的上传，优先同一来源。脚本自身的请求不算它的上传证据：
// 新脚本的第一次 POST 若路径含 upload / file、或请求体较大，也会被记为一次上传，时间正好等于首次出现，
// 不排除的话管理员使用新上线的后台页面就会被判为“同一来源上传后访问”，定为严重并自动确认为攻击源。
// 同一秒内的真实上传 + 访问仍然关联（访问日志只有秒级精度），所以按路径排除而不是按时间。
func (s *shellSite) uploadBefore(first time.Time, src, script string) (*uploadMark, bool) {
	var any *uploadMark
	for i := len(s.uploads) - 1; i >= 0; i-- {
		u := &s.uploads[i]
		if u.at.After(first) || first.Sub(u.at) > uploadWindow || u.path == script {
			continue
		}
		if u.src == src {
			return u, true
		}
		if any == nil {
			any = u
		}
	}
	return any, false
}
