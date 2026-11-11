package detect

import (
	"strings"

	"github.com/corazawaf/libinjection-go"

	"netsa/internal/model"
)

// 语法分析：用 libinjection 按 SQL 词法、HTML 解析复核参数取值，与正则规则相互独立。
//
// 正则只能说明“出现了某些写法”，libinjection 判断取值放进 SQL 语句或 HTML 页面后能否真正构成注入：
//   - 规则命中、语法分析也构成注入：证据中注明，误报的可能很小；
//   - 规则命中、语法分析不构成注入（如搜索“select 用法 from 入门教程”）：记为 Syntax=-1，
//     由自学习结合该参数平时的取值决定是否降级（见 learn/profile.go），单凭语法分析不降级；
//   - 规则没有命中、语法分析认定为 SQL 注入：生成 sqli-syntax 命中，覆盖正则没有写到的变形。
//     libinjection 会把“1 < 2 and 3 > 2”这类算式也认作注入，这类命中同样交给自学习按参数的正常取值复核。
//
// XSS 只复核不单独告警：libinjection 见到 <script 等标签就判为 XSS，普通文字中提到标签也会命中。

const (
	maxSyntaxParams = 32   // 每个请求最多分析的取值个数
	maxSyntaxLen    = 4096 // 超长取值只分析开头
)

// Param 是一个查询参数（或路径段，Name 为空），Value 已解码（+ 为空格、多轮百分号解码）。
type Param struct {
	Name, Value string
}

// QueryParams 拆分并解码查询参数（参数名小写），供自学习统计参数的正常取值。
func QueryParams(rawURI string) []Param { return splitParams(rawURI, false) }

// splitParams 拆分查询参数（withPath 时连同路径段）。先按原始的 & 与 = 拆分再解码，
// 取值中编码的 %26、%3D 不会把参数拆错。
func splitParams(rawURI string, withPath bool) []Param {
	ps, _ := splitParamsT(rawURI, withPath)
	return ps
}

// splitParamsT 与 splitParams 相同，另外返回是否有内容没有纳入分析（参数个数超过上限，或取值超长被截断）。
func splitParamsT(rawURI string, withPath bool) (out []Param, truncated bool) {
	path, query, _ := strings.Cut(rawURI, "?")
	if withPath {
		for _, seg := range strings.Split(path, "/") {
			if seg == "" {
				continue
			}
			if len(out) >= maxSyntaxParams || len(seg) > maxSyntaxLen {
				truncated = true
			}
			if len(out) < maxSyntaxParams {
				out = append(out, Param{Value: decodeValue(seg)})
			}
		}
	}
	for query != "" {
		var kv string
		kv, query, _ = strings.Cut(query, "&")
		k, v, _ := strings.Cut(kv, "=")
		if k == "" && v == "" {
			continue
		}
		if len(out) >= maxSyntaxParams {
			truncated = true
			break
		}
		if len(v) > maxSyntaxLen {
			truncated = true
		}
		out = append(out, Param{Name: strings.ToLower(decodeValue(k)), Value: decodeValue(v)})
	}
	return out, truncated
}

// decodeValue 按 Normalize 的方式解码单个取值，但不转小写、不去注释：libinjection 自己处理大小写与注释。
func decodeValue(s string) string {
	if len(s) > maxSyntaxLen {
		s = s[:maxSyntaxLen]
	}
	s = strings.ReplaceAll(s, "+", " ")
	for i := 0; i < 3; i++ {
		d, changed := percentDecode(s)
		if !changed {
			break
		}
		s = d
	}
	if strings.Contains(s, "\xc0") || strings.Contains(s, "\xc1") || strings.Contains(s, "\xe0\x80") {
		s = overlongUTF8.Replace(s)
	}
	return s
}

// reviewRef 指向一条需要复核的命中及其在归一化 URI 中的位置。
type reviewRef struct {
	hit, start, end int
}

// paramAt 返回归一化 URI 中 start 位置所在的查询参数名；在路径中时返回空串。
func paramAt(uri string, start int) string {
	q := strings.IndexByte(uri, '?')
	if q < 0 || start <= q {
		return ""
	}
	from := q + 1 + strings.LastIndexByte(uri[q+1:start], '&') + 1
	eq := strings.IndexByte(uri[from:start], '=')
	if eq < 0 {
		return ""
	}
	return uri[from : from+eq]
}

// paramOf 在拆分好的参数中查找包含命中文本的参数名。归一化 URI 把取值中编码的 %26 也解码了，
// paramAt 会把这类取值拆错，此时按取值内容查找。
func paramOf(ps []Param, matched string) string {
	for _, p := range ps {
		if p.Name != "" && matched != "" && strings.Contains(normValue(p.Value), matched) {
			return p.Name
		}
	}
	return ""
}

func hasParam(ps []Param, name string) bool {
	for _, p := range ps {
		if name != "" && p.Name == name {
			return true
		}
	}
	return false
}

// normValue 把取值归一成与规则匹配文本相同的形式（小写、去 SQL 注释、合并空白）。
func normValue(s string) string {
	if strings.ContainsRune(s, '&') {
		s = unescapeRefs(s)
	}
	s = strings.ToLower(s)
	if strings.Contains(s, "/*") {
		s = stripSQLComments(s)
	}
	return collapseSpace(s)
}

// sqliIn 返回第一个构成 SQL 注入的取值及其 libinjection 指纹。
func sqliIn(ps []Param, onlyMeta bool) (Param, string, bool) {
	for _, p := range ps {
		if onlyMeta && (p.Name == "" || !sqlMeta(p.Value)) {
			continue
		}
		if ok, fp := libinjection.IsSQLi(p.Value); ok && injectionFP(fp) {
			return p, fp, true
		}
	}
	return Param{}, "", false
}

// injectionFP 判断 libinjection 指纹是否含有注入的结构：字符串（引号闭合）、注释、语句分隔、逻辑运算、UNION / SELECT，
// 或数字、字符串之后的 ORDER BY / GROUP BY。只有单词加括号的指纹（T(n)o、f(n),）多半是普通文字里
// 恰好是 SQL 函数名的单词（left、quarter、while）后面跟了括号，不认定为注入。
func injectionFP(fp string) bool {
	return strings.ContainsAny(fp, "sc;&UE") || strings.Contains(fp, "B") && fp != "" && (fp[0] == '1' || fp[0] == 's')
}

func xssIn(ps []Param) bool {
	for _, p := range ps {
		if libinjection.IsXSS(p.Value) {
			return true
		}
	}
	return false
}

// sqlMeta 判断文本是否含有 SQL 注入离不开的符号（引号、括号、注释、语句分隔），没有时不必做语法分析。
func sqlMeta(s string) bool {
	return strings.ContainsAny(s, "'\"`(;#") || strings.Contains(s, "--")
}

// reviewSyntax 用语法分析复核 review 指向的命中（规则在 URI 上、可能出现在普通文字里的分类），
// 标注命中所在的参数，并补充规则漏掉的 SQL 注入。uri 为归一化后的完整 URI。
func reviewSyntax(ev *model.Event, uri, result string, hits []model.Hit, review []reviewRef) []model.Hit {
	q := strings.IndexByte(uri, '?')
	scan := q >= 0 && sqlMeta(uri[q+1:])
	if len(review) == 0 && !scan {
		return hits
	}
	ps, truncated := splitParamsT(ev.URI, len(review) > 0)
	// 没有发现注入时的结论：全部参数都分析过才是“不构成注入”（-1）；有参数因个数上限、长度上限没有分析时只能是“未分析”（0）。
	// 否则在载荷前面塞 32 个无关参数，真实的注入就会被记为“语法分析判定不构成注入”，自学习据此把它降为低危
	neg := int8(-1)
	if truncated {
		neg = 0
	}
	var sqlDone, xssDone bool
	var sqlV, xssV int8 // 每个请求只分析一次
	var sqlP Param
	var sqlFP string
	for _, r := range review {
		h := &hits[r.hit]
		if q >= 0 && r.start > q {
			if h.Param = paramAt(uri, r.start); !hasParam(ps, h.Param) {
				h.Param = paramOf(ps, uri[r.start:r.end])
			}
		}
		switch h.Category {
		case CatSQLi:
			if !sqlDone {
				sqlDone, sqlV = true, neg
				if p, fp, ok := sqliIn(ps, false); ok {
					sqlV, sqlP, sqlFP = 1, p, fp
				}
			}
			h.Syntax = sqlV
			if sqlV < 0 && h.Param != "" && !hasParam(ps, h.Param) {
				h.Syntax = 0 // 命中所在的参数没有分析到
			}
			if sqlV > 0 {
				h.Evidence += "；语法分析确认构成 SQL 注入（libinjection 指纹 " + sqlFP + "）"
			}
		case CatXSS:
			if !xssDone {
				xssDone, xssV = true, neg
				if xssIn(ps) {
					xssV = 1
				}
			}
			h.Syntax = xssV
			if xssV < 0 && h.Param != "" && !hasParam(ps, h.Param) {
				h.Syntax = 0
			}
			if xssV > 0 {
				h.Evidence += "；语法分析确认可构成 HTML / 脚本注入"
			}
		}
	}
	if !scan {
		return hits
	}
	for i := range hits {
		if hits[i].Category == CatSQLi {
			return hits // 规则已经识别出 SQL 注入
		}
	}
	// 规则没有命中的 SQL 注入：只看含有注入符号的查询参数，路径段里的算式、文件名不分析
	if !sqlDone {
		if p, fp, ok := sqliIn(ps, true); ok {
			sqlV, sqlP, sqlFP = 1, p, fp
		}
	}
	if sqlV <= 0 || sqlP.Name == "" {
		return hits
	}
	return append(hits, model.Hit{RuleID: "sqli-syntax", Name: "SQL注入（语法分析）", Category: CatSQLi, Severity: model.SevHigh,
		Phase: model.PhaseExploit, Result: result, Syntax: 1, Param: sqlP.Name,
		Evidence: "参数 " + Printable(sqlP.Name, 40) + "=" + Printable(sqlP.Value, 200) + "；语法分析确认构成 SQL 注入（libinjection 指纹 " + sqlFP + "）"})
}
