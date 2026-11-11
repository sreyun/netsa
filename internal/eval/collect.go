package eval

import (
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"netsa/internal/detect"
	"netsa/internal/model"
)

// 现场语料：从真实的 Web 日志中挑选有代表性的请求、脱敏，并用当前版本的检测结果作为标注与期望等级，
// 生成与 corpus/web.tsv 同格式的样本文件。之后每个版本用 netsa eval -corpus 跑一遍，不符合期望的样本
// 就是这次规则或定级改动带来的变化（新增的告警、消失的告警、等级变化）。
//
// 标注来自生成时的检测结果，不是人工结论：作为准确率依据之前，需要分析员复核并改正标注（benign / attack）。
// 脱敏后的请求仍要能触发同样的检测，所以只替换不影响攻击写法的内容：内网地址换成固定网段内的地址
// （回环、链路本地、云元数据地址保留）、指定的域名与网段换成文档用的地址、口令与令牌类参数的值、邮箱、
// 手机号、身份证号、JWT。参数值本身带攻击写法时保留原样。

// CollectOptions 是挑选样本的参数。
type CollectOptions struct {
	MaxCases int      // 样本总数上限（默认 5000），其中攻击样本最多占六成
	PerShape int      // 同一请求形态最多保留的条数（默认 3）
	Hide     []string // 需要替换的本单位域名（后缀）与网段（CIDR），如 example.org、43.242.97.0/24
}

// Collector 逐条接收日志事件并挑选样本（流式处理，只保留选中的请求）。
type Collector struct {
	opt     CollectOptions
	eng     *detect.Engine
	anon    *Anonymizer
	shapes  map[string]int
	cases   []Case
	attacks int
	Seen    int // 收到的 Web 请求数
	Hits    int // 其中命中攻击规则的请求数
}

// NewCollector 创建样本挑选器。
func NewCollector(opt CollectOptions) (*Collector, error) {
	if opt.MaxCases <= 0 {
		opt.MaxCases = 5000
	}
	if opt.PerShape <= 0 {
		opt.PerShape = 3
	}
	eng, err := detect.NewEngine("", 1)
	if err != nil {
		return nil, err
	}
	anon, err := NewAnonymizer(opt.Hide)
	if err != nil {
		return nil, err
	}
	return &Collector{opt: opt, eng: eng, anon: anon, shapes: map[string]int{}}, nil
}

// Add 接收一条事件：只看带请求路径的 Web 日志。攻击按（规则、请求形态）、正常请求按请求形态各保留几条，
// 这样大量重复的业务请求与同一扫描器的重复载荷不会占满样本。
func (c *Collector) Add(ev *model.Event) {
	if ev == nil || ev.Kind != model.KindWeb || ev.URI == "" || ev.Method == "" {
		return
	}
	c.Seen++
	top := ""
	var topSev model.Severity
	for _, h := range c.eng.Inspect(ev) {
		if !h.TagOnly && h.Severity >= model.SevLow && (top == "" || h.Severity > topSev) {
			top, topSev = h.RuleID, h.Severity
		}
	}
	if top != "" {
		c.Hits++
	}
	maxAttacks := c.opt.MaxCases * 6 / 10
	switch {
	case len(c.cases) >= c.opt.MaxCases:
		return
	case top != "" && c.attacks >= maxAttacks:
		return
	case top == "" && len(c.cases)-c.attacks >= c.opt.MaxCases-maxAttacks:
		return
	}
	key := "B|" + requestShape(ev)
	if top != "" {
		key = "A|" + top + "|" + requestShape(ev)
	}
	if c.shapes[key] >= c.opt.PerShape {
		return
	}
	c.shapes[key]++
	if top != "" {
		c.attacks++
	}
	c.cases = append(c.cases, Case{Label: "benign", Group: "real", Site: "app", Method: clean(ev.Method, 16), Status: ev.Status, Bytes: max(ev.Bytes, 0),
		Expect: "-", URI: clean(c.anon.URI(ev.URI), 4096), UA: clean(c.anon.Text(ev.UA), 512)})
}

// Finish 用评测流水线重新检测选中的样本，把结果写成标注与期望等级（与 netsa eval 的运行环境一致）。
func (c *Collector) Finish() ([]Case, *Report, error) {
	cases := append([]Case(nil), c.cases...)
	for i := range cases {
		if cases[i].UA == "" {
			cases[i].UA = "-"
		}
	}
	rep, err := Run(cases)
	if err != nil {
		return nil, nil, err
	}
	for i, r := range rep.Results {
		if r.Alerted && r.Severity >= model.SevLow {
			cases[i].Label, cases[i].Group = "attack", r.Rule
			cases[i].Expect = "=" + sevName(r.Severity)
		} else {
			cases[i].Expect = "none"
			if r.Alerted {
				cases[i].Expect = "<=" + sevName(r.Severity)
			}
		}
	}
	rep, err = Run(cases) // 按写入的期望重新评测一遍：生成的语料自身必须全部符合
	return cases, rep, err
}

func sevName(s model.Severity) string {
	for k, v := range sevNames {
		if v == s {
			return k
		}
	}
	return "info"
}

// WriteCorpus 写出样本文件（格式见 corpus/web.tsv）。
func WriteCorpus(w io.Writer, cases []Case, source string, seen, hits int) error {
	fmt.Fprintf(w, "# 由 netsa corpus 从现场日志生成：%s，%s\n", clean(source, 300), time.Now().Format("2006-01-02 15:04"))
	fmt.Fprintf(w, "# 共读取 %d 条 Web 请求，其中 %d 条命中攻击规则；按请求形态挑选 %d 条样本，已脱敏\n", seen, hits, len(cases))
	fmt.Fprintln(w, "# 标注与期望等级是生成时的检测结果，不是人工结论：作为准确率依据前请复核并改正第一列（benign / attack）")
	fmt.Fprintln(w, "# 列（Tab 分隔）：标注 分组 站点 方法 状态码 响应大小 期望等级 URI [UA]")
	for _, c := range cases {
		line := strings.Join([]string{c.Label, clean(c.Group, 64), c.Site, c.Method, strconv.Itoa(c.Status), strconv.FormatInt(c.Bytes, 10), c.Expect, c.URI, c.UA}, "\t")
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}

// clean 去掉制表符与换行（样本文件按行、按 Tab 分列），并按字节截断。
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "")
	}
	return s
}

var (
	reDigits = regexp.MustCompile(`^\d+$`)
	reLongID = regexp.MustCompile(`^[0-9A-Za-z_\-=]{16,}$`)
)

// requestShape 返回请求的形态：方法、状态码类别、路径（数字与长 ID 段归一）与参数名。
func requestShape(ev *model.Event) string {
	path, query, _ := strings.Cut(ev.URI, "?")
	segs := strings.Split(strings.ToLower(path), "/")
	for i, s := range segs {
		switch {
		case reDigits.MatchString(s):
			segs[i] = "{n}"
		case reLongID.MatchString(s):
			segs[i] = "{id}"
		case len(s) > 64:
			segs[i] = s[:64]
		}
	}
	var names []string
	for _, kv := range strings.Split(query, "&") {
		if k, _, _ := strings.Cut(kv, "="); k != "" && len(names) < 32 {
			names = append(names, strings.ToLower(k))
		}
	}
	sort.Strings(names)
	return ev.Method + " " + strconv.Itoa(ev.Status/100) + "xx " + strings.Join(segs, "/") + "?" + strings.Join(names, ",")
}

// Anonymizer 对样本做一致的脱敏：同一内网地址在整个语料中替换为同一个地址，攻击写法保持可检测。
type Anonymizer struct {
	domains []string
	nets    []netip.Prefix
	ips     map[string]string
	pub     map[string]string
}

// NewAnonymizer 创建脱敏器。hide 中的每一项是域名（后缀匹配）或 CIDR 网段。
func NewAnonymizer(hide []string) (*Anonymizer, error) {
	a := &Anonymizer{ips: map[string]string{}, pub: map[string]string{}}
	for _, h := range hide {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if strings.Contains(h, "/") {
			p, err := netip.ParsePrefix(h)
			if err != nil {
				return nil, fmt.Errorf("网段 %q 无效: %w", h, err)
			}
			a.nets = append(a.nets, p.Masked())
			continue
		}
		a.domains = append(a.domains, strings.TrimPrefix(h, "."))
	}
	sort.Slice(a.domains, func(i, j int) bool { return len(a.domains[i]) > len(a.domains[j]) }) // 长的先替换
	return a, nil
}

var (
	reAnonIPv4  = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)
	reAnonEmail = regexp.MustCompile(`[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}`)
	reAnonPhone = regexp.MustCompile(`(^|[^\d])1[3-9]\d{9}([^\d]|$)`)
	reAnonID    = regexp.MustCompile(`(^|[^\d])\d{17}[\dXx]([^\d]|$)`)
	reAnonJWT   = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)
	reAnonParam = regexp.MustCompile(`(?i)((?:^|[?&;])(?:pass(?:word|wd)?|pwd|token|access_token|refresh_token|session(?:id)?|sid|secret|api[_-]?key|apikey|ticket|jsessionid|phpsessid|auth(?:orization)?|code|signature|sign)=)([^&#]*)`)
)

// URI 脱敏请求路径与参数。
func (a *Anonymizer) URI(u string) string {
	u = reAnonParam.ReplaceAllStringFunc(u, func(m string) string {
		sub := reAnonParam.FindStringSubmatch(m)
		if attackish(sub[2]) {
			return m // 参数值本身就是攻击载荷：保留，否则语料失去意义
		}
		return sub[1] + "REDACTED"
	})
	return a.Text(u)
}

// Text 脱敏任意文本（URI 中参数以外的部分、UA）。
func (a *Anonymizer) Text(s string) string {
	if s == "" {
		return s
	}
	s = reAnonJWT.ReplaceAllString(s, "REDACTED.JWT.TOKEN")
	s = reAnonEmail.ReplaceAllString(s, "user@example.com")
	s = reAnonID.ReplaceAllString(s, "${1}110101199001011237${2}")
	s = reAnonPhone.ReplaceAllString(s, "${1}13800000000${2}")
	s = reAnonIPv4.ReplaceAllStringFunc(s, a.ip)
	low := strings.ToLower(s)
	for _, d := range a.domains {
		for i := strings.Index(low, d); i >= 0; i = strings.Index(low, d) {
			s, low = s[:i]+"example.com"+s[i+len(d):], low[:i]+"example.com"+low[i+len(d):]
		}
	}
	return s
}

// ip 替换地址：内网地址映射到 10.250.0.0/16 内的固定地址，指定网段内的公网地址映射到 198.51.100.0/24，
// 回环、链路本地（云元数据 169.254.169.254）、0.0.0.0 与其他公网地址（攻击者的回连地址）保留。
func (a *Anonymizer) ip(c string) string {
	addr, err := netip.ParseAddr(c)
	if err != nil || !addr.Is4() {
		return c
	}
	switch {
	case addr.IsLoopback(), addr.IsLinkLocalUnicast(), addr.IsUnspecified(), addr.IsMulticast():
		return c
	case addr.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(addr):
		k := addr.String()
		if v, ok := a.ips[k]; ok {
			return v
		}
		n := len(a.ips) + 1
		v := "10.250." + strconv.Itoa(n/250%250) + "." + strconv.Itoa(n%250+1)
		a.ips[k] = v
		return v
	}
	for _, p := range a.nets {
		if p.Contains(addr) {
			k := addr.String()
			if v, ok := a.pub[k]; ok {
				return v
			}
			v := "198.51.100." + strconv.Itoa(len(a.pub)%250+1)
			a.pub[k] = v
			return v
		}
	}
	return c
}

// attackish 判断参数值是否带攻击写法（这类值保留原样）。
func attackish(v string) bool {
	if d, err := url.QueryUnescape(v); err == nil {
		v = d
	}
	low := strings.ToLower(v)
	return strings.ContainsAny(v, "'\"<>;|`$(){}\\") || strings.Contains(v, "..") ||
		strings.Contains(low, "select") || strings.Contains(low, "union") || strings.Contains(low, "script") || strings.Contains(low, "${")
}
