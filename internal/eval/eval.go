// Package eval 用带标注的样本跑完整检测流水线，量化检出率与误报，并防止规则或定级改动造成退化。
//
// 内置样本是手工构造的，指标只说明这些场景的表现，不代表真实流量的准确率；
// 真实的准确率需要用脱敏后的现场日志（netsa eval -corpus）。
package eval

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"netsa/internal/detect"
	"netsa/internal/model"
	"netsa/internal/pipeline"
	"netsa/internal/store"
)

//go:embed corpus/web.tsv
var builtinCorpus string

const defaultUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"

// Case 是一条带标注的样本。
type Case struct {
	Label  string // benign / attack
	Group  string
	Site   string // app / spa
	Method string
	Status int
	Bytes  int64
	Expect string
	URI    string
	UA     string
	Line   int
}

// Result 是一条样本的检测结果。
type Result struct {
	Case
	Severity model.Severity
	Alerted  bool
	Outcome  string
	Rule     string
	OK       bool
}

// GroupStat 是一个分组的统计。
type GroupStat struct {
	Total    int `json:"total"`
	Detected int `json:"detected"`
}

// Report 是一次评测的汇总。
type Report struct {
	Benign         int                  `json:"benign"`
	BenignAlerted  int                  `json:"benign_alerted"`
	BenignHigh     int                  `json:"benign_high"`
	BenignCritical int                  `json:"benign_critical"`
	Attacks        int                  `json:"attacks"`
	Detected       int                  `json:"detected"`
	Critical       int                  `json:"critical"`
	Groups         map[string]GroupStat `json:"groups"`
	Violations     int                  `json:"violations"`
	Results        []Result             `json:"-"`
}

// Recall 返回攻击样本的检出率。
func (r *Report) Recall() float64 {
	if r.Attacks == 0 {
		return 0
	}
	return float64(r.Detected) / float64(r.Attacks)
}

// Builtin 返回内置样本。
func Builtin() ([]Case, error) { return Parse(strings.NewReader(builtinCorpus)) }

// LoadFile 读取样本文件，格式见 corpus/web.tsv。
func LoadFile(path string) ([]Case, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse 解析样本。
func Parse(rd io.Reader) ([]Case, error) {
	var out []Case
	sc := bufio.NewScanner(rd)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || line[0] == '#' {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			return nil, fmt.Errorf("第 %d 行：至少需要 8 列，实际 %d 列", n, len(f))
		}
		status, err := strconv.Atoi(f[4])
		if err != nil {
			return nil, fmt.Errorf("第 %d 行：状态码无效: %v", n, err)
		}
		size, err := strconv.ParseInt(f[5], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("第 %d 行：响应大小无效: %v", n, err)
		}
		if f[0] != "benign" && f[0] != "attack" {
			return nil, fmt.Errorf("第 %d 行：标注应为 benign 或 attack: %q", n, f[0])
		}
		if f[2] != "app" && f[2] != "spa" {
			return nil, fmt.Errorf("第 %d 行：站点应为 app 或 spa: %q", n, f[2])
		}
		if _, _, err := parseExpect(f[6]); err != nil {
			return nil, fmt.Errorf("第 %d 行：%v", n, err)
		}
		c := Case{Label: f[0], Group: f[1], Site: f[2], Method: f[3], Status: status, Bytes: size, Expect: f[6], URI: f[7], UA: defaultUA, Line: n}
		if len(f) > 8 {
			c.UA = f[8]
		}
		out = append(out, c)
	}
	return out, sc.Err()
}

var sevNames = map[string]model.Severity{"info": model.SevInfo, "low": model.SevLow, "medium": model.SevMedium, "high": model.SevHigh, "critical": model.SevCritical}

func parseExpect(s string) (string, model.Severity, error) {
	s, _, _ = strings.Cut(s, "@")
	if s == "-" || s == "none" {
		return s, 0, nil
	}
	for _, op := range []string{"<=", ">=", "="} {
		if rest, ok := strings.CutPrefix(s, op); ok {
			if v, ok := sevNames[rest]; ok {
				return op, v, nil
			}
		}
	}
	return "", 0, fmt.Errorf("期望等级无效: %q", s)
}

func (r *Result) check() bool {
	if _, outcome, ok := strings.Cut(r.Expect, "@"); ok && r.Outcome != outcome {
		return false
	}
	op, want, _ := parseExpect(r.Expect)
	switch op {
	case "-":
		return true
	case "none":
		return !r.Alerted
	case "<=":
		return !r.Alerted || r.Severity <= want
	case ">=":
		return r.Alerted && r.Severity >= want
	case "=":
		return r.Alerted && r.Severity == want
	}
	return false
}

// 让流水线学到站点的正常响应：spa 所有路径返回相同大小，app 各接口大小不同但稳定。
var appBaseline = map[string]int64{"/": 5120, "/item": 3000, "/view": 4000, "/ping": 512, "/cmd": 512, "/run": 512, "/s": 2000, "/fetch": 800, "/a": 1000}

func baselineEvents(now time.Time) []*model.Event {
	var evs []*model.Event
	mk := func(host, uri string, size int64, i int) *model.Event {
		return &model.Event{Kind: model.KindWeb, SrcIP: "198.51.100." + strconv.Itoa(i%30+1), Host: host, Method: "GET", URI: uri, Status: 200, Bytes: size,
			Time: now.Add(time.Duration(i) * time.Second), UA: defaultUA}
	}
	for i := 0; i < 20; i++ {
		evs = append(evs, mk("spa.example.com", "/", 2048, i), mk("spa.example.com", "/products/"+strconv.Itoa(i), 2048, i))
		for _, p := range sortedKeys(appBaseline) {
			evs = append(evs, mk("app.example.com", p, appBaseline[p], i))
		}
	}
	return evs
}

func sortedKeys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Run 用内置规则跑一遍样本。每条样本使用独立的来源地址，互不影响。
func Run(cases []Case) (*Report, error) {
	eng, err := detect.NewEngine("", 1)
	if err != nil {
		return nil, err
	}
	st := store.New(100000, 100000, 100, time.Hour)
	alerts := map[string][]*model.Alert{}
	p := &pipeline.Pipeline{Engine: eng, Store: st, OnAlert: func(a *model.Alert) { alerts[a.SrcIP] = append(alerts[a.SrcIP], a) }}
	in := make(chan []*model.Event, 4)
	done := p.Run(context.Background(), in, 1)
	now := time.Now()
	in <- baselineEvents(now)
	src := func(i int) string {
		return "203." + strconv.Itoa(i>>16&255) + "." + strconv.Itoa(i>>8&255) + "." + strconv.Itoa(i&255)
	}
	batch := make([]*model.Event, 0, len(cases))
	for i, c := range cases {
		batch = append(batch, &model.Event{Kind: model.KindWeb, SrcIP: src(i + 1), Host: c.Site + ".example.com", Method: c.Method, URI: c.URI,
			Status: c.Status, Bytes: c.Bytes, UA: c.UA, Time: now.Add(time.Hour + time.Duration(i)*time.Second)})
	}
	in <- batch
	close(in)
	<-done

	rep := &Report{Groups: map[string]GroupStat{}}
	for i, c := range cases {
		res := Result{Case: c}
		for _, a := range alerts[src(i+1)] {
			if !res.Alerted || a.Severity > res.Severity {
				res.Severity, res.Outcome, res.Rule = a.Severity, a.Result, a.RuleID
			}
			res.Alerted = true
		}
		res.OK = res.check()
		if !res.OK {
			rep.Violations++
		}
		rep.Results = append(rep.Results, res)
		if c.Label == "benign" {
			rep.Benign++
			if res.Alerted {
				rep.BenignAlerted++
				if res.Severity >= model.SevHigh {
					rep.BenignHigh++
				}
				if res.Severity >= model.SevCritical {
					rep.BenignCritical++
				}
			}
			continue
		}
		rep.Attacks++
		g := rep.Groups[c.Group]
		g.Total++
		if res.Alerted {
			rep.Detected++
			g.Detected++
			if res.Severity >= model.SevCritical {
				rep.Critical++
			}
		}
		rep.Groups[c.Group] = g
	}
	return rep, nil
}

// Write 输出文本报告。verbose 时列出每条未通过的样本。
func (r *Report) Write(w io.Writer, verbose bool) {
	pct := func(a, b int) float64 {
		if b == 0 {
			return 0
		}
		return 100 * float64(a) / float64(b)
	}
	fmt.Fprintf(w, "攻击样本：%d 条，检出 %d 条（%.1f%%），判为严重 %d 条\n", r.Attacks, r.Detected, pct(r.Detected, r.Attacks), r.Critical)
	fmt.Fprintf(w, "正常样本：%d 条，告警 %d 条（%.1f%%），其中高危及以上 %d 条，严重 %d 条\n", r.Benign, r.BenignAlerted, pct(r.BenignAlerted, r.Benign), r.BenignHigh, r.BenignCritical)
	names := make([]string, 0, len(r.Groups))
	for g := range r.Groups {
		names = append(names, g)
	}
	sort.Strings(names)
	for _, g := range names {
		s := r.Groups[g]
		fmt.Fprintf(w, "  %-10s %d/%d\n", g, s.Detected, s.Total)
	}
	fmt.Fprintf(w, "不符合期望等级：%d 条\n", r.Violations)
	if !verbose {
		return
	}
	for _, x := range r.Results {
		if x.OK {
			continue
		}
		got := "未告警"
		if x.Alerted {
			got = fmt.Sprintf("%s/%s/%s", x.Severity, x.Outcome, x.Rule)
		}
		fmt.Fprintf(w, "  第 %d 行 [%s/%s/%s] %s %s %d %d 期望 %s，实际 %s\n", x.Line, x.Label, x.Group, x.Site, x.Method, x.URI, x.Status, x.Bytes, x.Expect, got)
	}
}
