package rulemgr

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"netsa/internal/detect"
)

// Sigma 规则只转换能准确表达的部分。平台的规则是单条正则匹配一个文本段，表达不了多个字段同时满足或“排除”，
// 这类规则直接跳过并说明原因：悄悄丢掉条件会把一条精确的规则变成误报来源。

// SigmaSkip 是一条未转换的规则及原因。
type SigmaSkip struct {
	Title  string `json:"title"`
	Reason string `json:"reason"`
}

// SigmaResult 是转换结果。
type SigmaResult struct {
	Rules   []detect.Rule `json:"rules"`
	Skipped []SigmaSkip   `json:"skipped"`
}

type sigmaDoc struct {
	Title     string         `yaml:"title"`
	ID        string         `yaml:"id"`
	Status    string         `yaml:"status"`
	Level     string         `yaml:"level"`
	Tags      []string       `yaml:"tags"`
	LogSource map[string]any `yaml:"logsource"`
	Detection map[string]any `yaml:"detection"`
}

// 字段 → 规则的文本段。
var sigmaTargets = map[string]string{
	"cs-uri-query": "uri", "c-uri-query": "uri", "cs-uri": "uri", "c-uri": "uri", "url": "uri", "uri": "uri", "request_uri": "uri",
	"cs-uri-stem": "path", "c-uri-stem": "path", "c-uri-path": "path", "uri_path": "path",
	"c-useragent": "ua", "cs-user-agent": "ua", "useragent": "ua", "user-agent": "ua", "http_user_agent": "ua",
	"cs-referrer": "referer", "cs-referer": "referer", "c-referer": "referer", "referer": "referer",
}

var sigmaIDRe = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

// ConvertSigma 把 Sigma YAML（可以多个文档）转换为规则。
func ConvertSigma(data []byte) (*SigmaResult, error) {
	res := &SigmaResult{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	docs := 0
	for {
		var doc sigmaDoc
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("Sigma 规则不是有效的 YAML: %w", err)
		}
		docs++
		if doc.Detection == nil { // 多文档 Sigma 规则的公共部分，或空文档
			continue
		}
		r, err := convertSigmaDoc(&doc)
		if err != nil {
			res.Skipped = append(res.Skipped, SigmaSkip{Title: doc.Title, Reason: err.Error()})
			continue
		}
		res.Rules = append(res.Rules, *r)
	}
	if docs == 0 {
		return nil, errors.New("没有找到 Sigma 规则")
	}
	return res, nil
}

func convertSigmaDoc(d *sigmaDoc) (*detect.Rule, error) {
	if d.Title == "" {
		return nil, errors.New("缺少 title")
	}
	cat, _ := d.LogSource["category"].(string)
	if cat != "webserver" && cat != "proxy" {
		return nil, fmt.Errorf("只支持 Web 日志（category: webserver / proxy），这条是 %q", cat)
	}
	if d.Status == "deprecated" || d.Status == "unsupported" {
		return nil, fmt.Errorf("规则状态是 %s", d.Status)
	}
	sel, err := sigmaSelection(d.Detection)
	if err != nil {
		return nil, err
	}
	target, alts, methods, err := sigmaMatchers(sel)
	if err != nil {
		return nil, err
	}
	id := sigmaIDRe.ReplaceAllString(strings.ReplaceAll(d.ID, "-", ""), "")
	if len(id) > 12 {
		id = id[:12]
	}
	if id == "" {
		id = sigmaIDRe.ReplaceAllString(strings.ToLower(d.Title), "-")
		if len(id) > 40 {
			id = id[:40]
		}
	}
	level := map[string]string{"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}[strings.ToLower(d.Level)]
	if level == "" {
		level = "medium"
	}
	return &detect.Rule{ID: "sigma-" + id, Name: d.Title, Category: sigmaCategory(d), Severity: level, Target: target, Pattern: strings.Join(alts, "|"), Methods: methods}, nil
}

// sigmaSelection 只接受可以表达为“一个选择条件”的 condition。
func sigmaSelection(det map[string]any) (any, error) {
	cond, _ := det["condition"].(string)
	cond = strings.TrimSpace(cond)
	if cond == "" {
		return nil, errors.New("缺少 condition，或 condition 不是单个表达式")
	}
	if v, ok := det[cond]; ok {
		return v, nil
	}
	if rest, ok := strings.CutPrefix(cond, "1 of "); ok {
		prefix, wild := strings.CutSuffix(strings.TrimSpace(rest), "*")
		keys := make([]string, 0, len(det))
		for k := range det {
			if k != "condition" && (wild && strings.HasPrefix(k, prefix) || !wild && k == prefix) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		var merged []any
		for _, k := range keys {
			merged = append(merged, det[k])
		}
		if len(merged) > 0 {
			return merged, nil
		}
	}
	return nil, fmt.Errorf("condition %q 无法转换：只支持单个选择条件或 1 of selection*", cond)
}

// sigmaMatchers 把选择条件转换为同一文本段上的“或”关系。
func sigmaMatchers(sel any) (target string, alts, methods []string, err error) {
	setTarget := func(t string) error {
		if target != "" && target != t {
			return errors.New("条件涉及多个字段，无法用一条规则表达")
		}
		target = t
		return nil
	}
	var walk func(v any) error
	walk = func(v any) error {
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				if err := walk(e); err != nil {
					return err
				}
			}
			return nil
		case string, int, float64, bool: // 关键字：在整个 URI 中查找
			if err := setTarget("uri"); err != nil {
				return err
			}
			alts = append(alts, sigmaScalar(x))
			return nil
		case map[string]any:
			fields := 0
			for key, val := range x {
				name, mods, _ := strings.Cut(key, "|")
				lname := strings.ToLower(name)
				if lname == "sc-status" { // 响应结果由平台统一研判
					continue
				}
				if lname == "cs-method" || lname == "http_method" || lname == "method" {
					ms, err := sigmaStrings(val)
					if err != nil {
						return err
					}
					for _, m := range ms {
						methods = append(methods, strings.ToUpper(m))
					}
					continue
				}
				t, ok := sigmaTargets[lname]
				if !ok {
					return fmt.Errorf("不支持字段 %q", name)
				}
				fields++
				if fields > 1 {
					return errors.New("条件要求多个字段同时满足，无法用一条规则表达")
				}
				if err := setTarget(t); err != nil {
					return err
				}
				vals, err := sigmaStrings(val)
				if err != nil {
					return err
				}
				for _, s := range vals {
					p, err := sigmaPattern(s, mods)
					if err != nil {
						return err
					}
					alts = append(alts, p)
				}
			}
			return nil
		}
		return fmt.Errorf("不支持的条件类型 %T", v)
	}
	if err := walk(sel); err != nil {
		return "", nil, nil, err
	}
	if len(alts) == 0 || target == "" {
		return "", nil, nil, errors.New("没有可以匹配的内容")
	}
	return target, alts, methods, nil
}

func sigmaScalar(v any) string {
	switch x := v.(type) {
	case string:
		return regexp.QuoteMeta(strings.ToLower(x))
	case int:
		return strconv.Itoa(x)
	case float64:
		return regexp.QuoteMeta(strconv.FormatFloat(x, 'f', -1, 64))
	}
	return regexp.QuoteMeta(fmt.Sprint(v))
}

func sigmaStrings(v any) ([]string, error) {
	switch x := v.(type) {
	case string:
		return []string{x}, nil
	case int:
		return []string{strconv.Itoa(x)}, nil
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			switch s := e.(type) {
			case string:
				out = append(out, s)
			case int:
				out = append(out, strconv.Itoa(s))
			default:
				return nil, fmt.Errorf("不支持的取值 %v", e)
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("不支持的取值 %v", v)
}

func sigmaPattern(val, mods string) (string, error) {
	q := regexp.QuoteMeta(strings.ToLower(val))
	switch mods {
	case "contains", "":
		if mods == "" { // 不带修饰符是整个字段相等；Sigma 的 * 和 ? 是通配符
			wild := strings.ReplaceAll(strings.ReplaceAll(q, `\*`, ".*"), `\?`, ".")
			if wild != q {
				return wild, nil
			}
			return "^" + q + "$", nil
		}
		return q, nil
	case "startswith":
		return "^" + q, nil
	case "endswith":
		return q + "$", nil
	case "re":
		if _, err := regexp.Compile(val); err != nil {
			return "", fmt.Errorf("正则不兼容（平台使用 RE2，不支持回溯和环视）: %v", err)
		}
		return "(?:" + val + ")", nil
	}
	return "", fmt.Errorf("不支持修饰符 %q（如 contains|all 要求多个值同时出现）", mods)
}

// sigmaCategory 按标题和标签归入平台的攻击分类，分类决定等级底线和处置建议。
func sigmaCategory(d *sigmaDoc) string {
	text := strings.ToLower(d.Title + " " + strings.Join(d.Tags, " "))
	for _, m := range []struct{ key, cat string }{
		{"sql injection", detect.CatSQLi}, {"sqli", detect.CatSQLi}, {"xss", detect.CatXSS}, {"cross-site", detect.CatXSS},
		{"webshell", detect.CatWebShell}, {"traversal", detect.CatTraversal}, {"file inclusion", detect.CatTraversal},
		{"ssrf", detect.CatSSRF}, {"command injection", detect.CatCmdExec}, {"rce", detect.CatCmdExec}, {"remote code", detect.CatCmdExec},
		{"log4j", detect.CatExpr}, {"ognl", detect.CatExpr}, {"deserializ", detect.CatDeser}, {"xxe", detect.CatXXE}, {"scanner", detect.CatScanner}, {"cve.", detect.CatCVE}, {"cve-", detect.CatCVE},
	} {
		if strings.Contains(text, m.key) {
			return m.cat
		}
	}
	return "自定义规则"
}
