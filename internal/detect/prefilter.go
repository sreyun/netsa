package detect

import (
	"regexp/syntax"
	"sort"
	"strings"
	"unicode/utf8"
)

// 规则预过滤（参考 RE2 prefilter 思路）：从正则语法树推导出匹配成功时文本必须满足的条件，
// 形式为若干子句的“与”，每个子句是若干子串的“或”（合取范式）。不满足时直接跳过正则。
//
// 推导规则保证不漏报：
//   - 字面量/小字符类：可精确枚举的有限字符串集合（exact）；
//   - 连接：相邻可枚举部分做笛卡尔积得到更长的必要串（如 "\." + "(php|jsp)" → ".php" ".jsp"），
//     无法枚举的部分把链条切断，每段链条都是独立的必要子句；
//   - 选择：各分支都可枚举时取并集，否则取各分支最优子句的并集；
//   - x+ 视为 x* x，x? 视为 (x|空)，x*/任意字符等不提供信息。
// 被检测文本均已小写，因此字面量统一小写。

const (
	maxClassExpand = 16 // 字符类最多展开的字符数
	maxExact       = 64 // 精确枚举集合的最大规模
	maxExactLen    = 48 // 精确枚举字符串的最大长度
	maxClauses     = 3  // 每条规则保留的最优子句数
)

type pfInfo struct {
	exact []string   // 可精确枚举的匹配串集合；nil 表示不可枚举
	cnf   [][]string // 必要条件（子句之间为“与”，子句内为“或”）
}

func analyze(re *syntax.Regexp) pfInfo {
	switch re.Op {
	case syntax.OpLiteral:
		return pfInfo{exact: []string{strings.ToLower(string(re.Rune))}}
	case syntax.OpCharClass:
		var out []string
		for i := 0; i+1 < len(re.Rune); i += 2 {
			lo, hi := re.Rune[i], re.Rune[i+1]
			if int(hi-lo)+1+len(out) > maxClassExpand {
				return pfInfo{}
			}
			for r := lo; r <= hi; r++ {
				out = append(out, strings.ToLower(string(r)))
			}
		}
		return pfInfo{exact: dedup(out)}
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return pfInfo{exact: []string{""}}
	case syntax.OpCapture:
		return analyze(re.Sub[0])
	case syntax.OpQuest:
		s := analyze(re.Sub[0])
		if s.exact != nil && len(s.exact) < maxExact {
			return pfInfo{exact: dedup(append(append([]string(nil), s.exact...), ""))}
		}
		return pfInfo{}
	case syntax.OpPlus:
		return pfInfo{cnf: toCNF(analyze(re.Sub[0]))}
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return pfInfo{cnf: toCNF(analyze(re.Sub[0]))}
		}
		return pfInfo{}
	case syntax.OpAlternate:
		return analyzeAlternate(re.Sub)
	case syntax.OpConcat:
		return analyzeConcat(re.Sub)
	}
	return pfInfo{}
}

func analyzeAlternate(subs []*syntax.Regexp) pfInfo {
	infos := make([]pfInfo, len(subs))
	allExact, total := true, 0
	for i, sub := range subs {
		infos[i] = analyze(sub)
		if infos[i].exact == nil {
			allExact = false
		}
		total += len(infos[i].exact)
	}
	if allExact && total <= maxExact {
		var out []string
		for _, in := range infos {
			out = append(out, in.exact...)
		}
		return pfInfo{exact: dedup(out)}
	}
	var clause []string
	for _, in := range infos {
		c := toCNF(in)
		if len(c) == 0 {
			return pfInfo{}
		}
		clause = append(clause, c[0]...) // c 已按区分度排序，取最优子句
		if len(clause) > maxExact {
			return pfInfo{}
		}
	}
	return pfInfo{cnf: [][]string{dedup(clause)}}
}

func analyzeConcat(subs []*syntax.Regexp) pfInfo {
	var clauses [][]string
	cur, chainExact := []string{""}, true // 当前可枚举链条
	closeChain := func() {
		if valid(cur) {
			clauses = append(clauses, cur)
		}
		cur = []string{""}
	}
	for _, sub := range subs {
		// x+ 等价于 x* x：先切断链条，再以 x 开始新链条
		if (sub.Op == syntax.OpPlus || sub.Op == syntax.OpRepeat && sub.Min >= 1) && len(sub.Sub) == 1 {
			inner := analyze(sub.Sub[0])
			closeChain()
			if inner.exact != nil {
				cur = inner.exact
			} else {
				clauses = append(clauses, inner.cnf...)
			}
			chainExact = false
			continue
		}
		s := analyze(sub)
		if s.exact != nil {
			if next, ok := cross(cur, s.exact); ok {
				cur = next
				continue
			}
			closeChain()
			cur = s.exact
			chainExact = false
			continue
		}
		closeChain()
		clauses = append(clauses, s.cnf...)
		chainExact = false
	}
	if chainExact {
		return pfInfo{exact: cur}
	}
	closeChain()
	return pfInfo{cnf: best(clauses)}
}

func cross(a, b []string) ([]string, bool) {
	if len(a)*len(b) > maxExact {
		return nil, false
	}
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			if len(x)+len(y) > maxExactLen {
				return nil, false
			}
			out = append(out, x+y)
		}
	}
	return dedup(out), true
}

// valid 判断一个枚举集合能否作为必要子句（包含空串则不能）。
func valid(set []string) bool {
	if len(set) == 0 {
		return false
	}
	for _, s := range set {
		if s == "" {
			return false
		}
	}
	return true
}

func toCNF(in pfInfo) [][]string {
	if len(in.cnf) > 0 {
		return in.cnf
	}
	if valid(in.exact) {
		return [][]string{in.exact}
	}
	return nil
}

// score 衡量子句的区分度：最短子串越长、候选越少越好。
func score(set []string) int {
	min := 1 << 30
	for _, s := range set {
		if n := utf8.RuneCountInString(s); n < min {
			min = n
		}
	}
	return min*100 - len(set)
}

// best 按区分度保留最优的若干子句。
func best(clauses [][]string) [][]string {
	var out [][]string
	for _, c := range clauses {
		if valid(c) {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return score(out[i]) > score(out[j]) })
	if len(out) > maxClauses {
		out = out[:maxClauses]
	}
	return out
}

func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// buildPrefilter 解析规则正则并推导必要条件；无法推导时返回 nil（每次都执行正则）。
func buildPrefilter(pattern string, flags syntax.Flags) [][]string {
	re, err := syntax.Parse(pattern, flags)
	if err != nil {
		return nil
	}
	return best(toCNF(analyze(re.Simplify())))
}

// prefilterPass 判断文本是否满足全部必要子句。
func prefilterPass(s string, cnf [][]string) bool {
	for _, clause := range cnf {
		if !containsAnyStr(s, clause) {
			return false
		}
	}
	return true
}

func containsAnyStr(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
