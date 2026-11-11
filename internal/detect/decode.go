package detect

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/corazawaf/libinjection-go"

	"netsa/internal/model"
	"netsa/internal/risk"
)

// 编码载荷还原：路径段与查询参数中 Base64、Hex 编码的载荷，以及路径中用 + 代替空格的注入，解码后再按规则匹配。
// URL 编码、双重编码、%uXXXX、HTML 实体在 Normalize 中已统一还原，这里补充需要按片段判断的编码。
//
// 控制开销与误报：
//   - 只看长度 16 ~ 2048 的片段，字符集必须合规：Base64 大小写混合、= 只在末尾、标准与 URL 安全两种字母表不混用；
//     Hex 为偶数长度。普通单词、数字 ID、哈希值（解码后是二进制）都会被排除；
//   - 解码结果必须是合法的 UTF-8 且全为可打印字符，并含有攻击离不开的符号，否则不再匹配；
//   - 只采信能单独说明攻击的分类：命令执行、目录穿越 / 文件包含、表达式注入、反序列化、XXE；SQL 注入与 XSS
//     还须语法分析确认（解码结果可能只是一段普通的 JSON 或文字）。SSRF、开放重定向不采信：把回跳网址做 Base64
//     编码放在参数里是常见的正常写法；
//   - 每个请求最多采信 8 个产生命中的片段，候选片段最多 64 个、累计解码不超过 64KB；已被原文命中的规则不重复报。

const (
	minEncoded    = 16
	maxEncoded    = 2048
	maxPieces     = 8
	maxCandidates = 64       // 每个请求尝试解码的候选片段上限
	maxDecodeIn   = 64 << 10 // 每个请求累计解码的字节上限
	minDecodeOut  = 8        // 解码结果至少这么多字节
)

// decodedCats 是对解码结果采信的攻击类型。
var decodedCats = map[string]bool{CatCmdExec: true, CatTraversal: true, CatExpr: true, CatDeser: true, CatXXE: true, CatSQLi: true, CatXSS: true}

// piece 是一个还原出来的编码片段。
type piece struct {
	param string // 所在的查询参数（路径段为空）
	enc   string // 编码方式
	text  string // 解码结果（保留大小写）
	segs  []string
}

// encodedPieces 找出 URI 中可还原的编码片段。没有候选片段时不分配内存。
// accept 不为空时，只有它接受的片段（解码结果确实命中规则）才计入 maxPieces：普通文字里的一个撇号、括号也算
// “攻击写法”，只按 hasAttackMark 计数的话，前面放 8 个带引号的无害 Base64 参数就能把真正的载荷挤出名额。
// 总开销改由候选片段数与累计解码字节数约束。
func encodedPieces(rawURI string, accept func(*piece) bool) []piece {
	path, query, _ := strings.Cut(rawURI, "?")
	var out []piece
	cands, decoded := 0, 0
	full := func() bool { return len(out) >= maxPieces || cands >= maxCandidates || decoded >= maxDecodeIn }
	add := func(p piece) {
		cands++
		if accept == nil || accept(&p) {
			out = append(out, p)
		}
	}
	try := func(name, raw string) {
		if len(raw) < minEncoded || full() {
			return
		}
		v := raw
		if strings.IndexByte(v, '%') >= 0 {
			for i := 0; i < 2; i++ { // 编码片段本身可能再做过 URL 编码（%2B、%2F、%3D）
				d, changed := percentDecode(v)
				if !changed {
					break
				}
				v = d
			}
		}
		if len(v) < minEncoded || len(v) > maxEncoded {
			return
		}
		// JWT 之类用点分隔的多段 Base64：逐段尝试。只有带攻击写法的解码结果才成为候选
		for v != "" && !full() {
			var part string
			part, v, _ = strings.Cut(v, ".")
			if len(part) < minEncoded {
				continue
			}
			decoded += len(part)
			if t, ok := decodeBase64(part); ok {
				if hasAttackMark(t) {
					add(piece{param: name, enc: "Base64", text: t})
				}
			} else if t, ok := decodeHex(part); ok && hasAttackMark(t) {
				add(piece{param: name, enc: "Hex", text: t})
			}
		}
	}
	for rest := path; rest != ""; {
		var seg string
		seg, rest, _ = strings.Cut(rest, "/")
		if s, _, ok := strings.Cut(seg, ";"); ok { // 路径参数：/a;jsessionid=…
			seg = s
		}
		try("", seg)
	}
	for rest := query; rest != "" && !full(); {
		var kv string
		kv, rest, _ = strings.Cut(rest, "&")
		k, v, _ := strings.Cut(kv, "=")
		try(k, v)
	}
	// 路径中用 + 代替空格：/index.php/1+union+select…、/cgi-bin/x;cat+/etc/passwd。查询串中的 + 已在 Normalize 中还原
	if strings.IndexByte(path, '+') >= 0 && len(out) < maxPieces {
		// 路径整体只还原一次，不受候选数限制：查询串里的诱饵片段不能挤掉它
		p := strings.ReplaceAll(path, "+", " ")
		if !hasAttackMark(decodeValue(p)) {
			return out
		}
		var segs []string
		for _, s := range strings.Split(p, "/") {
			if strings.IndexByte(s, ' ') >= 0 {
				segs = append(segs, decodeValue(s))
			}
		}
		if p := (piece{enc: "路径中的 +", text: p, segs: segs}); accept == nil || accept(&p) {
			out = append(out, p)
		}
	}
	return out
}

// probeLen 是先行解码的前缀长度：随机串、加密数据只解这一小段就能排除，不必整段解码。
const probeLen = 16

// decodeBase64 按 Base64（标准或 URL 安全字母表，可省略填充）解码，解码结果须为可打印文本。
func decodeBase64(s string) (string, bool) {
	n := len(s)
	for n > 0 && s[n-1] == '=' {
		n--
	}
	if len(s)-n > 2 || n < minEncoded || n%4 == 1 {
		return "", false
	}
	var upper, lower, std, url bool
	for i := 0; i < n; i++ {
		switch c := s[i]; {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
		case c == '+' || c == '/':
			std = true
		case c == '-' || c == '_':
			url = true
		default:
			return "", false
		}
	}
	// 真实的 Base64 几乎总是大小写混合；纯小写、纯大写是普通单词、十六进制或常量名
	if !upper || !lower || std && url {
		return "", false
	}
	enc := base64.RawStdEncoding
	if url {
		enc = base64.RawURLEncoding
	}
	var head [probeLen * 3 / 4]byte
	if _, err := enc.Decode(head[:], []byte(s[:probeLen])); err != nil || !asciiText(head[:]) {
		return "", false
	}
	b, err := enc.DecodeString(s[:n])
	if err != nil {
		return "", false
	}
	return printableText(b)
}

// decodeHex 按十六进制解码（可带 0x 前缀），解码结果须为可打印文本。
func decodeHex(s string) (string, bool) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s) < minEncoded || len(s)%2 != 0 {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if _, ok := unhex(s[i]); !ok {
			return "", false
		}
	}
	var head [probeLen / 2]byte
	if _, err := hex.Decode(head[:], []byte(s[:probeLen])); err != nil || !asciiText(head[:]) {
		return "", false
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", false
	}
	return printableText(b)
}

// asciiText 判断字节是否都是可打印的 ASCII 字符（含制表、换行）。攻击载荷都是 ASCII；
// 随机的 12 个字节恰好都落在可打印 ASCII 范围内的概率不到十万分之一。
func asciiText(b []byte) bool {
	for _, c := range b {
		if (c < 0x20 || c > 0x7e) && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}

// printableText 判断解码结果是不是可打印的 ASCII 文本，并含有攻击离不开的符号。
// 随机串、哈希值、加密数据解码后是二进制，几乎不可能满足；非 ASCII 的文字（中文内容）不是攻击载荷，不再匹配。
func printableText(b []byte) (string, bool) {
	if len(b) < minDecodeOut || !asciiText(b) {
		return "", false
	}
	s := string(b)
	if !strings.ContainsAny(s, "/\\.;|`$'\"<>(){}= &") {
		return "", false
	}
	return s, true
}

// decodedHits 还原 URI 中的编码片段并按规则匹配，返回原文没有命中的规则。
func (e *Engine) decodedHits(ev *model.Event, result string, have []model.Hit) []model.Hit {
	var out []model.Hit
	seen := func(id string) bool {
		for _, h := range have {
			if h.RuleID == id {
				return true
			}
		}
		for _, h := range out {
			if h.RuleID == id {
				return true
			}
		}
		return false
	}
	// 解码与匹配逐片段进行：只有产生新命中的片段计入片段上限
	encodedPieces(ev.URI, func(p *piece) bool {
		n := len(out)
		for _, h := range e.matchDecoded(Normalize(p.text), ev.Method, result) {
			if seen(h.RuleID) {
				continue
			}
			if h.Category == CatSQLi || h.Category == CatXSS {
				if !p.confirms(h.Category) {
					continue
				}
				h.Syntax = 1
			}
			where := p.enc + " 解码后"
			if p.param != "" {
				where = "参数 " + Printable(p.param, 40) + " 经 " + where
			}
			h.Param = strings.ToLower(Printable(p.param, 64))
			h.Evidence = Printable("（"+where+"）"+h.Evidence, 400)
			out = append(out, h)
		}
		return len(out) > n
	})
	return out
}

// confirms 用语法分析确认解码结果构成 SQL 注入 / HTML 注入。
func (p *piece) confirms(cat string) bool {
	texts := p.segs
	if len(texts) == 0 {
		texts = []string{p.text}
	}
	for _, t := range texts {
		if len(t) > maxSyntaxLen {
			t = t[:maxSyntaxLen]
		}
		switch cat {
		case CatSQLi:
			if ok, fp := libinjection.IsSQLi(t); ok && injectionFP(fp) {
				return true
			}
		case CatXSS:
			if libinjection.IsXSS(t) {
				return true
			}
		}
	}
	return false
}

// matchDecoded 用作用于 URI 的规则匹配解码后的文本（已归一化），只返回采信的分类。
func (e *Engine) matchDecoded(text, method, result string) []model.Hit {
	if text == "" {
		return nil
	}
	var segs [segCount]bitset
	if e.ac != nil {
		bp := e.bitsPool.Get().(*bitset)
		defer e.bitsPool.Put(bp)
		buf := *bp
		buf.clear()
		for i := range segs {
			segs[i] = buf[i*e.words : (i+1)*e.words]
		}
		e.scanSegments(text, len(text), len(text), 0, &segs)
		// 规则用到的字面量一个都没有出现（正常的 JSON、回跳网址、普通文字）：不必逐条匹配
		if !e.decAlways && !segs[segAny].intersects(e.decLits) {
			return nil
		}
	}
	var hits []model.Hit
	for _, i := range e.decRules {
		r := e.rules[i]
		seg := segOf(r.Target)
		if !r.methodOK(method) {
			continue
		}
		if r.OnlyFailed && result != model.ResultFailed && result != model.ResultBlocked {
			continue
		}
		if r.needIDs != nil && e.ac != nil && !clausesPass(r.needIDs, segs[seg]) {
			continue
		}
		loc := r.re.FindStringIndex(text)
		if loc == nil {
			continue
		}
		if r.Shadow {
			e.shadow.note(r.ID, "（编码载荷解码后）"+excerpt(text, loc[0], loc[1]))
			continue
		}
		h := model.Hit{RuleID: r.ID, Name: r.Name, Category: r.Category, Severity: r.sev, Phase: r.Phase,
			Evidence: excerpt(text, loc[0], loc[1]), Result: result}
		if result == model.ResultSuccess && !risk.ResponseProvable(r.Category) {
			h.Result = model.ResultPassed
		}
		hits = append(hits, h)
	}
	return hits
}

// hasAttackMark 判断解码结果中有没有采信的攻击类型离不开的写法（一次扫描，不分配内存）：
// 命令分隔与替换、引号、括号、尖括号、目录跳转、表达式 ${ #{ {{、SQL 注释、命令行参数、系统路径、伪协议。
// 正常的 JSON（JWT 载荷、翻页游标）、回跳网址、普通文字都没有这些写法，绝大多数候选片段在这里就结束。
func hasAttackMark(s string) bool {
	for i := 0; i < len(s); i++ {
		var n byte
		if i+1 < len(s) {
			n = s[i+1]
		}
		switch s[i] {
		case '\\', ';', '|', '`', '<', '>', '\'', '(', '%', '&':
			return true
		case '.':
			if n == '.' {
				return true
			}
		case '$', '#':
			if n == '{' || n == '(' {
				return true
			}
		case '{':
			if n == '{' {
				return true
			}
		case '-':
			// SQL 注释 --；命令行参数（bash -i、sh -c、nc -e、powershell -enc）
			if n == '-' || i > 0 && s[i-1] == ' ' && isASCIILetter(n) {
				return true
			}
		case '"':
			if n == ';' { // PHP 序列化对象
				return true
			}
		case '/':
			if hasPrefixFold(s[i:], "/etc/", "/proc/", "/bin/", "/dev/", "/tmp/", "/root/", "/var/", "/windows/") {
				return true
			}
		case ':':
			if schemeBefore(s, i) {
				return true
			}
		}
	}
	return false
}

func isASCIILetter(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }

// hasPrefixFold 判断 s 是否以任一前缀开头（ASCII 不区分大小写）。
func hasPrefixFold(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if len(s) >= len(p) && strings.EqualFold(s[:len(p)], p) {
			return true
		}
	}
	return false
}

// wrapperSchemes 是文件包含、远程加载、反序列化回连常用的伪协议。
var wrapperSchemes = map[string]bool{"php": true, "file": true, "phar": true, "expect": true, "data": true, "zip": true,
	"jndi": true, "ldap": true, "rmi": true, "gopher": true, "dict": true}

// schemeBefore 判断 s[i] 处的冒号前是不是伪协议名。
func schemeBefore(s string, i int) bool {
	j := i
	for j > 0 && i-j < 8 && isASCIILetter(s[j-1]) {
		j--
	}
	return j < i && wrapperSchemes[strings.ToLower(s[j:i])]
}
