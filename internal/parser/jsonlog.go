package parser

import (
	"encoding/json"
	"strconv"
	"strings"
)

// ---------------- JSON 日志的通用处理 ----------------

// unmarshalLog 解码一行 JSON 日志。nginx 的 log_format 未加 escape=json 时，值中的引号、反斜杠、控制字符与非 ASCII 字节
// 会按 nginx 默认转义写成 \x22、\x5C、\xE4 等，整行不是合法 JSON：还原后再解码，避免带引号、中文的请求（往往正是攻击）被丢弃。
// 合法 JSON 中不会出现 \x 转义（字面的 \x 一定写作 \\x，hexToJSON 不改动），含 \x 时直接还原后解码，只解码一次。
func unmarshalLog(line string) (map[string]any, bool) {
	data := []byte(line)
	if strings.Contains(line, `\x`) {
		data = hexToJSON(line)
	}
	var m map[string]any
	if json.Unmarshal(data, &m) != nil {
		return nil, false
	}
	return m, true
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// hexToJSON 把 \xHH 转义换成 JSON 合法的写法：引号与反斜杠重新转义，控制字符写成 \u00HH，
// 其余字节原样写入（中文等多字节字符的 \xE4\xB8\xAD 由此还原为 UTF-8）。其他 JSON 转义（\" \\ \n 等）保持不变。
func hexToJSON(s string) []byte {
	const hexDigits = "0123456789abcdef"
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b = append(b, c)
			continue
		}
		if s[i+1] == 'x' && i+3 < len(s) {
			hi, ok1 := unhex(s[i+2])
			lo, ok2 := unhex(s[i+3])
			if ok1 && ok2 {
				switch v := hi<<4 | lo; {
				case v == '"' || v == '\\':
					b = append(b, '\\', v)
				case v < 0x20:
					b = append(b, '\\', 'u', '0', '0', hexDigits[v>>4], hexDigits[v&15])
				default:
					b = append(b, v)
				}
				i += 3
				continue
			}
		}
		b = append(b, c, s[i+1]) // 其他转义（含 \\ 后紧跟的 x）原样保留
		i++
	}
	return b
}

// maxFlattenDepth 是展开 JSON 的最大层级：真实日志一般不超过 4 层，限制层级防止深层嵌套的恶意日志拼接出超长的路径键。
const maxFlattenDepth = 8

// flattenLower 将 JSON 对象展开为小写键的字符串映射。嵌套字段同时以完整路径（如 url.original）和最后一级键（如 original）保存：
// 解析器优先按完整路径取 ECS 等嵌套格式的字段，避免 url.original 与 user_agent.original 这类同名的最后一级键互相覆盖；
// 最后一级键重名时层级浅的优先。
func flattenLower(m map[string]any) map[string]string {
	type node struct {
		m      map[string]any
		prefix string
		depth  int
	}
	out := make(map[string]string, len(m))
	queue := []node{{m: m}}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for k, v := range n.m {
			k = strings.ToLower(k)
			var s string
			switch x := v.(type) {
			case string:
				s = x
			case float64:
				s = strconv.FormatFloat(x, 'f', -1, 64)
			case bool:
				s = strconv.FormatBool(x)
			case map[string]any:
				if n.depth+1 < maxFlattenDepth {
					queue = append(queue, node{x, n.prefix + k + ".", n.depth + 1})
				}
				continue
			case []any:
				// Caddy 的请求头为字符串数组，取第一个值
				if len(x) == 0 {
					continue
				}
				str, ok := x[0].(string)
				if !ok {
					continue
				}
				s = str
			default:
				continue
			}
			if n.prefix != "" {
				out[n.prefix+k] = s
				if cur, dup := out[k]; dup && cur != "" {
					continue
				}
			}
			out[k] = s
		}
	}
	return out
}

// 包装格式：容器运行时或日志采集器把原始日志放在 JSON 字段或固定前缀之后。
const (
	wrapNone    int32 = iota
	wrapLog           // Docker json-file、Fluent Bit、Fluentd：{"log": "..."}
	wrapMessage       // Filebeat、Logstash、Vector 等：{"message": "..."}
	wrapCRI           // containerd / CRI-O（Kubernetes）：<时间> stdout F <日志>
)

var wrapLabel = [...]string{wrapLog: "log 字段包装", wrapMessage: "message 字段包装", wrapCRI: "容器 CRI 包装"}

// unwrapLine 取出被包装的原始日志，返回原始日志与包装格式。
func unwrapLine(line string) (string, int32) {
	if strings.HasPrefix(line, "{") {
		if !strings.Contains(line, `"log"`) && !strings.Contains(line, `"message"`) && !strings.Contains(line, `"msg"`) {
			return "", wrapNone
		}
		var w struct {
			Log     any `json:"log"`
			Message any `json:"message"`
			Msg     any `json:"msg"`
		}
		if json.Unmarshal([]byte(line), &w) != nil {
			return "", wrapNone
		}
		for _, c := range [...]struct {
			v    any
			kind int32
		}{{w.Log, wrapLog}, {w.Message, wrapMessage}, {w.Msg, wrapMessage}} {
			if s, ok := c.v.(string); ok {
				if s = strings.TrimRight(s, "\r\n"); strings.TrimSpace(s) != "" {
					return s, c.kind
				}
			}
		}
		return "", wrapNone
	}
	if i := criPrefix(line); i > 0 {
		return line[i:], wrapCRI
	}
	return "", wrapNone
}

// criPrefix 返回 CRI 日志（2026-10-26T10:00:00.123456789+08:00 stdout F <日志>，P 表示超长日志被拆分的片段）中原始日志的起始位置，
// 不是 CRI 格式时返回 -1。CRI 的时间前缀形似 syslog 头，需在 syslog 解析之前识别，否则 stdout 会被当成主机名。
func criPrefix(line string) int {
	if len(line) < 32 || line[4] != '-' || line[10] != 'T' {
		return -1
	}
	sp := strings.IndexByte(line, ' ')
	if sp < 19 || sp > 40 {
		return -1
	}
	rest := line[sp+1:]
	if len(rest) >= 9 && (rest[:7] == "stdout " || rest[:7] == "stderr ") && (rest[7] == 'F' || rest[7] == 'P') && rest[8] == ' ' {
		return sp + 10
	}
	return -1
}
