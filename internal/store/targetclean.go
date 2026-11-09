package store

import (
	"strings"

	"netsa/internal/model"
)

// 旧版本把日志中的原始字节直接保存为页面上显示的内容：
//   - 非 HTTP 请求（TLS、RDP、DNS 等二进制协议发往 HTTP 端口）的请求行被当作攻击目标（站点 + 空格 + 请求行），
//     攻击源、事件、攻击活动、资产攻击链路的“主要目标”里出现大段乱码，每个随机的二进制载荷还各占一个目标名额；
//   - 告警证据、User-Agent、标签说明、攻击面发现的证据里的控制字符与非法字节，页面上显示为方块或问号。
// 新记录的内容在写入时转义（model.Printable）；载入快照时按同样的写法整理旧数据。幂等。

// printable 转义来自日志的显示内容。末尾的 NUL 是 C 字符串的结束符（华为 syslog 按 C 字符串发送），直接去掉。
func printable(s string) string { return model.Printable(strings.TrimRight(s, "\x00"), 0) }

// cleanKeys 返回按 clean 整理键之后的计数（整理后相同的键合并计数）；没有需要整理的键时返回原 map。
func cleanKeys(m map[string]int, clean func(string) string) map[string]int {
	dirty := false
	for k := range m {
		if clean(k) != k {
			dirty = true
			break
		}
	}
	if !dirty {
		return m
	}
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[clean(k)] += v
	}
	return out
}

func cleanTargetMap(m map[string]int) map[string]int { return cleanKeys(m, model.CleanTarget) }

// cleanProfile 整理攻击源画像中来自日志的显示内容（载入快照时、增量统计重建之前调用）。
func cleanProfile(p *IPProfile) {
	p.Targets = cleanTargetMap(p.Targets)
	p.UAs = cleanKeys(p.UAs, printable)
	p.LastXFF = printable(p.LastXFF)
	for k, v := range p.Tags {
		p.Tags[k] = printable(v)
	}
}

// cleanTargetsLocked 整理事件、告警、资产攻击链路与攻击面中保存的显示内容（调用方持写锁）。
func (s *Store) cleanTargetsLocked() {
	for _, inc := range s.incidents {
		if inc != nil {
			inc.Targets = cleanTargetMap(inc.Targets)
		}
	}
	for _, a := range s.alerts {
		if a != nil {
			a.Target, a.Evidence, a.UA = model.CleanTarget(a.Target), printable(a.Evidence), printable(a.UA)
		}
	}
	for _, tr := range s.chains {
		for _, st := range tr.Steps {
			if st != nil {
				st.Target, st.Evidence = model.CleanTarget(st.Target), printable(st.Evidence)
			}
		}
	}
	if s.surf != nil {
		for _, f := range s.surf.Findings {
			if f != nil {
				f.Evidence = printable(f.Evidence)
			}
		}
	}
}
